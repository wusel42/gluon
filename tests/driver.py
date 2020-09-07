#!/usr/bin/env python3
import atexit
import _thread
import itertools
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from functools import partial
from tempfile import mkdtemp
from typing import Any, Callable


NODES = []

MACHINE_COLORS_ITER = (f"\x1b[{x}m" for x in itertools.cycle(reversed(range(31, 37))))


def start_all():
    global NODES
    for node in NODES:
        _thread.start_new_thread(node.run, ())
        #node.run()

    while not all([node.configmode == False for node in NODES]):
        time.sleep(0.2)


def retry(fn: Callable) -> None:
    """Call the given function repeatedly, with 1 second intervals,
    until it returns True or a timeout is reached.
    """

    for _ in range(900):
        if fn(False):
            return
        time.sleep(1)

    if not fn(True):
        raise Exception("action timed out")


class Network:
    max_id = 0

    def __init__(self, *members, name=None):
        self.id = Network.max_id
        Network.max_id += 1

        self._name = name
        self.members = members

        self.has_listener = False

    @property
    def name(self):
        return self._name or f"mesh{self.id}"

    @property
    def port(self):
        return 24000 + self.id

    @property
    def needs_listener(self):
        # we connect QEMU VMs through TCP sockets, the VM that is started first needs to be the listener
        if self.has_listener:
            return False

        self.has_listener = True
        return True


class Node:
    max_id = 0

    def __init__(self, name=None):
        global NODES

        self._name = name
        self.id = Node.max_id
        Node.max_id += 1
        self.ifindex_max = 1
        self.color = next(MACHINE_COLORS_ITER)

        # time the QEMU process was started
        self.started = None
        # is the VM in config mode?
        self.configmode = None

        # dynamic VM inventory
        self.networks = list()

        # commands to run automatically
        self.config_mode_commands = [
            f"pretty-hostname {self.name}",
            "uci set gluon-setup-mode.@setup_mode[0].configured='1'",
            "uci set gluon-setup-mode.@setup_mode[0].enabled='0'",
        ]

        # each node gets it's own working directory
        self.temp_dir = mkdtemp(prefix="gluon-test-")
        atexit.register(shutil.rmtree, self.temp_dir)

        NODES.append(self)

    @property
    def name(self):
        return self._name or f"machine{self.id}"

    def log(self, msg, bold=False):
        delta = time.time() - self.started
        if bold:
            msg = f"\033[1m{msg}\033[0m"
        print(f"({delta:>8.2f}) \0{self.color}{self.name}\x1b[39m: {msg}")
        sys.stdout.flush()

    def connect(self, node):
        network = Network(self, node)

        self.ifindex_max += 1
        self.networks.append((f"eth{self.ifindex_max}", network))

        node.ifindex_max += 1
        node.networks.append((f"eth{node.ifindex_max}", network))

        return network

    @property
    def run_command(self):
        qemu_executable = "qemu-system-x86_64"

        # https://firmware.darmstadt.freifunk.net/images/2.3~20200811/factory/gluon-ffda-2.3~20200811-x86-64.img.gz
        image = "/tmp/gluon-ffda-2.3~20201027-x86-64.img"
        #image = "/tmp/openwrt-x86-64-combined-ext4.img"
        #image = "/tmp/gluon-ffda-2.3~20200913-x86-64.img"

        # create dedicated copy for each VM, as they need to write lock the image
        image_path = os.path.join(self.temp_dir, "gluon.img")
        shutil.copyfile(image, os.path.join(self.temp_dir, "gluon.img"))

        disk_backend = f"-drive file={image_path},format=raw,if=none,id=disk0"
        disk_frontend = "-device virtio-blk-pci,scsi=off,bus=pci.0,addr=0x07,drive=disk0,id=virto-disk0,bootindex=1"

        # any network driver included in Gluon should work, see
        # https://github.com/freifunk-gluon/gluon/blob/master/targets/x86.inc
        nic_driver = "virtio-net-pci"

        def create_socket(path: str) -> socket.socket:
            if os.path.exists(path):
                os.unlink(path)
            s = socket.socket(family=socket.AF_UNIX, type=socket.SOCK_STREAM)
            s.bind(path)
            s.listen(1)
            return s

        monitor_path = os.path.join(self.temp_dir, "monitor")
        self.monitor_socket = create_socket(monitor_path)

        shell_path = os.path.join(self.temp_dir, "shell")
        self.shell_socket = create_socket(shell_path)

        # network interfaces, note the frontend addr is used to affect the order so wan/client are assigned correctly.
        wan_backend = f"-netdev user,id=wan,hostfwd=tcp::{22000 + self.id}-10.0.2.15:22"
        wan_frontend = f"-device {nic_driver},addr=0x06,netdev=wan"

        client_backend = f"-netdev user,id=client,hostfwd=tcp::{23000 + self.id}-192.168.1.1:22,net=192.168.1.15/24"
        client_frontend = f"-device {nic_driver},addr=0x05,netdev=client"

        start_command = [
            qemu_executable,
            "-m 128",
            # enable kvm acceleration, so the boot doesn't get stuck arbitrarily
            "-enable-kvm",
            # do not open a graphical window
            "-nographic",
            # monitor, to control the machine from outside
            f"-monitor unix:{monitor_path}",
            # serial i/o
            f"-chardev socket,id=shell,path={shell_path}",
            "-device virtio-serial",
            "-device virtconsole,chardev=shell",
            # random number generator
            "-device virtio-rng-pci",
            # network interfaces
            wan_backend,
            wan_frontend,
            client_backend,
            client_frontend,
            # firmware image
            disk_backend,
            disk_frontend
        ]

        for ifname, network in self.networks:
            role = "listen" if network.needs_listener else "connect"

            start_command.extend(
                [
                    f"-device {nic_driver},addr={hex(0xA + network.id)},netdev={network.name}",
                    f"-netdev socket,id={network.name},{role}=:{network.port}",
                ]
            )

            self.config_mode_commands.extend([
                # configure network for wired meshing
                f"uci set network.{ifname}_mesh=interface",
                f"uci set network.{ifname}_mesh.auto=1",
                f"uci set network.{ifname}_mesh.proto=gluon_wired",
                f"uci set network.{ifname}_mesh.ifname={ifname}",

                # allow vxlan traffic over the newly created interfaces
                f"uci add_list firewall.wired_mesh.network={ifname}_mesh"
            ])

        print(" \\\n\t".join(start_command))

        return " ".join(start_command)

    def run(self):
        def process_serial_output(machine, prevent_clear=True) -> None:
            # Remove ANSII sequences that make text unnecessarily hard to read, especially GRUB output
            # Taken from https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python/38662876#38662876
            def escape_ansi(line):
                ansi_escape = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
                return ansi_escape.sub("", line)

            assert machine.process.stdout is not None
            for _line in machine.process.stdout:
                # Ignore undecodable bytes that may occur in boot menus
                line = escape_ansi(_line.decode(errors="ignore").replace("\r", "").rstrip())
                if prevent_clear:
                    line = line.replace("\033", "")
                if line:
                    machine.log(line)
                #print(":".join("{:02x}".format(ord(c)) for c in line))
                # self.logger.enqueue({"msg": line, "machine": self.name})

        if self.started:
            return

        environment = dict(os.environ)
        environment.update(
            {"TMPDIR": self.temp_dir, "USE_TMPDIR": "1", "SHARED_DIR": self.temp_dir,}
        )

        self.process = subprocess.Popen(
            self.run_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            cwd=self.temp_dir,
            env=environment,
        )
        self.started = time.time()

        self.monitor, _ = self.monitor_socket.accept()
        self.shell, _ = self.shell_socket.accept()

        _thread.start_new_thread(process_serial_output, (self, True))

        self.pid = self.process.pid
        print(f"QEMU for {self.name} running under PID {self.pid}")

        atexit.register(self.shutdown)

        self.wait_for_monitor_prompt()
        self.wait_until_booted()
        self.run_hooks()

    def wait_until_booted(self):
        self.wait_for_console()

        sys.stdout.flush()

        self.get_state()

    def ensure_up(self):
        if self.started:
            return

        self.run()

    def get_state(self):
        # wait until network is up, then check for /var/gluon/setup-mode to determine if we're in config mode
        self.execute("ubus -t 30 wait_for network.interface")
        status, _ = self.execute("test -d /var/gluon/setup-mode")

        if status == 0:
            self.configmode = True
        else:
            self.configmode = False

    def run_hooks(self):
        if self.configmode:
            self.log("Booted into config mode", bold=True)
            if not self.config_mode_commands:
                return

            while self.config_mode_commands:
                command = self.config_mode_commands.pop(0)
                self.execute(command)

            self.succeed("uci commit")

            # wait for overlay completion marker
            self.wait_until_succeeds("readlink /overlay/.fs_state | grep 2")

            self.log("Rebooting from config mode into normal mode", bold=True)
            self.reboot()
        else:
            self.log("Booted into normal mode", bold=True)

    def execute(self, command):
        self.ensure_up()
        #self.log(f"Execute: {command}")

        # append an output end marker that includes the exit code
        out_command = "( {} ); echo '|!EOF' $?\n".format(command)
        self.shell.send(out_command.encode())
        sys.stdout.flush()

        output = ""
        status_code_pattern = re.compile(r"(.*)\|\!EOF\s+(\d+)")

        while True:
            chunk = self.shell.recv(4096).decode(errors="ignore")
            sys.stdout.flush()
            match = status_code_pattern.match(chunk)
            if match:
                output += match[1]
                status_code = int(match[2])
                #for line in output.split('\n'):
                #    self.log(f"LINE: {line}")
                return (
                    status_code,
                    output[
                        output.find("echo '|!EOF' $?") + len("echo '|!EOF' $?") :
                    ].strip(),
                )
            output += chunk

    def succeed(self, *commands: str) -> str:
        """Execute each command and check that it succeeds."""
        output = ""
        for command in commands:
            self.log(f"Must succeed: {command}", bold=True)
            (status, out) = self.execute(command)
            if status != 0:
                raise Exception(
                "command `{}` failed (exit code {})".format(command, status)
                )
            output += out
        return output

    def wait_until_succeeds(self, command: str) -> str:
        """Wait until a command returns success and return its output.
        Throws an exception on timeout.
        """
        output = ""

        self.log(f"Wait until succeeds: {command}", bold=True)

        def check_success(_: Any) -> bool:
            nonlocal output
            status, output = self.execute(command)
            return status == 0

        retry(check_success)
        return output

    def reboot(self):
        self.shell.send("reboot\n".encode())
        sys.stdout.flush()
        self.wait_until_booted()
        self.run_hooks()

    def shutdown(self):
        try:
            self.shell.send("poweroff\n".encode())
        except BrokenPipeError:
            # This case can occur when the VM was terminated early, don't worry about it.
            pass
        self.wait_for_shutdown()

    def wait_for_shutdown(self):
        sys.stdout.flush()
        self.process.wait()

    def wait_for_monitor_prompt(self):
        assert self.monitor is not None

        answer = ""
        while True:
            undecoded_answer = self.monitor.recv(1024)
            if not undecoded_answer:
                break
            answer += undecoded_answer.decode()
            if answer.endswith("(qemu) "):
                break
        return answer

    def wait_until_tty_matches(self, pattern):
        assert self.shell is not None

        _pattern = re.compile(pattern)

        chunks = ""
        while True:
            chunk = self.shell.recv(4096).decode(errors="ignore")
            match = _pattern.search(chunk)
            if match:
                return True

    def wait_for_console(self):
        self.wait_until_tty_matches(r"^Please press Enter to activate this console\.$")

        sys.stdout.flush()

        # press enter
        self.shell.send("\n".encode())

        # wait for prompt
        pattern = re.compile(r"root@[()0-9a-zA-Z-]+:/#")
        output = ""
        while True:
            chunk = self.shell.recv(4096).decode(errors="ignore")
            output += chunk
            if pattern.search(chunk):
                for line in output.split('\n'):
                    self.log(line)

                return True


if __name__ == "__main__":
    a = Node()
    b = Node()
    a.connect(b)

    start_all()

    a.execute("ubus wait_for -t 60 network.interface.wan")

    addrs = a.succeed("ip addr")
    a.log(addrs)

    routes = a.succeed("ip route")
    a.log(routes)

    batctl_version = a.succeed("batctl -v")
    a.log(batctl_version)

    batctl_neighbours = a.succeed("batctl n")
    a.log(batctl_neighbours)

    links = b.succeed("ip link")
    b.log(links)

    a.wait_until_succeeds("gluon-wan wget -4 http://ifconfig.me")

