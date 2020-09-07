#!/usr/bin/env python3
import sys
from driver import Node, Network, start_all
import asyncio
import time


def test_tpmeter():
    a = Node()
    b = Node()

    a.connect(b)

    start_all()

    b.wait_until_succeeds("ping -c 5 node1")

    addr = a.succeed('cat /sys/class/net/primary0/address')
    result = b.succeed(f'batctl tp {addr}')

    print(result)

