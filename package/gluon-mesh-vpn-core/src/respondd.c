/*
  Copyright (c) 2021, Aiyion <gluon@aiyionpri.me>
  Copyright (c) 2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <respondd.h>

#include <stdio.h>
#include <string.h>

#include <json-c/json.h>
#include <libgluonutil.h>


char * read_stdout(const char *command) {
	FILE *f = popen(command, "r");
	if (!f)
		return NULL;

	char *line = NULL;
	size_t len = 0;

	ssize_t r = getline(&line, &len, f);

	pclose(f);

	if (r < 0) {
		free(line);
		return NULL;
	}

	/* The len given by getline is the buffer size, not the string length */
	len = strlen(line);

	if (len && line[len-1] == '\n')
		line[len-1] = 0;

	return line;
}

static struct json_object * get_mesh_vpn_enabled() {
	int enabled = -1;
	char *line = read_stdout("exec lua -e 'print(require(\"gluon.mesh-vpn\").enabled())'");

	if (!strcmp(line, "true"))
		enabled = 1;
	if (!strcmp(line, "false"))
		enabled = 0;
	free(line);

	if (enabled < 0)
		return NULL;

	struct json_object *ret = json_object_new_boolean((json_bool)enabled);
	return ret;
}

static struct json_object * get_active_vpn_provider() {
	char *line = read_stdout("exec lua -e 'name, _ = require(\"gluon.mesh-vpn\").get_active_provider(); print(name)'");

	if (!strcmp(line, "nil")) {
		free(line);
		return NULL;
	}

	return gluonutil_wrap_and_free_string(line);
}

static struct json_object * respondd_provider_nodeinfo(void) {
	struct json_object *ret = json_object_new_object();
	struct json_object *network = json_object_new_object();
	struct json_object *mesh_vpn = json_object_new_object();

	json_object_object_add(mesh_vpn, "provider", get_active_vpn_provider());
	json_object_object_add(mesh_vpn, "enabled", get_mesh_vpn_enabled());
	json_object_object_add(network, "mesh_vpn", mesh_vpn);
	json_object_object_add(ret, "network", network);

	return ret;
}

const struct respondd_provider_info respondd_providers[] = {
	{"nodeinfo", respondd_provider_nodeinfo},
	{},
	{}
};