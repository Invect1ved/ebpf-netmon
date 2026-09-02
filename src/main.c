/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"  --json           JSON lines output\n"
		"  --stats SEC      print per-process summary every SEC seconds\n"
		"  -h, --help       show this help\n",
		argv0);
}

int main(int argc, char **argv)
{
	struct agent_config cfg = {
		.json = false,
		.stats_interval_sec = 0,
	};

	static struct option long_opts[] = {
		{"json", no_argument, 0, 'j'},
		{"stats", required_argument, 0, 's'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0},
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "jhs:", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'j':
			cfg.json = true;
			break;
		case 's':
			cfg.stats_interval_sec = atoi(optarg);
			if (cfg.stats_interval_sec < 0)
				cfg.stats_interval_sec = 0;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	return agent_run(&cfg);
}
