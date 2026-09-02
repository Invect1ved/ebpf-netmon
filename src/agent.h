/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef AGENT_H
#define AGENT_H

#include <stdbool.h>
#include <stdint.h>

#include "netmon.h"

struct agent_config {
	bool json;
	bool skip_loopback;
	int stats_interval_sec; /* 0 = disabled */
};

struct proc_stats {
	uint32_t tgid;
	char comm[NETMON_COMM_LEN];
	uint64_t tcp_connect;
	uint64_t tcp_accept;
	uint64_t tcp_close;
	uint64_t udp_send;
	uint64_t udp_recv;
	uint64_t packets;
	uint64_t bytes;
};

int agent_run(const struct agent_config *cfg);

void agent_print_event(const struct netmon_event *e, bool json);
void agent_stats_update(const struct netmon_event *e);
void agent_stats_print(bool json);

#endif /* AGENT_H */
