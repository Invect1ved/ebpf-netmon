/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "agent.h"
#include "netmon.skel.h"

#define MAX_PROCS 4096

static volatile sig_atomic_t exiting;

static struct proc_stats g_stats[MAX_PROCS];
static size_t g_nstats;
static bool g_json;

static void on_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

static const char *event_name(__u32 type)
{
	switch (type) {
	case NETMON_EVT_TCP_CONNECT: return "tcp_connect";
	case NETMON_EVT_TCP_ACCEPT:  return "tcp_accept";
	case NETMON_EVT_TCP_CLOSE:   return "tcp_close";
	case NETMON_EVT_UDP_SEND:    return "udp_send";
	case NETMON_EVT_UDP_RECV:    return "udp_recv";
	default:                     return "unknown";
	}
}

static void format_ip(const struct netmon_event *e, char *src, char *dst, size_t n)
{
	if (e->family == NETMON_AF_INET) {
		inet_ntop(AF_INET, e->saddr, src, (socklen_t)n);
		inet_ntop(AF_INET, e->daddr, dst, (socklen_t)n);
	} else if (e->family == NETMON_AF_INET6) {
		inet_ntop(AF_INET6, e->saddr, src, (socklen_t)n);
		inet_ntop(AF_INET6, e->daddr, dst, (socklen_t)n);
	} else {
		snprintf(src, n, "?");
		snprintf(dst, n, "?");
	}
}

void agent_print_event(const struct netmon_event *e, bool json)
{
	char src[64], dst[64];
	const char *af = e->family == NETMON_AF_INET6 ? "v6" : "v4";

	format_ip(e, src, dst, sizeof(src));

	if (json) {
		printf("{\"type\":\"%s\",\"af\":\"%s\",\"tgid\":%u,\"pid\":%u,\"uid\":%u,"
		       "\"comm\":\"%s\",\"src\":\"%s\",\"sport\":%u,"
		       "\"dst\":\"%s\",\"dport\":%u,\"bytes\":%u,\"packets\":%u,"
		       "\"ts_ns\":%llu}\n",
		       event_name(e->type), af, e->tgid, e->pid, e->uid, e->comm,
		       src, e->sport, dst, e->dport, e->bytes, e->packets,
		       (unsigned long long)e->ts_ns);
	} else {
		printf("%-12s %-2s tgid=%-6u pid=%-6u %-16s %s:%u -> %s:%u bytes=%u pkts=%u\n",
		       event_name(e->type), af, e->tgid, e->pid, e->comm,
		       src, e->sport, dst, e->dport, e->bytes, e->packets);
	}
}

void agent_stats_update(const struct netmon_event *e)
{
	struct proc_stats *s = NULL;

	for (size_t i = 0; i < g_nstats; i++) {
		if (g_stats[i].tgid == e->tgid) {
			s = &g_stats[i];
			break;
		}
	}
	if (!s) {
		if (g_nstats >= MAX_PROCS)
			return;
		s = &g_stats[g_nstats++];
		memset(s, 0, sizeof(*s));
		s->tgid = e->tgid;
		memcpy(s->comm, e->comm, sizeof(s->comm));
	}

	switch (e->type) {
	case NETMON_EVT_TCP_CONNECT: s->tcp_connect++; break;
	case NETMON_EVT_TCP_ACCEPT:  s->tcp_accept++;  break;
	case NETMON_EVT_TCP_CLOSE:   s->tcp_close++;   break;
	case NETMON_EVT_UDP_SEND:    s->udp_send += e->packets ? e->packets : 1; break;
	case NETMON_EVT_UDP_RECV:    s->udp_recv += e->packets ? e->packets : 1; break;
	default: break;
	}
	s->packets += e->packets ? e->packets : 1;
	s->bytes += e->bytes;
}

void agent_stats_print(bool json)
{
	if (json) {
		printf("{\"stats\":[");
		for (size_t i = 0; i < g_nstats; i++) {
			struct proc_stats *s = &g_stats[i];
			printf("%s{\"tgid\":%u,\"comm\":\"%s\",\"tcp_connect\":%llu,"
			       "\"tcp_accept\":%llu,\"tcp_close\":%llu,"
			       "\"udp_send\":%llu,\"udp_recv\":%llu,"
			       "\"packets\":%llu,\"bytes\":%llu}",
			       i ? "," : "", s->tgid, s->comm,
			       (unsigned long long)s->tcp_connect,
			       (unsigned long long)s->tcp_accept,
			       (unsigned long long)s->tcp_close,
			       (unsigned long long)s->udp_send,
			       (unsigned long long)s->udp_recv,
			       (unsigned long long)s->packets,
			       (unsigned long long)s->bytes);
		}
		printf("]}\n");
		return;
	}

	printf("\n=== process traffic summary ===\n");
	printf("%-8s %-16s %8s %8s %8s %8s %8s %10s %10s\n",
	       "tgid", "comm", "t_conn", "t_acc", "t_cls", "u_snd", "u_rcv", "pkts", "bytes");
	for (size_t i = 0; i < g_nstats; i++) {
		struct proc_stats *s = &g_stats[i];
		printf("%-8u %-16s %8llu %8llu %8llu %8llu %8llu %10llu %10llu\n",
		       s->tgid, s->comm,
		       (unsigned long long)s->tcp_connect,
		       (unsigned long long)s->tcp_accept,
		       (unsigned long long)s->tcp_close,
		       (unsigned long long)s->udp_send,
		       (unsigned long long)s->udp_recv,
		       (unsigned long long)s->packets,
		       (unsigned long long)s->bytes);
	}
	printf("\n");
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct netmon_event *e = data;

	(void)ctx;
	if (len < sizeof(*e))
		return 0;

	agent_print_event(e, g_json);
	agent_stats_update(e);
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static int apply_config(struct netmon_bpf *skel, const struct agent_config *cfg)
{
	__u32 key = 0;
	struct netmon_config c = {
		.skip_loopback = cfg->skip_loopback ? 1 : 0,
	};
	int fd = bpf_map__fd(skel->maps.config_map);

	if (fd < 0) {
		fprintf(stderr, "config_map fd unavailable\n");
		return -1;
	}
	if (bpf_map_update_elem(fd, &key, &c, BPF_ANY)) {
		fprintf(stderr, "failed to update config_map: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int agent_run(const struct agent_config *cfg)
{
	struct netmon_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	int err = 0;
	time_t last_stats = time(NULL);

	g_json = cfg->json;
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	skel = netmon_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	err = netmon_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF: %d\n", err);
		goto cleanup;
	}

	if (apply_config(skel, cfg)) {
		err = 1;
		goto cleanup;
	}

	err = netmon_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		err = -errno;
		goto cleanup;
	}

	fprintf(stderr,
		"netmon attached (skip_loopback=%s); waiting for events (Ctrl+C to stop)\n",
		cfg->skip_loopback ? "on" : "off");

	while (!exiting) {
		err = ring_buffer__poll(rb, 200);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "ring_buffer__poll: %d\n", err);
			break;
		}
		err = 0;

		if (cfg->stats_interval_sec > 0) {
			time_t now = time(NULL);
			if (now - last_stats >= cfg->stats_interval_sec) {
				agent_stats_print(cfg->json);
				last_stats = now;
			}
		}
	}

	agent_stats_print(cfg->json);

cleanup:
	ring_buffer__free(rb);
	netmon_bpf__destroy(skel);
	return err != 0;
}
