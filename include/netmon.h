/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef NETMON_H
#define NETMON_H

#ifdef __BPF__
/* Types come from vmlinux.h (included before this header in .bpf.c). */
#else
#include <linux/types.h>
#endif

#define NETMON_COMM_LEN 16

enum netmon_event_type {
	NETMON_EVT_TCP_CONNECT = 1,
	NETMON_EVT_TCP_ACCEPT  = 2,
	NETMON_EVT_TCP_CLOSE   = 3,
	NETMON_EVT_UDP_SEND    = 4,
	NETMON_EVT_UDP_RECV    = 5,
};

enum netmon_af {
	NETMON_AF_INET  = 2,
	NETMON_AF_INET6 = 10,
};

/* Runtime toggles (BPF array map index 0). */
struct netmon_config {
	__u32 skip_loopback; /* 1 = drop 127.0.0.0/8 and ::1 */
};

struct netmon_event {
	__u64 ts_ns;
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 type;      /* enum netmon_event_type */
	__u32 family;    /* NETMON_AF_* */
	__u32 protocol;  /* IPPROTO_TCP / IPPROTO_UDP */
	__u16 sport;
	__u16 dport;
	__u8  saddr[16]; /* IPv4 in first 4 bytes; IPv6 uses all 16 */
	__u8  daddr[16];
	__u32 bytes;     /* payload bytes (UDP) or flushed aggregate */
	__u32 packets;   /* 1 for TCP; flushed packet count for UDP agg */
	char  comm[NETMON_COMM_LEN];
};

#endif /* NETMON_H */
