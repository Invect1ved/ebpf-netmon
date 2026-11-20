// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* eBPF: пассивный мониторинг TCP/UDP + атрибуция к процессу.
 *
 * Hooks:
 *   - tcp_v4_connect / tcp_v6_connect
 *   - inet_csk_accept (kretprobe)
 *   - tcp_close
 *   - udp_sendmsg / udp_recvmsg
 *
 * Features (stage 2):
 *   - IPv4 + IPv6 tuples from sock_common
 *   - UDP payload length via msg_iter.count
 *   - optional skip_loopback via config map
 *   - sock* → owner cache for more stable process attribution
 *   - UDP flow aggregation to reduce ringbuf noise
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* vmlinux.h не тащит uapi AF_* */
#ifndef AF_INET
#define AF_INET  2
#define AF_INET6 10
#endif

#include "netmon.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define UDP_FLUSH_PACKETS 16
#define UDP_FLUSH_NS      1000000000ULL /* 1s */

struct sock_owner {
	__u32 tgid;
	__u32 pid;
	__u32 uid;
	char  comm[NETMON_COMM_LEN];
};

struct udp_flow_key {
	__u32 tgid;
	__u32 family;
	__u16 sport;
	__u16 dport;
	__u8  saddr[16];
	__u8  daddr[16];
	__u8  dir; /* NETMON_EVT_UDP_SEND or NETMON_EVT_UDP_RECV */
	__u8  pad[3];
};

struct udp_flow_val {
	__u64 packets;
	__u64 bytes;
	__u64 last_flush_ts;
	__u32 pid;
	__u32 uid;
	char  comm[NETMON_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct netmon_config);
	__uint(max_entries, 1);
} config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); /* (u64)struct sock * */
	__type(value, struct sock_owner);
	__uint(max_entries, 16384);
} sock_owners SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct udp_flow_key);
	__type(value, struct udp_flow_val);
	__uint(max_entries, 8192);
} udp_flows SEC(".maps");

static __always_inline bool skip_loopback_enabled(void)
{
	__u32 key = 0;
	struct netmon_config *cfg = bpf_map_lookup_elem(&config_map, &key);

	return cfg && cfg->skip_loopback;
}

static __always_inline bool is_loopback_addrs(const struct netmon_event *e)
{
	if (e->family == NETMON_AF_INET) {
		__u32 s, d;

		__builtin_memcpy(&s, e->saddr, 4);
		__builtin_memcpy(&d, e->daddr, 4);
		s = bpf_ntohl(s);
		d = bpf_ntohl(d);
		if ((s >> 24) == 127 || (d >> 24) == 127)
			return true;
	} else if (e->family == NETMON_AF_INET6) {
		/* ::1 — 15 zero bytes + 0x01 */
		int i;
		bool s_loop = true, d_loop = true;

		for (i = 0; i < 15; i++) {
			if (e->saddr[i])
				s_loop = false;
			if (e->daddr[i])
				d_loop = false;
		}
		if (!(s_loop && e->saddr[15] == 1))
			s_loop = false;
		if (!(d_loop && e->daddr[15] == 1))
			d_loop = false;
		if (s_loop || d_loop)
			return true;
	}
	return false;
}

static __always_inline void fill_task(struct netmon_event *e)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = (__u32)pid_tgid;
	e->tgid = (__u32)(pid_tgid >> 32);
	e->uid = (__u32)uid_gid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void remember_sock(struct sock *sk, const struct netmon_event *e)
{
	struct sock_owner own = {};
	__u64 key = (__u64)sk;

	own.tgid = e->tgid;
	own.pid = e->pid;
	own.uid = e->uid;
	__builtin_memcpy(own.comm, e->comm, sizeof(own.comm));
	bpf_map_update_elem(&sock_owners, &key, &own, BPF_ANY);
}

static __always_inline void forget_sock(struct sock *sk)
{
	__u64 key = (__u64)sk;

	bpf_map_delete_elem(&sock_owners, &key);
}

static __always_inline void apply_sock_owner(struct sock *sk, struct netmon_event *e)
{
	__u64 key = (__u64)sk;
	struct sock_owner *own = bpf_map_lookup_elem(&sock_owners, &key);

	if (!own)
		return;
	e->tgid = own->tgid;
	e->pid = own->pid;
	e->uid = own->uid;
	__builtin_memcpy(e->comm, own->comm, sizeof(e->comm));
}

static __always_inline int fill_tuple_from_sock(struct netmon_event *e, struct sock *sk)
{
	struct sock_common *skc = (struct sock_common *)sk;
	__u16 family = BPF_CORE_READ(skc, skc_family);

	e->sport = BPF_CORE_READ(skc, skc_num);
	e->dport = bpf_ntohs(BPF_CORE_READ(skc, skc_dport));
	__builtin_memset(e->saddr, 0, sizeof(e->saddr));
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));

	if (family == AF_INET) {
		__be32 saddr = BPF_CORE_READ(skc, skc_rcv_saddr);
		__be32 daddr = BPF_CORE_READ(skc, skc_daddr);

		e->family = NETMON_AF_INET;
		__builtin_memcpy(e->saddr, &saddr, 4);
		__builtin_memcpy(e->daddr, &daddr, 4);
		return 0;
	}

	if (family == AF_INET6) {
		e->family = NETMON_AF_INET6;
		BPF_CORE_READ_INTO(&e->saddr, skc, skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&e->daddr, skc, skc_v6_daddr.in6_u.u6_addr8);
		return 0;
	}

	return -1;
}

static __always_inline int emit_event(struct netmon_event *tmpl)
{
	struct netmon_event *e;

	if (skip_loopback_enabled() && is_loopback_addrs(tmpl))
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memcpy(e, tmpl, sizeof(*e));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int handle_tcp_connect(struct sock *sk)
{
	struct netmon_event ev = {};

	fill_task(&ev);
	ev.type = NETMON_EVT_TCP_CONNECT;
	ev.protocol = IPPROTO_TCP;
	ev.packets = 1;
	if (fill_tuple_from_sock(&ev, sk))
		return 0;
	remember_sock(sk, &ev);
	return emit_event(&ev);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_tcp_v4_connect, struct sock *sk)
{
	return handle_tcp_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(handle_tcp_v6_connect, struct sock *sk)
{
	return handle_tcp_connect(sk);
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_inet_csk_accept, struct sock *sk)
{
	struct netmon_event ev = {};

	if (!sk)
		return 0;

	fill_task(&ev);
	ev.type = NETMON_EVT_TCP_ACCEPT;
	ev.protocol = IPPROTO_TCP;
	ev.packets = 1;
	if (fill_tuple_from_sock(&ev, sk))
		return 0;
	remember_sock(sk, &ev);
	return emit_event(&ev);
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(handle_tcp_close, struct sock *sk)
{
	struct netmon_event ev = {};

	fill_task(&ev);
	apply_sock_owner(sk, &ev);
	ev.type = NETMON_EVT_TCP_CLOSE;
	ev.protocol = IPPROTO_TCP;
	ev.packets = 1;
	if (fill_tuple_from_sock(&ev, sk)) {
		forget_sock(sk);
		return 0;
	}
	emit_event(&ev);
	forget_sock(sk);
	return 0;
}

static __always_inline int handle_udp(struct sock *sk, struct msghdr *msg, __u32 type)
{
	struct netmon_event ev = {};
	struct udp_flow_key key = {};
	struct udp_flow_val *val;
	struct udp_flow_val neo = {};
	__u32 nbytes = 0;
	__u64 now;
	bool flush;

	fill_task(&ev);
	apply_sock_owner(sk, &ev);
	ev.type = type;
	ev.protocol = IPPROTO_UDP;
	if (fill_tuple_from_sock(&ev, sk))
		return 0;

	if (msg)
		nbytes = (__u32)BPF_CORE_READ(msg, msg_iter.count);
	ev.bytes = nbytes;
	ev.packets = 1;

	if (skip_loopback_enabled() && is_loopback_addrs(&ev))
		return 0;

	remember_sock(sk, &ev);

	key.tgid = ev.tgid;
	key.family = ev.family;
	key.sport = ev.sport;
	key.dport = ev.dport;
	key.dir = (__u8)type;
	__builtin_memcpy(key.saddr, ev.saddr, 16);
	__builtin_memcpy(key.daddr, ev.daddr, 16);

	now = bpf_ktime_get_ns();
	val = bpf_map_lookup_elem(&udp_flows, &key);
	if (!val) {
		/* First packet of a flow is emitted immediately; counters start fresh. */
		neo.packets = 0;
		neo.bytes = 0;
		neo.last_flush_ts = now;
		neo.pid = ev.pid;
		neo.uid = ev.uid;
		__builtin_memcpy(neo.comm, ev.comm, sizeof(neo.comm));
		bpf_map_update_elem(&udp_flows, &key, &neo, BPF_ANY);
		return emit_event(&ev);
	}

	val->packets += 1;
	val->bytes += nbytes;

	flush = (val->packets % UDP_FLUSH_PACKETS) == 0 ||
		(now - val->last_flush_ts) >= UDP_FLUSH_NS;
	if (!flush)
		return 0;

	ev.packets = (__u32)val->packets;
	ev.bytes = (__u32)val->bytes;
	ev.pid = val->pid;
	ev.uid = val->uid;
	__builtin_memcpy(ev.comm, val->comm, sizeof(ev.comm));
	val->packets = 0;
	val->bytes = 0;
	val->last_flush_ts = now;
	return emit_event(&ev);
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(handle_udp_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return handle_udp(sk, msg, NETMON_EVT_UDP_SEND);
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(handle_udp_recvmsg, struct sock *sk, struct msghdr *msg)
{
	/* len often unknown until return; msg_iter may still expose bound. */
	return handle_udp(sk, msg, NETMON_EVT_UDP_RECV);
}
