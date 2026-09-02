# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* eBPF: пассивный мониторинг TCP/UDP + атрибуция к процессу.
 *
 * MVP hooks (можно расширять / переводить на fentry при наличии BTF):
 *   - tcp_v4_connect / tcp_v6_connect
 *   - inet_csk_accept
 *   - tcp_close
 *   - udp_sendmsg / udp_recvmsg
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define __BPF__
#include "netmon.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MiB */
} events SEC(".maps");

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

static __always_inline void ipv4_tuple(struct netmon_event *e,
				       __be32 saddr, __be32 daddr,
				       __u16 sport, __u16 dport)
{
	e->family = NETMON_AF_INET;
	__builtin_memset(e->saddr, 0, sizeof(e->saddr));
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));
	__builtin_memcpy(e->saddr, &saddr, 4);
	__builtin_memcpy(e->daddr, &daddr, 4);
	e->sport = sport;
	e->dport = dport;
}

/* ---- TCP connect (IPv4) ---- */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_tcp_v4_connect, struct sock *sk)
{
	struct netmon_event *e;
	struct sock_common *skc;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	fill_task(e);
	e->type = NETMON_EVT_TCP_CONNECT;
	e->protocol = IPPROTO_TCP;

	skc = (struct sock_common *)sk;
	ipv4_tuple(e,
		   BPF_CORE_READ(skc, skc_rcv_saddr),
		   BPF_CORE_READ(skc, skc_daddr),
		   bpf_ntohs(BPF_CORE_READ(skc, skc_num)),
		   bpf_ntohs(BPF_CORE_READ(skc, skc_dport)));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---- TCP accept ---- */
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_inet_csk_accept, struct sock *sk)
{
	struct netmon_event *e;
	struct sock_common *skc;

	if (!sk)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	fill_task(e);
	e->type = NETMON_EVT_TCP_ACCEPT;
	e->protocol = IPPROTO_TCP;

	skc = (struct sock_common *)sk;
	ipv4_tuple(e,
		   BPF_CORE_READ(skc, skc_rcv_saddr),
		   BPF_CORE_READ(skc, skc_daddr),
		   bpf_ntohs(BPF_CORE_READ(skc, skc_num)),
		   bpf_ntohs(BPF_CORE_READ(skc, skc_dport)));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---- TCP close ---- */
SEC("kprobe/tcp_close")
int BPF_KPROBE(handle_tcp_close, struct sock *sk)
{
	struct netmon_event *e;
	struct sock_common *skc;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	fill_task(e);
	e->type = NETMON_EVT_TCP_CLOSE;
	e->protocol = IPPROTO_TCP;

	skc = (struct sock_common *)sk;
	ipv4_tuple(e,
		   BPF_CORE_READ(skc, skc_rcv_saddr),
		   BPF_CORE_READ(skc, skc_daddr),
		   bpf_ntohs(BPF_CORE_READ(skc, skc_num)),
		   bpf_ntohs(BPF_CORE_READ(skc, skc_dport)));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---- UDP send ---- */
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(handle_udp_sendmsg, struct sock *sk, struct msghdr *msg)
{
	struct netmon_event *e;
	struct sock_common *skc;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	fill_task(e);
	e->type = NETMON_EVT_UDP_SEND;
	e->protocol = IPPROTO_UDP;
	/* Полный разбор msg->msg_iter — следующий шаг; пока 0 */
	e->bytes = 0;

	skc = (struct sock_common *)sk;
	ipv4_tuple(e,
		   BPF_CORE_READ(skc, skc_rcv_saddr),
		   BPF_CORE_READ(skc, skc_daddr),
		   bpf_ntohs(BPF_CORE_READ(skc, skc_num)),
		   bpf_ntohs(BPF_CORE_READ(skc, skc_dport)));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---- UDP recv ---- */
SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(handle_udp_recvmsg, struct sock *sk)
{
	struct netmon_event *e;
	struct sock_common *skc;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	fill_task(e);
	e->type = NETMON_EVT_UDP_RECV;
	e->protocol = IPPROTO_UDP;
	e->bytes = 0;

	skc = (struct sock_common *)sk;
	ipv4_tuple(e,
		   BPF_CORE_READ(skc, skc_rcv_saddr),
		   BPF_CORE_READ(skc, skc_daddr),
		   bpf_ntohs(BPF_CORE_READ(skc, skc_num)),
		   bpf_ntohs(BPF_CORE_READ(skc, skc_dport)));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

