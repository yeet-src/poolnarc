// SPDX-License-Identifier: GPL-2.0
/*
 * poolnarc — kernel-side observer for outbound TCP, with per-conn
 * byte accounting and process attribution. All mining classification
 * happens in userspace; the kernel just streams events.
 *
 * Three CO-RE hooks (require CONFIG_DEBUG_INFO_BTF + libbpf reloc):
 *   tp_btf/inet_sock_set_state   lifecycle (ESTABLISHED, CLOSE)
 *   fentry/tcp_sendmsg           tx bytes + pid fixup (app ctx)
 *   fentry/tcp_cleanup_rbuf      rx bytes + pid fixup (app ctx)
 *
 * One HASH map (conns, keyed by sock pointer). One RINGBUF (256 KiB)
 * carrying OPEN, BYTES (delta every 64 KiB), CLOSE.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET   2
#define AF_INET6 10

#define TCP_ESTABLISHED 1
#define TCP_CLOSE       7

#define EVT_OPEN  0
#define EVT_BYTES 1
#define EVT_CLOSE 2

#define BYTES_EMIT_THRESHOLD (64 * 1024)
#define MAX_TRACKED          (1 << 16)

#define FLAG_OPEN_EMITTED  (1 << 0)
#define FLAG_PID_REAL      (1 << 1)

char LICENSE[] SEC("license") = "GPL";

/* ---- per-conn state ------------------------------------------------ */
struct conn_info {
    __u64 ts_open_ns;
    __u32 pid;
    __u8  family;
    __u8  flags;
    __u16 sport;            /* host order */
    __u16 dport;            /* host order */
    __u8  _pad[2];
    __u8  saddr[16];
    __u8  daddr[16];
    char  comm[16];
    __u64 bytes_tx;
    __u64 bytes_rx;
    __u64 emitted_tx;
    __u64 emitted_rx;
};

/* ---- userspace event shape ----------------------------------------- */
struct conn_evt {
    __u8  kind;             /* EVT_OPEN | EVT_BYTES | EVT_CLOSE */
    __u8  family;
    __u8  _pad0[2];
    __u32 pid;
    __u64 sk;
    __u64 ts_ns;
    __u64 bytes_tx;
    __u64 bytes_rx;
    __u64 delta_tx;
    __u64 delta_rx;
    __u16 sport;
    __u16 dport;
    __u8  _pad1[4];
    char  comm[16];
    __u8  saddr[16];
    __u8  daddr[16];
};

__attribute__((used)) static const struct conn_evt __conn_evt_anchor;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TRACKED);
    __type(key,   __u64);
    __type(value, struct conn_info);
} conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

/* ---- helpers ------------------------------------------------------- */

/* Reject kernel-thread comms as the real owner. TCP state transitions
 * fire from softirq; we wait for tcp_sendmsg/cleanup_rbuf in app
 * context to get the true PID. */
static __always_inline int is_kernel_comm(const char *c) {
    if (c[0] == 's' && c[1] == 'w' && c[2] == 'a' && c[3] == 'p') return 1;  /* swapper */
    if (c[0] == 'k' && c[1] == 'w' && c[2] == 'o' && c[3] == 'r') return 1;  /* kworker */
    if (c[0] == 'k' && c[1] == 's' && c[2] == 'o' && c[3] == 'f') return 1;  /* ksoftirqd */
    return 0;
}

/* Read addrs/ports/family off the sock via CO-RE accessors. */
static __always_inline void fill_addrs(struct sock *sk, struct conn_info *ci) {
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    ci->family = (__u8)family;
    ci->sport  = BPF_CORE_READ(sk, __sk_common.skc_num);
    ci->dport  = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    __builtin_memset(ci->saddr, 0, sizeof(ci->saddr));
    __builtin_memset(ci->daddr, 0, sizeof(ci->daddr));

    if (family == AF_INET) {
        __be32 s4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 d4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(ci->saddr, &s4, 4);
        __builtin_memcpy(ci->daddr, &d4, 4);
    } else if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&ci->saddr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&ci->daddr, sk, __sk_common.skc_v6_daddr);
    }
}

static __always_inline void fill_evt(struct conn_evt *e, struct sock *sk,
                                     struct conn_info *ci, __u8 kind) {
    __builtin_memset(e, 0, sizeof(*e));
    e->kind     = kind;
    e->family   = ci->family;
    e->pid      = ci->pid;
    e->sk       = (__u64)sk;
    e->ts_ns    = bpf_ktime_get_ns();
    e->bytes_tx = ci->bytes_tx;
    e->bytes_rx = ci->bytes_rx;
    e->sport    = ci->sport;
    e->dport    = ci->dport;
    __builtin_memcpy(e->comm,  ci->comm,  sizeof(e->comm));
    __builtin_memcpy(e->saddr, ci->saddr, sizeof(e->saddr));
    __builtin_memcpy(e->daddr, ci->daddr, sizeof(e->daddr));
}

/* ---- lifecycle ---------------------------------------------------- */
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(on_set_state, struct sock *sk, int oldstate, int newstate) {
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) return 0;

    __u64 key = (__u64)sk;

    if (newstate == TCP_ESTABLISHED) {
        struct conn_info *existing = bpf_map_lookup_elem(&conns, &key);
        if (existing) return 0;

        struct conn_info ci = {};
        ci.ts_open_ns = bpf_ktime_get_ns();

        __u64 pt = bpf_get_current_pid_tgid();
        ci.pid = pt >> 32;
        bpf_get_current_comm(ci.comm, sizeof(ci.comm));
        if (!is_kernel_comm(ci.comm)) ci.flags |= FLAG_PID_REAL;

        fill_addrs(sk, &ci);
        bpf_map_update_elem(&conns, &key, &ci, BPF_ANY);
        return 0;
    }

    if (newstate == TCP_CLOSE) {
        struct conn_info *ci = bpf_map_lookup_elem(&conns, &key);
        if (!ci) return 0;

        struct conn_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            bpf_map_delete_elem(&conns, &key);
            return 0;
        }
        fill_evt(e, sk, ci, EVT_CLOSE);
        bpf_ringbuf_submit(e, 0);
        bpf_map_delete_elem(&conns, &key);
        return 0;
    }

    return 0;
}

/* ---- bytes sent --------------------------------------------------- */
SEC("fentry/tcp_sendmsg")
int BPF_PROG(on_sendmsg, struct sock *sk, struct msghdr *msg, __u64 size) {
    if (size == 0) return 0;
    __u64 key = (__u64)sk;
    struct conn_info *ci = bpf_map_lookup_elem(&conns, &key);
    if (!ci) return 0;

    /* PID fixup. Once FLAG_PID_REAL is set, attribution is locked.
     * A "kworker" process locked here is the hidden miner -- real
     * kernel threads never reach this code path in app context. */
    if (!(ci->flags & FLAG_PID_REAL)) {
        char comm[16];
        bpf_get_current_comm(comm, sizeof(comm));
        if (!is_kernel_comm(comm)) {
            __u64 pt = bpf_get_current_pid_tgid();
            ci->pid = pt >> 32;
            __builtin_memcpy(ci->comm, comm, sizeof(ci->comm));
            ci->flags |= FLAG_PID_REAL;
        }
    }

    ci->bytes_tx += size;

    if (!(ci->flags & FLAG_OPEN_EMITTED) && (ci->flags & FLAG_PID_REAL)) {
        struct conn_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            fill_evt(e, sk, ci, EVT_OPEN);
            bpf_ringbuf_submit(e, 0);
        }
        ci->flags |= FLAG_OPEN_EMITTED;
    }

    __u64 dtx = ci->bytes_tx - ci->emitted_tx;
    if (dtx >= BYTES_EMIT_THRESHOLD) {
        struct conn_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            fill_evt(e, sk, ci, EVT_BYTES);
            e->delta_tx = dtx;
            e->delta_rx = ci->bytes_rx - ci->emitted_rx;
            ci->emitted_tx = ci->bytes_tx;
            ci->emitted_rx = ci->bytes_rx;
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}

/* ---- bytes received ----------------------------------------------- */
SEC("fentry/tcp_cleanup_rbuf")
int BPF_PROG(on_cleanup_rbuf, struct sock *sk, int copied) {
    if (copied <= 0) return 0;
    __u64 key = (__u64)sk;
    struct conn_info *ci = bpf_map_lookup_elem(&conns, &key);
    if (!ci) return 0;

    if (!(ci->flags & FLAG_PID_REAL)) {
        char comm[16];
        bpf_get_current_comm(comm, sizeof(comm));
        if (!is_kernel_comm(comm)) {
            __u64 pt = bpf_get_current_pid_tgid();
            ci->pid = pt >> 32;
            __builtin_memcpy(ci->comm, comm, sizeof(ci->comm));
            ci->flags |= FLAG_PID_REAL;
        }
    }

    ci->bytes_rx += (__u64)copied;

    if (!(ci->flags & FLAG_OPEN_EMITTED) && (ci->flags & FLAG_PID_REAL)) {
        struct conn_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            fill_evt(e, sk, ci, EVT_OPEN);
            bpf_ringbuf_submit(e, 0);
        }
        ci->flags |= FLAG_OPEN_EMITTED;
    }

    __u64 drx = ci->bytes_rx - ci->emitted_rx;
    if (drx >= BYTES_EMIT_THRESHOLD) {
        struct conn_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            fill_evt(e, sk, ci, EVT_BYTES);
            e->delta_tx = ci->bytes_tx - ci->emitted_tx;
            e->delta_rx = drx;
            ci->emitted_tx = ci->bytes_tx;
            ci->emitted_rx = ci->bytes_rx;
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}
