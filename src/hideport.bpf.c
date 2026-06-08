// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define REDIRECT_CONNECT_PORT 1
#define IPV4_LOOPBACK_PREFIX 0x7f000000U
#define PORT_ORDER_NET 1
#define PORT_ORDER_HOST 2
#define MIN_SOCKADDR_PORT_LEN 4
#define MIN_SOCKADDR_IN_LEN 8
#define MIN_SOCKADDR_IN6_LEN 24

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u16);
    __type(value, __u8);
} target_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u8);
} allowed_uids SEC(".maps");

struct bind_attempt_state {
    __s32 fd;
    __u16 port;
    __u8 claim_created;
};

struct bind_rewrite_state {
    __u64 uaddr;
    __u16 port;
};

struct fd_port_key {
    __u32 tgid;
    __s32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct bind_attempt_state);
} pending_bind_attempts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct fd_port_key);
    __type(value, __u16);
} fd_bound_ports SEC(".maps");

/*
 * Tracks live "claims" of a hidden port by a non-whitelisted task, keyed by
 * (tgid << 32 | net-order port). The value is the pid_tgid that created the
 * speculative claim, so bind failure cleanup can avoid deleting another
 * racing thread's live claim.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} bound_hidden_claims SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct bind_rewrite_state);
} pending_getsockname SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static __always_inline struct fd_port_key make_fd_key(__s32 fd)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fd_port_key key = {};

    key.tgid = (__u32)(pid_tgid >> 32);
    key.fd = fd;
    return key;
}

static __always_inline __u64 make_claim_key(__u16 port)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);

    return ((__u64)tgid << 32) | (__u64)port;
}

static __always_inline int uid_is_allowed(void)
{
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    __u8 *match = bpf_map_lookup_elem(&allowed_uids, &uid);

    return match != 0;
}

static __always_inline __u8 target_port_order(__u16 port)
{
    __u8 *match = bpf_map_lookup_elem(&target_ports, &port);

    if (!match)
        return 0;

    return *match;
}

static __always_inline int is_ipv4_local_probe(__u32 ip4)
{
    if (ip4 == 0)
        return 1;

    if ((ip4 & 0xff000000U) == IPV4_LOOPBACK_PREFIX)
        return 1;

    return (bpf_ntohl(ip4) & 0xff000000U) == IPV4_LOOPBACK_PREFIX;
}

static __always_inline int is_ipv6_local_probe(__u32 ip0, __u32 ip1,
                                               __u32 ip2, __u32 ip3)
{
    if (ip0 != 0 || ip1 != 0)
        return 0;

    if (ip2 == 0)
        return ip3 == 0 || ip3 == bpf_htonl(1) || ip3 == 1;

    if (ip2 == 0x0000ffffU || ip2 == bpf_htonl(0x0000ffffU))
        return is_ipv4_local_probe(ip3);

    return 0;
}

static __always_inline __u8 hideport_redirect_order(__u16 port)
{
    __u8 order = target_port_order(port);

    if (!order)
        return 0;

    if (uid_is_allowed())
        return 0;

    return order;
}

static __always_inline __u16 port_for_sockaddr(__u16 port, __u8 order)
{
    if (order == PORT_ORDER_HOST)
        return bpf_htons(port);

    return port;
}

static __always_inline void redirect_connect_port(struct bpf_sock_addr *ctx,
                                                  __u8 order)
{
    if (order == PORT_ORDER_HOST)
        ctx->user_port = REDIRECT_CONNECT_PORT;
    else
        ctx->user_port = bpf_htons(REDIRECT_CONNECT_PORT);
}

static __always_inline int read_target_local_sockaddr(const void *uaddr,
                                                      int addrlen,
                                                      __u16 *sockaddr_port)
{
    __u16 family = 0;
    __u16 port = 0;
    __u8 order;

    if (!uaddr || addrlen < MIN_SOCKADDR_PORT_LEN)
        return 0;

    if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0)
        return 0;

    if (bpf_probe_read_user(&port, sizeof(port), (const char *)uaddr + 2) < 0)
        return 0;

    order = hideport_redirect_order(port);
    if (!order)
        return 0;

    if (family == AF_INET) {
        __u32 ip4 = 0;

        if (addrlen < MIN_SOCKADDR_IN_LEN)
            return 0;

        if (bpf_probe_read_user(&ip4, sizeof(ip4), (const char *)uaddr + 4) < 0)
            return 0;

        if (!is_ipv4_local_probe(ip4))
            return 0;
    } else if (family == AF_INET6) {
        __u32 ip0 = 0;
        __u32 ip1 = 0;
        __u32 ip2 = 0;
        __u32 ip3 = 0;

        if (addrlen < MIN_SOCKADDR_IN6_LEN)
            return 0;

        if (bpf_probe_read_user(&ip0, sizeof(ip0), (const char *)uaddr + 8) < 0 ||
            bpf_probe_read_user(&ip1, sizeof(ip1), (const char *)uaddr + 12) < 0 ||
            bpf_probe_read_user(&ip2, sizeof(ip2), (const char *)uaddr + 16) < 0 ||
            bpf_probe_read_user(&ip3, sizeof(ip3), (const char *)uaddr + 20) < 0)
            return 0;

        if (!is_ipv6_local_probe(ip0, ip1, ip2, ip3))
            return 0;
    } else {
        return 0;
    }

    *sockaddr_port = port_for_sockaddr(port, order);
    return 1;
}

static __always_inline int hideport_maybe_rewrite_bind(struct bpf_sock_addr *ctx)
{
    __u16 port = (__u16)ctx->user_port;
    __u8 order = hideport_redirect_order(port);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 claim_key;
    __u64 owner;
    __u64 *claimed;
    struct bind_attempt_state *pending;

    if (!order)
        return 1;

    /*
     * A real kernel lets only one socket hold a given local port at a time
     * (absent SO_REUSEADDR/SO_REUSEPORT). Without this guard, a probe could
     * bind the same hidden port on two fds: today both would be silently
     * rewritten to distinct ephemeral ports while getsockname() reports the
     * hidden port for both, an impossible result that fingerprints us.
     *
     * Track a per-task claim keyed by (tgid, net-order port). The first bind
     * records a speculative claim and is rewritten to an ephemeral port; a
     * second bind of the same hidden port by the same task while the claim is
     * live is rejected, matching the EADDRINUSE-style failure of a real kernel.
     * If the rewritten bind later fails, hideport_bind_ret rolls back only if
     * this bind attempt created the speculative claim. This avoids deleting a
     * claim owned by an earlier successful bind from the same thread.
     */
    claim_key = make_claim_key(port);
    claimed = bpf_map_lookup_elem(&bound_hidden_claims, &claim_key);
    if (claimed)
        return 0;

    owner = pid_tgid;
    if (!bpf_map_update_elem(&bound_hidden_claims, &claim_key, &owner, BPF_ANY)) {
        pending = bpf_map_lookup_elem(&pending_bind_attempts, &pid_tgid);
        if (pending && pending->port == port)
            pending->claim_created = 1;
    }
    ctx->user_port = 0;
    return 1;
}

SEC("cgroup/connect4")
int hideport_connect4(struct bpf_sock_addr *ctx)
{
    __u16 port = (__u16)ctx->user_port;
    __u8 order;

    if (!is_ipv4_local_probe(ctx->user_ip4))
        return 1;

    order = hideport_redirect_order(port);
    if (order)
        redirect_connect_port(ctx, order);

    return 1;
}

SEC("cgroup/bind4")
int hideport_bind4(struct bpf_sock_addr *ctx)
{
    if (!is_ipv4_local_probe(ctx->user_ip4))
        return 1;

    return hideport_maybe_rewrite_bind(ctx);
}

SEC("cgroup/connect6")
int hideport_connect6(struct bpf_sock_addr *ctx)
{
    __u16 port = (__u16)ctx->user_port;
    __u32 ip0 = ctx->user_ip6[0];
    __u32 ip1 = ctx->user_ip6[1];
    __u32 ip2 = ctx->user_ip6[2];
    __u32 ip3 = ctx->user_ip6[3];
    __u8 order;

    if (!is_ipv6_local_probe(ip0, ip1, ip2, ip3))
        return 1;

    order = hideport_redirect_order(port);
    if (order)
        redirect_connect_port(ctx, order);

    return 1;
}

SEC("cgroup/bind6")
int hideport_bind6(struct bpf_sock_addr *ctx)
{
    __u32 ip0 = ctx->user_ip6[0];
    __u32 ip1 = ctx->user_ip6[1];
    __u32 ip2 = ctx->user_ip6[2];
    __u32 ip3 = ctx->user_ip6[3];

    if (!is_ipv6_local_probe(ip0, ip1, ip2, ip3))
        return 1;

    return hideport_maybe_rewrite_bind(ctx);
}

static __always_inline int record_bind_attempt(__s32 fd,
                                               const void *uaddr,
                                               int addrlen)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct bind_attempt_state state = {};
    __u16 port = 0;

    bpf_map_delete_elem(&pending_bind_attempts, &key);

    if (fd < 0)
        return 0;

    if (!read_target_local_sockaddr(uaddr, addrlen, &port))
        return 0;

    state.fd = fd;
    state.port = port;
    bpf_map_update_elem(&pending_bind_attempts, &key, &state, BPF_ANY);
    return 0;
}

SEC("kprobe/__sys_bind")
int hideport_bind_entry_direct(struct pt_regs *ctx)
{
    return record_bind_attempt((__s32)PT_REGS_PARM1(ctx),
                               (const void *)PT_REGS_PARM2(ctx),
                               (int)PT_REGS_PARM3(ctx));
}

SEC("kprobe/__arm64_sys_bind")
int hideport_bind_entry_arm64(struct pt_regs *ctx)
{
    const struct pt_regs *syscall_regs = (const struct pt_regs *)PT_REGS_PARM1(ctx);

    return record_bind_attempt((__s32)BPF_CORE_READ(syscall_regs, regs[0]),
                               (const void *)BPF_CORE_READ(syscall_regs, regs[1]),
                               (int)BPF_CORE_READ(syscall_regs, regs[2]));
}

SEC("kretprobe/__sys_bind")
int hideport_bind_ret(struct pt_regs *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct bind_attempt_state *state;
    __s32 fd;
    __u16 port;
    __u8 claim_created;
    long ret;

    state = bpf_map_lookup_elem(&pending_bind_attempts, &key);
    if (!state)
        return 0;

    fd = state->fd;
    port = state->port;
    claim_created = state->claim_created;
    ret = PT_REGS_RC(ctx);

    if (ret == 0) {
        struct fd_port_key fd_key = make_fd_key(fd);

        bpf_map_update_elem(&fd_bound_ports, &fd_key, &port, BPF_ANY);
    } else if (claim_created) {
        __u64 claim_key = make_claim_key(port);
        __u64 *owner;

        owner = bpf_map_lookup_elem(&bound_hidden_claims, &claim_key);
        if (owner && *owner == key)
            bpf_map_delete_elem(&bound_hidden_claims, &claim_key);
    }

    bpf_map_delete_elem(&pending_bind_attempts, &key);
    return 0;
}

static __always_inline int record_getsockname_user_addr(__s32 fd, __u64 uaddr)
{
    __u64 pending_key = bpf_get_current_pid_tgid();
    struct fd_port_key fd_key = make_fd_key(fd);
    __u16 *port = bpf_map_lookup_elem(&fd_bound_ports, &fd_key);
    struct bind_rewrite_state state = {};

    bpf_map_delete_elem(&pending_getsockname, &pending_key);

    if (fd < 0 || !port || !uaddr)
        return 0;

    state.uaddr = uaddr;
    state.port = *port;
    bpf_map_update_elem(&pending_getsockname, &pending_key, &state, BPF_ANY);
    return 0;
}

SEC("kprobe/__sys_getsockname")
int hideport_getsockname_entry_direct(struct pt_regs *ctx)
{
    return record_getsockname_user_addr((__s32)PT_REGS_PARM1(ctx),
                                        (__u64)PT_REGS_PARM2(ctx));
}

SEC("kprobe/__arm64_sys_getsockname")
int hideport_getsockname_entry_arm64(struct pt_regs *ctx)
{
    const struct pt_regs *syscall_regs = (const struct pt_regs *)PT_REGS_PARM1(ctx);

    return record_getsockname_user_addr((__s32)BPF_CORE_READ(syscall_regs, regs[0]),
                                        BPF_CORE_READ(syscall_regs, regs[1]));
}

SEC("kretprobe/__sys_getsockname")
int hideport_getsockname_ret(struct pt_regs *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct bind_rewrite_state *state;

    state = bpf_map_lookup_elem(&pending_getsockname, &key);
    if (!state)
        return 0;

    if (PT_REGS_RC(ctx) == 0) {
        __u64 port_addr = state->uaddr + 2;
        __u16 port = state->port;

        bpf_probe_write_user((void *)port_addr, &port, sizeof(port));
    }

    bpf_map_delete_elem(&pending_getsockname, &key);
    return 0;
}

static __always_inline int forget_fd(__s32 fd)
{
    struct fd_port_key key;
    __u16 *port;

    if (fd < 0)
        return 0;

    key = make_fd_key(fd);

    /*
     * Release the per-task port claim recorded at bind time so a later,
     * legitimate rebind of the same hidden port by this task is not
     * mistaken for a duplicate. fd_bound_ports holds the net-order hidden
     * port this fd was bound to.
     */
    port = bpf_map_lookup_elem(&fd_bound_ports, &key);
    if (port) {
        __u64 claim_key = make_claim_key(*port);

        bpf_map_delete_elem(&bound_hidden_claims, &claim_key);
    }

    bpf_map_delete_elem(&fd_bound_ports, &key);
    return 0;
}

SEC("kprobe/__sys_close")
int hideport_close_entry_direct(struct pt_regs *ctx)
{
    return forget_fd((__s32)PT_REGS_PARM1(ctx));
}

SEC("kprobe/__arm64_sys_close")
int hideport_close_entry_arm64(struct pt_regs *ctx)
{
    const struct pt_regs *syscall_regs = (const struct pt_regs *)PT_REGS_PARM1(ctx);

    return forget_fd((__s32)BPF_CORE_READ(syscall_regs, regs[0]));
}
