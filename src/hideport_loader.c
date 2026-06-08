// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "hideport.skel.h"

#define MAX_PORTS 16
#define MAX_UIDS 32
#define CGROUP_PATH "/sys/fs/cgroup"

struct config {
    uint16_t ports[MAX_PORTS];
    int port_count;
    uint32_t uids[MAX_UIDS];
    int uid_count;
};

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [--port PORT]... [--uid UID]... [UID...]\n"
            "\n"
            "Default hidden ports: 8788, 8765, 14731, 14754.\n"
            "Default allowed UIDs: 0, 1000, 2000.\n"
            "Bare numeric arguments are treated as UID whitelist entries.\n",
            argv0);
}

static int parse_ulong(const char *text, unsigned long max, unsigned long *out)
{
    char *end = NULL;
    unsigned long value;

    if (!text || !*text)
        return -EINVAL;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !end || *end != '\0' || value > max)
        return -EINVAL;

    *out = value;
    return 0;
}

static int add_port(struct config *cfg, unsigned long port)
{
    if (port == 0 || port > 65535 || cfg->port_count >= MAX_PORTS)
        return -EINVAL;

    cfg->ports[cfg->port_count++] = (uint16_t)port;
    return 0;
}

static int add_uid(struct config *cfg, unsigned long uid)
{
    if (uid > UINT32_MAX || cfg->uid_count >= MAX_UIDS)
        return -EINVAL;

    cfg->uids[cfg->uid_count++] = (uint32_t)uid;
    return 0;
}

static int parse_args(int argc, char **argv, struct config *cfg)
{
    unsigned long value;
    int saw_custom_port = 0;

    memset(cfg, 0, sizeof(*cfg));
    add_port(cfg, 8788);
    add_port(cfg, 8765);
    add_port(cfg, 14731);
    add_port(cfg, 14754);
    add_uid(cfg, 0);
    add_uid(cfg, 1000);
    add_uid(cfg, 2000);

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char *value_text = NULL;

        if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            usage(argv[0]);
            return 1;
        }

        if (!strcmp(arg, "--port")) {
            if (++i >= argc)
                return -EINVAL;
            value_text = argv[i];
            if (parse_ulong(value_text, 65535, &value) || value == 0)
                return -EINVAL;
            if (!saw_custom_port) {
                cfg->port_count = 0;
                saw_custom_port = 1;
            }
            if (add_port(cfg, value))
                return -EINVAL;
            continue;
        }

        if (!strncmp(arg, "--port=", 7)) {
            value_text = arg + 7;
            if (parse_ulong(value_text, 65535, &value) || value == 0)
                return -EINVAL;
            if (!saw_custom_port) {
                cfg->port_count = 0;
                saw_custom_port = 1;
            }
            if (add_port(cfg, value))
                return -EINVAL;
            continue;
        }

        if (!strcmp(arg, "--uid")) {
            if (++i >= argc)
                return -EINVAL;
            value_text = argv[i];
            if (parse_ulong(value_text, UINT32_MAX, &value))
                return -EINVAL;
            if (add_uid(cfg, value))
                return -EINVAL;
            continue;
        }

        if (!strncmp(arg, "--uid=", 6)) {
            value_text = arg + 6;
            if (parse_ulong(value_text, UINT32_MAX, &value))
                return -EINVAL;
            if (add_uid(cfg, value))
                return -EINVAL;
            continue;
        }

        if (parse_ulong(arg, UINT32_MAX, &value) || add_uid(cfg, value))
            return -EINVAL;
    }

    return 0;
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
        return -errno;

    return 0;
}

static int setup_ports(struct hideport_bpf *skel, const struct config *cfg)
{
    __u8 net_value = 1;

    for (int i = 0; i < cfg->port_count; i++) {
        __u16 net_key = htons(cfg->ports[i]);

        if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_ports),
                                &net_key, &net_value, BPF_ANY)) {
            fprintf(stderr, "failed to add port %u: %s\n",
                    cfg->ports[i], strerror(errno));
            return -errno;
        }

        fprintf(stderr, "hidden port: %u\n", cfg->ports[i]);
    }

    return 0;
}

static int setup_uids(struct hideport_bpf *skel, const struct config *cfg)
{
    __u8 value = 1;

    for (int i = 0; i < cfg->uid_count; i++) {
        __u32 key = cfg->uids[i];

        if (bpf_map_update_elem(bpf_map__fd(skel->maps.allowed_uids),
                                &key, &value, BPF_ANY)) {
            fprintf(stderr, "failed to add uid %u: %s\n",
                    cfg->uids[i], strerror(errno));
            return -errno;
        }
        fprintf(stderr, "allowed uid: %u\n", cfg->uids[i]);
    }

    return 0;
}

static int attach_cgroup_connect_prog(struct bpf_program *prog,
                                      int cgroup_fd,
                                      enum bpf_attach_type attach_type,
                                      const char *name)
{
    int prog_fd = bpf_program__fd(prog);

    if (prog_fd < 0) {
        fprintf(stderr, "invalid %s program fd\n", name);
        return -EINVAL;
    }

    if (!bpf_prog_attach(prog_fd, cgroup_fd, attach_type, BPF_F_ALLOW_MULTI)) {
        fprintf(stderr, "attached %s to %s with allow-multi\n",
                name, CGROUP_PATH);
        return 0;
    }

    if (!bpf_prog_attach(prog_fd, cgroup_fd, attach_type, 0)) {
        fprintf(stderr, "attached %s to %s with legacy single attach\n",
                name, CGROUP_PATH);
        return 0;
    }

    fprintf(stderr, "attach %s to %s failed: %s\n",
            name, CGROUP_PATH, strerror(errno));
    return -errno;
}

static void detach_cgroup_connect_prog(struct bpf_program *prog,
                                       int cgroup_fd,
                                       enum bpf_attach_type attach_type,
                                       const char *name)
{
    int prog_fd;

    if (cgroup_fd < 0)
        return;

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0)
        return;

    if (bpf_prog_detach2(prog_fd, cgroup_fd, attach_type)) {
        fprintf(stderr, "detach %s from %s failed: %s\n",
                name, CGROUP_PATH, strerror(errno));
    }
}

static int attach_getsockname_pair(struct bpf_program *entry_prog,
                                   struct bpf_program *ret_prog,
                                   const char *symbol,
                                   struct bpf_link **entry_link,
                                   struct bpf_link **ret_link)
{
    struct bpf_link *entry = NULL;
    struct bpf_link *ret = NULL;
    long err;

    entry = bpf_program__attach_kprobe(entry_prog, false, symbol);
    err = libbpf_get_error(entry);
    if (err) {
        fprintf(stderr, "attach getsockname entry probe to %s failed: %ld (%s)\n",
                symbol, err, strerror((int)-err));
        return (int)err;
    }

    ret = bpf_program__attach_kprobe(ret_prog, true, symbol);
    err = libbpf_get_error(ret);
    if (err) {
        fprintf(stderr, "attach getsockname ret probe to %s failed: %ld (%s)\n",
                symbol, err, strerror((int)-err));
        bpf_link__destroy(entry);
        return (int)err;
    }

    fprintf(stderr, "attached getsockname probes to %s\n", symbol);
    *entry_link = entry;
    *ret_link = ret;
    return 0;
}

static int attach_getsockname_probes(struct hideport_bpf *skel,
                                     struct bpf_link **entry_link,
                                     struct bpf_link **ret_link)
{
    static const char *const direct_symbols[] = {
        "__sys_getsockname",
        "__se_sys_getsockname",
        "sys_getsockname",
        "SyS_getsockname",
    };
    static const char *const arm64_symbols[] = {
        "__arm64_sys_getsockname",
    };

    for (size_t i = 0; i < sizeof(direct_symbols) / sizeof(direct_symbols[0]); i++) {
        if (!attach_getsockname_pair(skel->progs.hideport_getsockname_entry_direct,
                                     skel->progs.hideport_getsockname_ret,
                                     direct_symbols[i],
                                     entry_link,
                                     ret_link)) {
            return 0;
        }
    }

    for (size_t i = 0; i < sizeof(arm64_symbols) / sizeof(arm64_symbols[0]); i++) {
        if (!attach_getsockname_pair(skel->progs.hideport_getsockname_entry_arm64,
                                     skel->progs.hideport_getsockname_ret,
                                     arm64_symbols[i],
                                     entry_link,
                                     ret_link)) {
            return 0;
        }
    }

    return -ENOENT;
}

static int attach_bind_pair(struct bpf_program *entry_prog,
                            struct bpf_program *ret_prog,
                            const char *symbol,
                            struct bpf_link **entry_link,
                            struct bpf_link **ret_link)
{
    struct bpf_link *entry = NULL;
    struct bpf_link *ret = NULL;
    long err;

    entry = bpf_program__attach_kprobe(entry_prog, false, symbol);
    err = libbpf_get_error(entry);
    if (err) {
        fprintf(stderr, "attach bind entry probe to %s failed: %ld (%s)\n",
                symbol, err, strerror((int)-err));
        return (int)err;
    }

    ret = bpf_program__attach_kprobe(ret_prog, true, symbol);
    err = libbpf_get_error(ret);
    if (err) {
        fprintf(stderr, "attach bind ret probe to %s failed: %ld (%s)\n",
                symbol, err, strerror((int)-err));
        bpf_link__destroy(entry);
        return (int)err;
    }

    fprintf(stderr, "attached bind probes to %s\n", symbol);
    *entry_link = entry;
    *ret_link = ret;
    return 0;
}

static int attach_bind_probes(struct hideport_bpf *skel,
                              struct bpf_link **entry_link,
                              struct bpf_link **ret_link)
{
    static const char *const direct_symbols[] = {
        "__sys_bind",
        "__se_sys_bind",
        "sys_bind",
        "SyS_bind",
    };
    static const char *const arm64_symbols[] = {
        "__arm64_sys_bind",
    };

    for (size_t i = 0; i < sizeof(direct_symbols) / sizeof(direct_symbols[0]); i++) {
        if (!attach_bind_pair(skel->progs.hideport_bind_entry_direct,
                              skel->progs.hideport_bind_ret,
                              direct_symbols[i],
                              entry_link,
                              ret_link)) {
            return 0;
        }
    }

    for (size_t i = 0; i < sizeof(arm64_symbols) / sizeof(arm64_symbols[0]); i++) {
        if (!attach_bind_pair(skel->progs.hideport_bind_entry_arm64,
                              skel->progs.hideport_bind_ret,
                              arm64_symbols[i],
                              entry_link,
                              ret_link)) {
            return 0;
        }
    }

    return -ENOENT;
}

static struct bpf_link *try_attach_close_symbols(struct bpf_program *prog,
                                                 const char *const *symbols,
                                                 size_t count,
                                                 const char *kind)
{
    for (size_t i = 0; i < count; i++) {
        struct bpf_link *link;
        long err;

        link = bpf_program__attach_kprobe(prog, false, symbols[i]);
        err = libbpf_get_error(link);
        if (!err) {
            fprintf(stderr, "attached close cleanup probe to %s\n", symbols[i]);
            return link;
        }

        fprintf(stderr, "attach close cleanup %s probe to %s failed: %ld (%s)\n",
                kind, symbols[i], err, strerror((int)-err));
    }

    return NULL;
}

static struct bpf_link *attach_optional_close_probe(struct hideport_bpf *skel)
{
    static const char *const direct_symbols[] = {
        "__sys_close",
        "__se_sys_close",
        "sys_close",
        "SyS_close",
    };
    static const char *const arm64_symbols[] = {
        "__arm64_sys_close",
    };
    struct bpf_link *link;

    link = try_attach_close_symbols(skel->progs.hideport_close_entry_direct,
                                    direct_symbols,
                                    sizeof(direct_symbols) / sizeof(direct_symbols[0]),
                                    "direct");
    if (link)
        return link;

    return try_attach_close_symbols(skel->progs.hideport_close_entry_arm64,
                                    arm64_symbols,
                                    sizeof(arm64_symbols) / sizeof(arm64_symbols[0]),
                                    "arm64 syscall-wrapper");
}

int main(int argc, char **argv)
{
    struct config cfg;
    struct hideport_bpf *skel = NULL;
    struct bpf_link *bind_entry_link = NULL;
    struct bpf_link *bind_ret_link = NULL;
    struct bpf_link *getsockname_entry_link = NULL;
    struct bpf_link *getsockname_ret_link = NULL;
    struct bpf_link *close_link = NULL;
    int cgroup_fd = -1;
    int connect4_attached = 0;
    int connect6_attached = 0;
    int bind4_attached = 0;
    int bind6_attached = 0;
    int bind_rewrite_enabled = 0;
    int err;

    err = parse_args(argc, argv, &cfg);
    if (err) {
        if (err < 0)
            usage(argv[0]);
        return err < 0 ? 2 : 0;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = bump_memlock_rlimit();
    if (err)
        fprintf(stderr, "warning: failed to raise RLIMIT_MEMLOCK: %s\n",
                strerror(-err));

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = hideport_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    err = hideport_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = setup_ports(skel, &cfg);
    if (err)
        goto cleanup;

    err = setup_uids(skel, &cfg);
    if (err)
        goto cleanup;

    cgroup_fd = open(CGROUP_PATH, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cgroup_fd < 0) {
        fprintf(stderr, "failed to open %s: %s\n",
                CGROUP_PATH, strerror(errno));
        err = -errno;
        goto cleanup;
    }

    err = attach_cgroup_connect_prog(skel->progs.hideport_connect4,
                                     cgroup_fd,
                                     BPF_CGROUP_INET4_CONNECT,
                                     "connect4");
    if (err)
        goto cleanup;
    connect4_attached = 1;

    err = attach_cgroup_connect_prog(skel->progs.hideport_connect6,
                                     cgroup_fd,
                                     BPF_CGROUP_INET6_CONNECT,
                                     "connect6");
    if (err)
        goto cleanup;
    connect6_attached = 1;

    err = attach_getsockname_probes(skel,
                                    &getsockname_entry_link,
                                    &getsockname_ret_link);
    if (err) {
        fprintf(stderr, "warning: getsockname probes unavailable; bind rewrite disabled\n");
        err = 0;
    } else {
        err = attach_bind_probes(skel,
                                 &bind_entry_link,
                                 &bind_ret_link);
        if (err) {
            fprintf(stderr, "warning: bind probes unavailable; bind rewrite disabled\n");
            bpf_link__destroy(getsockname_ret_link);
            bpf_link__destroy(getsockname_entry_link);
            getsockname_ret_link = NULL;
            getsockname_entry_link = NULL;
            err = 0;
        } else {
            bind_rewrite_enabled = 1;
            close_link = attach_optional_close_probe(skel);
            if (!close_link)
                fprintf(stderr, "warning: close cleanup probe unavailable; fd state will expire by LRU\n");
        }
    }

    if (bind_rewrite_enabled) {
        err = attach_cgroup_connect_prog(skel->progs.hideport_bind4,
                                         cgroup_fd,
                                         BPF_CGROUP_INET4_BIND,
                                         "bind4");
        if (err)
            goto cleanup;
        bind4_attached = 1;

        err = attach_cgroup_connect_prog(skel->progs.hideport_bind6,
                                         cgroup_fd,
                                         BPF_CGROUP_INET6_BIND,
                                         "bind6");
        if (err)
            goto cleanup;
        bind6_attached = 1;
    }

    fprintf(stderr, "hideport cgroup-connect loaded\n");
    while (!exiting)
        sleep(1);

    err = 0;

cleanup:
    if (bind6_attached)
        detach_cgroup_connect_prog(skel->progs.hideport_bind6,
                                   cgroup_fd,
                                   BPF_CGROUP_INET6_BIND,
                                   "bind6");
    if (bind4_attached)
        detach_cgroup_connect_prog(skel->progs.hideport_bind4,
                                   cgroup_fd,
                                   BPF_CGROUP_INET4_BIND,
                                   "bind4");
    if (connect6_attached)
        detach_cgroup_connect_prog(skel->progs.hideport_connect6,
                                   cgroup_fd,
                                   BPF_CGROUP_INET6_CONNECT,
                                   "connect6");
    if (connect4_attached)
        detach_cgroup_connect_prog(skel->progs.hideport_connect4,
                                   cgroup_fd,
                                   BPF_CGROUP_INET4_CONNECT,
                                   "connect4");
    bpf_link__destroy(close_link);
    bpf_link__destroy(bind_ret_link);
    bpf_link__destroy(bind_entry_link);
    bpf_link__destroy(getsockname_ret_link);
    bpf_link__destroy(getsockname_entry_link);
    if (cgroup_fd >= 0)
        close(cgroup_fd);
    hideport_bpf__destroy(skel);
    return err;
}
