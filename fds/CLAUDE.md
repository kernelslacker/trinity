# fds/ — FD Provider Layer

Trinity's fd-supply layer. Each file (mostly) implements a "provider" that knows how to open/create one kind of file descriptor (BPF map, cgroup dir, io_uring instance, KVM vCPU, socket, ...) and publish it into the global object pool, so `gen_arg_fd()` and the typed-fd argtypes (`ARG_FD_BPF_MAP`, `ARG_FD_SOCKET`, ...) can hand realistic fds to syscalls under test.

## Files (37 files, ~9,123 LOC)

| File | Lines | Role |
|---|---|---|
| fds.c | 922 | Registry core: provider list, init dispatch (`open_fds`), random/typed fd pickers, protected-fd gate, `--enable-fds`/`--disable-fds` parsing |
| bpf.c | 749 | BPF map/prog/link/btf/token providers — largest single-domain file, drives `bpf(2)` directly |
| sockets.c | 748 | Socket fd provider across address families/types |
| scratch_block.c | 642 | loop-device + mkfs.ext4/tmpfs scratch block fds behind mount-namespace isolation |
| kvm.c | 603 | KVM system/VM/vCPU fd providers (`#ifdef USE_KVM`) |
| canary.c | 324 | Deterministic-content file pool for read-side verification (pagecache canary childop) |
| io_uring.c | 321 | io_uring instance fd provider |
| epoll.c | 240 | epoll fd provider + lazy child-side arming (`arm_epoll_if_needed`) |
| pagecache.c | 262 | Read-only pagecache-backed file fd pool |
| perf.c | 262 | `perf_event_open` fd provider |
| landlock.c | 235 | Landlock ruleset fd provider |
| testfiles.c | 235 | Regular-file test fd pool (open/create/fcntl-state tracked) |
| userfaultfd.c | 219 | userfaultfd provider (`poll_can_block`-tagged) |
| writeable-pagecache.c | 211 | Writable pagecache-backed file fd pool |
| files.c | 201 | Shared pool-file helpers (`open_pool_files`, `get_rand_pool_fd`) backing devfs/procfs/sysfs |
| sparse-files.c | 175 | Sparse-file fd provider |
| mq.c | 172 | POSIX message-queue fd provider |
| pipes.c | 171 | Pipe fd provider |
| timerfd.c | 171 | timerfd provider |
| memfd.c | 169 | memfd provider |
| seccomp_notif.c | 166 | seccomp user-notification fd provider (`#ifdef USE_SECCOMP`) |
| watch_queue.c | 166 | Notification-pipe fds via `pipe2(O_NOTIFICATION_PIPE)` |
| drm.c | 164 | DRM device fd provider |
| inotify.c | 163 | inotify fd provider |
| pidfd.c | 161 | pidfd provider (`pidfd_open`) |
| memfd_secret.c | 168 | `memfd_secret` fd provider |
| dev_template.c | 149 | Templated `/dev/*` probing provider (parent-side, pre-fork) |
| cgroup.c | 145 | cgroup subdirectory fds (`O_PATH` on `/sys/fs/cgroup`) |
| fs_ctx.c | 140 | `fsopen`/`fsconfig` filesystem-context fd provider |
| fanotify_init.c | 131 | fanotify fd provider |
| mount.c | 120 | mount fd provider (`open_tree`/`fsmount`/`move_mount`) |
| eventfd.c | 117 | eventfd provider |
| signalfd.c | 116 | signalfd provider |
| iommufd.c | 115 | IOMMUFD provider (`#ifdef USE_IOMMUFD`) |
| devfs.c | 34 | `/dev` pool provider (thin wrapper over files.c, pool 0) |
| procfs.c | 18 | `/proc` pool provider (thin wrapper over files.c, pool 1) |
| sysfs.c | 18 | `/sys` pool provider (thin wrapper over files.c, pool 2) |

## Key design decisions

1. **`struct fd_provider` is the unit of registration** (`include/fd.h`): `{name, objtype, init, get, child_ops, enabled, initialized, poll_can_block}`. Each file instantiates one (or a few) `static const struct fd_provider` and registers it via `REG_FD_PROV(_struct)`, a constructor-attribute macro that calls `register_fd_provider()` at load time before `main()` — no central list of providers to edit when adding a new one.
2. **Providers publish into `OBJ_GLOBAL` object pools**, keyed by a per-provider `enum objecttype` (`OBJ_FD_BPF_MAP`, `OBJ_FD_SOCKET`, ..., `include/object-types.h`). `.init()` populates the pool once at startup; `.get()` draws a fd from it. No provider exposes a runtime replenish hook — pools only drain after init, which bounds their fuzzing lifetime and is logged at startup (`fds.c:229-253`).
3. **Two fd-acquisition paths from argument generation**: untyped (`get_random_fd()` / `get_new_random_fd()`, uniform across all active non-empty providers) for plain `ARG_FD`, and typed (`get_typed_fd(enum argtype)`) for syscalls that need a specific kind — a fixed switch in `fds.c:488-518` maps `ARG_FD_*` argtypes to `objecttype`s and falls back to `get_random_fd()` if unmapped or empty.
4. **`get_random_fd()` caches an fd across calls** (`child->fd_lifetime`, `RAND_RANGE(5, max_children)` reuses) to bias toward realistic fd-reuse patterns, and validates staleness via a generation counter (`fd_hash_lookup` + `cached_fd_generation`) rather than a syscall.
5. **Protected-fd registry** (`fd_is_protected()`, `lowest_protected_fd_in_range()`): keeps the child's kcov PC/CMP fds and the stderr-capture memfd out of the fuzz-supplied fd pool, since a fuzzed `close`/`dup2`/`ftruncate`/etc. landing on them silently kills coverage or corrupts the crash log. Consulted by `gen_arg_fd()`, the close family, and size-changing sanitisers (`reroll_protected_fd_arg()`).
6. **`poll_can_block` opt-in flag**: providers whose kernel `->poll` can block on an external actor (FUSE via devfs/dev_template, userfaultfd, KVM, io_uring, pidfd, seccomp_notif) tag themselves so `epoll_ctl`/`poll`/`select` sanitisers exclude them from watch sets — arming one of these under `EPOLL_CTL_ADD` can wedge the whole child in `TASK_UNINTERRUPTIBLE`, unrecoverable even by SIGKILL/watchdog.
7. **Shared pool-file helper** (`files.c`, `include/files.h`): devfs.c/procfs.c/sysfs.c are ~18-34 line wrappers over `open_pool_files(pool_id, objtype)` / `get_rand_pool_fd(objtype)` — three numbered pools (0=/dev, 1=/proc, 2=/sys), not three independent implementations.
8. **`init_reason` diagnostics**: providers that fail `.init()` can call `fd_provider_init_fail(reason, errno, detail)` to classify the failure (config-absent, cap-missing, resource, errno) before returning false, letting `open_fds()` log why (e.g. distinguishing kernel-lacks-IOMMUFD from missing CAP_SYS_ADMIN) instead of a bare failure line.
9. **Randomized init order**: `open_fds()` opens roughly half of enabled providers in random order (`RAND_BOOL()` skip) before sweeping the rest, so provider init order isn't a fixed, guessable sequence.

## Integration points

- `args/gen_arg_scalar.c` (`gen_arg_fd`) — main untyped ARG_FD generator: 70% chance of drawing from the child's live-fd ring (`get_child_live_fd`), else `get_new_random_fd()`/typed pool, with protected-fd rerolls throughout
- `args/argtype_table.c`, `include/syscall.h` — `ARG_FD` and the typed `ARG_FD_*` family (`is_typed_fdarg`) dispatch table entries
- `trinity.c` — calls `open_fds()` once at startup after global object init
- `childops/fd-stress.c`, `run_fd_provider_child_ops()` — periodic per-child fd-level actions (bind/listen/accept, etc.) via each provider's optional `.child_ops`
- `syscalls/dup.c`, `syscalls/fcntl.c`, `syscalls/ftruncate.c`, `syscalls/fallocate.c`, `syscalls/lseek.c`, `syscalls/llseek.c`, `syscalls/*write*`, `syscalls/copy_file_range.c`, `syscalls/sendfile.c`, `syscalls/splice.c` — consult `fd_is_protected()` / `reroll_protected_fd_arg()` to keep kcov and stderr-capture fds safe from the close/size-changing families
- `syscalls/poll.c`, `syscalls/select.c`, `syscalls/pselect6.c`, `syscalls/epoll_ctl.c` — use `get_pollable_random_fd()` and `fd_poll_can_block()` to build/validate watch sets
- `kcov/lifecycle.c`, `kcov/diag.c` — own the fds that `fd_is_protected()` shields (`child->kcov.fd`, `child->kcov.cmp_fd`)
- `random_syscall/chain-subst.c` — fd substitution in syscall chains draws from the same typed/random pickers
- `ioctls/fuse.c`, `ioctls/autofs.c`, `ioctls/seccomp.c`, `net/proto-unix.c`, `net/proto-pppox.c`, `lib/cmsg_build.c` — ioctl/net-specific consumers of fds sourced through this layer
- `struct_catalog/aio.c`, `struct_catalog/landlock.c`, `struct_catalog/registry.c` — struct-field fd slots populated from typed providers
- `minicorpus.c` — corpus replay biases ARG_FD/typed-fd argument reuse
- `include/fd.h`, `include/files.h`, `include/object-types.h` — provider struct, pool-file helpers, `OBJ_FD_*` objecttype enum

## Areas of attention

1. **bpf.c (749 LOC)** builds raw `union bpf_attr` blobs across ~16 map types (`bpf_fd_types[]`) plus prog/link/btf/token providers in one file — the largest and most kernel-ABI-coupled provider; a `union bpf_attr` layout change or new map type needs updates here.
2. **kvm.c (603 LOC) and scratch_block.c (642 LOC)** manage multi-stage, stateful kernel resources (VM→vCPU hierarchy; loop device→mkfs→mount) with explicit teardown ordering — scratch_block.c's `atexit()` parent-teardown path (unmount, `LOOP_CLR_FD`, unlink, rmdir) is best-effort/idempotent by design because partial failure is only recoverable by process exit.
3. **Security/isolation-sensitive providers**: scratch_block.c gates on `shm->isolation.mnt_ready` (post-`unshare(CLONE_NEWNS)` latch) before touching loop devices, so a real host disk node cannot enter the pool; cgroup.c and mount.c operate on `/sys/fs/cgroup` and mount namespaces respectively and are natural blast-radius points if the isolation gate were ever bypassed.
4. **fds.c's `get_random_fd()`/`get_new_random_fd()` retry/decay logic** (lines ~258-477) is dense: nested inner (10-try) and outer (64, decaying to 16) retry budgets exist specifically to avoid a documented prior bug where a depleted-pool child could tight-loop burning CPU undetected by the parent's progress watchdog (the syscall record sits in PREP, before the watchdog's BEFORE-onward liveness check applies).
5. **`#ifdef`-gated providers** (bpf.c `USE_BPF`, kvm.c `USE_KVM`, iommufd.c `USE_IOMMUFD`, seccomp_notif.c `USE_SECCOMP`) mean the registered-provider set varies by build config; `fds.c` code must never assume a fixed provider count.

## Summary

A registration-by-constructor pattern (`REG_FD_PROV`) turns ~35 independent "how do I get an fd of kind X" implementations into a uniform `fd_provider` interface that `fds.c` drives generically: init all enabled providers once, expose random/typed/pollable/live-fd pickers to argument generation, and protect a small set of trinity-internal fds (kcov, stderr capture) from being clobbered by the same fuzzed syscalls that consume everything else in the pool.
