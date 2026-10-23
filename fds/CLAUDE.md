# fds/ — FD Provider Layer

Trinity's fd-supply layer. Each file (mostly) implements a "provider" that knows how to open/create one kind of file descriptor (BPF map, cgroup dir, io_uring instance, pidfd, socket, ...) and publish it into the global object pool, so `gen_arg_fd()` and the typed-fd argtypes (`ARG_FD_BPF_MAP`, `ARG_FD_SOCKET`, ...) can hand realistic fds to syscalls under test.

## Files (45 .c files + 1 internal header, ~9,983 LOC)

The registry core spans `fds.c` and the `fds-*.c` files behind
`fds-internal.h`, one concern per translation unit.

| File | Lines | Role |
|---|---|---|
| sockets.c | 752 | Socket fd provider across address families/types |
| bpf.c | 736 | BPF map/prog/link/btf/token providers — largest single-domain file, drives `bpf(2)` directly |
| scratch_block.c | 650 | loop-device + mkfs.ext4/tmpfs scratch block fds behind mount-namespace isolation |
| pagecache.c | 396 | Read-only pagecache-backed file fd pool |
| fds-pick.c | 389 | The pickers: `get_new_random_fd()`, `get_random_fd()` (cache + retry/decay), `get_typed_fd()`, `get_pollable_random_fd()`, `get_child_live_fd()` |
| cgroup.c | 352 | cgroup subdirectory fds (`O_PATH` on `/sys/fs/cgroup`) |
| canary.c | 319 | Deterministic-content file pool for read-side verification (pagecache canary childop) |
| io_uring.c | 303 | io_uring instance fd provider |
| epoll.c | 297 | epoll fd provider + lazy child-side arming (`arm_epoll_if_needed`) |
| perf.c | 259 | `perf_event_open` fd provider |
| memfd.c | 252 | memfd provider |
| timerfd.c | 238 | timerfd provider |
| landlock.c | 233 | Landlock ruleset fd provider |
| testfiles.c | 235 | Regular-file test fd pool (open/create/fcntl-state tracked) |
| memfd_secret.c | 216 | `memfd_secret` fd provider |
| pipes.c | 223 | Pipe fd provider |
| userfaultfd.c | 226 | userfaultfd provider (`poll_can_block`-tagged) |
| fds-protected.c | 286 | Protected-fd registry: `fd_is_protected()`, `lowest_protected_fd_in_range()`, `reroll_protected_fd_arg()`, `stat_names_protected_file()` (a path can reopen a protected file under a number the registry does not know); plus `fd_relocate_high()`, the park-above-`PROTECTED_FD_HIGH_BASE` step the kcov, taint, fail-nth and rotation-sink fds share |
| watch_queue.c | 213 | Notification-pipe fds via `pipe2(O_NOTIFICATION_PIPE)` |
| inotify.c | 217 | inotify fd provider |
| writeable-pagecache.c | 197 | Writable pagecache-backed file fd pool |
| files.c | 201 | Shared pool-file helpers (`open_pool_files`, `get_rand_pool_fd`) backing devfs/procfs/sysfs |
| seccomp_notif.c | 174 | seccomp user-notification fd provider (`#ifdef USE_SECCOMP`) |
| fanotify_init.c | 175 | fanotify fd provider |
| sparse-files.c | 171 | Sparse-file fd provider |
| eventfd.c | 174 | eventfd provider |
| mq.c | 172 | POSIX message-queue fd provider |
| signalfd.c | 160 | signalfd provider |
| fds.c | 164 | Provider dispatchers: fd→provider lookup, `fd_poll_can_block()`, the periodic `child_ops` / `child_init` walks, and the rate-limited `run_fd_provider_replenish()` tick, which resumes after the last provider it served |
| drm.c | 164 | DRM device fd provider |
| pidfd.c | 159 | pidfd provider (`pidfd_open`) |
| dev_template.c | 145 | Templated `/dev/*` probing provider (parent-side, pre-fork) |
| fs_ctx.c | 135 | `fsopen`/`fsconfig` filesystem-context fd provider |
| fds-init.c | 127 | `open_fds()` — randomized init sweep, `active_providers[]` build, enabled/initialized and per-pool-size startup logging |
| mount.c | 118 | mount fd provider (`open_tree`/`fsmount`/`move_mount`) |
| iommufd.c | 115 | IOMMUFD provider (`#ifdef USE_IOMMUFD`) |
| fds-param.c | 95 | `--enable-fds` / `--disable-fds` parsing (`process_fds_param`) |
| fds-registry.c | 93 | The constructor-time provider list: `register_fd_provider()`, `fd_provider_name()`, `dump_fd_provider_names()` |
| fds-internal.h | 66 | Private cross-file interface of the registry translation units — the counters and provider arrays they share, and the replenish per-tick cap |
| owned-fd-ring.c | 89 | `owned_fd_ring_record()` and `owned_fd_ring_retire()` (`include/owned-fd-ring.h`): the ring of fds a `.try_replenish` provider minted; closes the oldest on wrap, but only while `fstat()` still shows the file it recorded. A retire takes a number out of every provider's ring without closing it: a record retires the number it is given first, and `account_fd_and_group()` retires each number a fuzzed call returns, which `fstat()` cannot do for anon-inode files and dups |
| fds-dup.c | 116 | `pool_dup_result()` and `pool_foreign_fd()` (`include/fd.h`): pool the fd a dup, dup2, dup3 or `fcntl(F_DUPFD*)` returned under the object type of the fd it copied, after retiring the local object its number held; and the fd `pidfd_getfd` returned, when `fstat()` says it is a socket or a pipe end |
| fds-pool.c | 135 | `pool_returned_fd()`, `pool_open_result()` and `pool_typed_fd()` (`include/fd.h`): the child's capped pool of the files a call hands back that no provider owns (an open result, the fd an ioctl cmd returns), as local `OBJ_FD_TESTFILE` objects. At most `POOLED_FD_MAX` of them: a full pool destroys its oldest object (smallest `slot_version`) through the head's destructor to make room, and a head with no destructor takes nothing. An open result qualifies only as a regular file or a directory that is not a second name of a protected file. `pool_typed_fd()` is the same retire-then-publish, capped at `POOLED_FD_MAX` per type, under a typed producer's own type; what it refuses past stdio and protected numbers it closes |
| fds-diag.c | 42 | `fd_provider_init_fail()` and the last-init-reason slot `open_fds()` reads back |
| devfs.c | 34 | `/dev` pool provider (thin wrapper over files.c, pool 0) |
| procfs.c | 18 | `/proc` pool provider (thin wrapper over files.c, pool 1) |
| sysfs.c | 18 | `/sys` pool provider (thin wrapper over files.c, pool 2) |

## Key design decisions

1. **`struct fd_provider` is the unit of registration** (`include/fd.h`): `{name, objtype, init, get, child_init, child_ops, try_replenish, enabled, initialized, poll_can_block}`. Each file instantiates one (or a few) `static const struct fd_provider` and registers it via `REG_FD_PROV(_struct)`, a constructor-attribute macro that calls `register_fd_provider()` at load time before `main()` — no central list of providers to edit when adding a new one.
2. **Providers publish into `OBJ_GLOBAL` object pools**, keyed by a per-provider `enum objecttype` (`OBJ_FD_BPF_MAP`, `OBJ_FD_SOCKET`, ..., `include/object-types.h`). `.init()` populates the pool once at startup; `.get()` draws a fd from it. The `OBJ_GLOBAL` pools themselves only drain after init — a post-fork `add_object(OBJ_GLOBAL)` is a no-op behind the mainpid guard — so each pool's init size is its whole lifetime budget, and it is logged at startup (`fds-init.c:98-124`). Ten small-pool providers (epoll, eventfd, fanotify_init, inotify, memfd, memfd_secret, pipes, signalfd, timerfd, watch_queue) opt into the `.try_replenish` top-up hook instead, which pushes new fds straight into the child's live-fd ring via `child_fd_ring_push()`.
3. **Two fd-acquisition paths from argument generation**: untyped (`get_random_fd()` / `get_new_random_fd()`, uniform across all active non-empty providers) for plain `ARG_FD`, and typed (`get_typed_fd(enum argtype)`) for syscalls that need a specific kind — a fixed switch in `fds-pick.c:257-280` maps `ARG_FD_*` argtypes to `objecttype`s and falls back to `get_random_fd()` if unmapped or empty.
4. **`get_random_fd()` caches an fd across calls** (`child->fd_lifetime`, `RAND_RANGE(5, max_children)` reuses) to bias toward realistic fd-reuse patterns, and validates staleness via a generation counter (`fd_hash_lookup` + `cached_fd_generation`) rather than a syscall.
5. **Protected-fd registry** (`fd_is_protected()`, `lowest_protected_fd_in_range()`): keeps the child's kcov PC/CMP fds, the stderr-capture memfd and the rotation-events sink out of the fuzz-supplied fd pool, since a fuzzed `close`/`dup2`/`ftruncate`/etc. landing on them silently kills coverage, corrupts the crash log or tears the JSONL every child shares. Consulted by `gen_arg_fd()`, the close family, size-changing sanitisers (`reroll_protected_fd_arg()`), and the two rewrites that land after a sanitiser, chain substitution and the RedQueen pin, through `rewrite_refused_slots()`. `close_range()`'s sanitiser truncates a range below the lowest protected fd it sweeps, and with EXCEPT, which closes everything outside the range, widens it to hold every one; a rewrite after sanitise could undo either, so `validate_arg_coupling()` refuses a `close_range` whose slots no longer match what the sanitiser vetted (close_range's `.vet_final` hook: chain substitution and a RedQueen pin both land after it), and the entry is not `REEXEC_SANITISE_OK`. Children also park the kcov, taint, fail-nth and rotation-sink fds above one shared base, `PROTECTED_FD_HIGH_BASE` (`include/fd.h`), out of the small numbers the pickers and mutated fd args reach; the move is `fd_relocate_high()`, which keeps the low fd when it fails.
6. **`poll_can_block` opt-in flag**: providers whose kernel `->poll` can block on an external actor (FUSE via devfs/dev_template, userfaultfd, io_uring, pidfd, seccomp_notif) tag themselves so `epoll_ctl`/`poll`/`select` sanitisers exclude them from watch sets — arming one of these under `EPOLL_CTL_ADD` can wedge the whole child in `TASK_UNINTERRUPTIBLE`, unrecoverable even by SIGKILL/watchdog.
7. **Shared pool-file helper** (`files.c`, `include/files.h`): devfs.c/procfs.c/sysfs.c are ~18-34 line wrappers over `open_pool_files(pool_id, objtype)` / `get_rand_pool_fd(objtype)` — three numbered pools (0=/dev, 1=/proc, 2=/sys), not three independent implementations.
8. **`fd_init_reason` diagnostics**: providers that fail `.init()` can call `fd_provider_init_fail(reason, errno, detail)` to classify the failure (config-absent, cap-missing, resource, errno) before returning false, letting `open_fds()` log why (e.g. distinguishing kernel-lacks-IOMMUFD from missing CAP_SYS_ADMIN) instead of a bare failure line.
9. **Randomized init order**: `open_fds()` opens roughly half of enabled providers in random order (`RAND_BOOL()` skip) before sweeping the rest, so provider init order isn't a fixed, guessable sequence.

## Integration points

- `args/gen_arg_scalar.c` (`gen_arg_fd`) — main untyped ARG_FD generator: 70% chance of drawing from the child's live-fd ring (`get_child_live_fd`), else `get_new_random_fd()`/typed pool, with protected-fd rerolls throughout
- `args/argtype_table.c`, `include/syscall.h` — `ARG_FD` and the typed `ARG_FD_*` family (`is_typed_fdarg`) dispatch table entries
- `main/trinity-warmstart.c` — calls `open_fds()` once at startup after global object init
- `child/child-periodic.c`, `run_fd_provider_child_ops()` — every 128th op, a per-child fd-level action (bind/listen/accept, etc.) via each provider's optional `.child_ops`, skipped under `-c`/`-r`/`-g`
- `syscalls/fs/dup.c`, `syscalls/fs/ftruncate.c`, `syscalls/fs/fallocate.c`, `syscalls/fs/lseek.c`, `syscalls/fs/llseek.c`, `syscalls/*write*`, `syscalls/fs/splice/copy_file_range.c`, `syscalls/fs/splice/sendfile.c`, `syscalls/fs/splice/splice.c` — consult `fd_is_protected()` / `reroll_protected_fd_arg()` to keep kcov and stderr-capture fds safe from the close/size-changing families
- `syscalls/fs/dup.c`, `syscalls/fs/fcntl.c` — pool the results of dup, dup2, dup3 and `fcntl(F_DUPFD*)` through `pool_dup_result()` (`fds/fds-dup.c`): the copy joins the `OBJ_LOCAL` pool of the fd it copies (`find_object_by_fd()`, then `publish_resource()`), and the object the returned number held is retired first (`remove_local_objects_by_fd()`); protected fds never enter a pool, on either end
- `syscalls/pidfd/pidfd_getfd.c` — pools the fd it returns through `pool_foreign_fd()` (`fds/fds-dup.c`) when `fstat()` says it is a socket (its triplet read back with `getsockopt()`) or a pipe end, and closes anything else: an anon-inode fd cannot be typed from `fstat()`
- `syscalls/fs/open.c`, `syscalls/fs/creat.c` — open, openat, openat2, open_by_handle_at and creat pool what they return through `pool_open_result()` (`fds/fds-pool.c`) when `fstat()` says it is a regular file or a directory, and close anything else: a device, a FIFO and a socket stay closed, as does a second name of a protected file. The object the number held is retired first, and a child keeps at most `POOLED_FD_MAX` of them, so a run of successful opens cannot fill the fd table
- `fds/mount.c`, `fds/fs_ctx.c` — `post_mount_fd()` (open_tree, open_tree_attr, fsmount) and `post_fs_ctx_fd()` (fsopen, fspick) pool their fd through `pool_typed_fd()` as `OBJ_FD_MOUNT` / `OBJ_FD_FS_CTX`, and coerce a refused one's retval to -1 so `register_returned_fd()` does not pool it
- `syscalls/poll/epoll_create.c` — epoll_create and epoll_create1 pool their fd the same way as `OBJ_FD_EPOLL`, recording which call made it and epoll_create1's flags
- `syscalls/ioctl.c` — `post_ioctl()` pools the nsfs fd a pidfs namespace getter returns through `pool_returned_fd()` (`fds/fds-pool.c`), and closes it when the pool will not take it. It leaves a number alone unless the cmd is a getter (`pidfd_ns_getter()`) and `fstatfs()` says nsfs, and never closes a stdio or protected number
- `random_syscall/fd-group.c` — `account_fd_and_group()` calls `owned_fd_ring_retire()` for every fd a fuzzed call returns, so a stale ring slot cannot close the new owner of its number; a call that returns the fd it was handed (`dup2(fd, fd)`, `signalfd()` on a signalfd) retires nothing. A bounded walk of the rings, no syscall
- `syscalls/poll/poll.c`, `syscalls/poll/select.c`, `syscalls/poll/pselect6.c`, `syscalls/poll/epoll_ctl.c` — use `get_pollable_random_fd()` and `fd_poll_can_block()` to build/validate watch sets
- `kcov/lifecycle.c`, `kcov/diag.c` — own the fds that `fd_is_protected()` shields (`child->kcov.fd`, `child->kcov.cmp_fd`)
- `stats/rotation_event.c` — owns the rotation-events sink fd (`stats_rotation_event_fd()`), the one shielded fd the parent opens and every child inherits; each child parks its copy above `PROTECTED_FD_HIGH_BASE` (60000, `include/fd.h`), like the kcov/taint/fail-nth slots
- `random_syscall/chain-subst.c` — fd substitution in syscall chains draws from the same typed/random pickers
- `ioctls/fuse.c`, `ioctls/autofs.c`, `ioctls/seccomp.c`, `net/proto/unix.c`, `net/proto/pppox.c`, `lib/cmsg_build.c` — ioctl/net-specific consumers of fds sourced through this layer
- `struct_catalog/mount.c`, `struct_catalog/bpf-*.c` — struct-field fd slots (`FT_FD`), filled by `args/struct_fill.c` from the generic fd pool
- `persist/minicorpus-field-mutate.c` — corpus replay biases ARG_FD/typed-fd argument reuse (the fd-pool cross-pollination mutator case draws from `get_random_fd()`)
- `include/fd.h`, `include/files.h`, `include/object-types.h` — provider struct, pool-file helpers, `OBJ_FD_*` objecttype enum

## Areas of attention

1. **bpf.c (736 LOC)** builds raw `union bpf_attr` blobs across ~16 map types (`bpf_fd_types[]`) plus prog/link/btf/token providers in one file — the largest and most kernel-ABI-coupled provider; a `union bpf_attr` layout change or new map type needs updates here.
2. **scratch_block.c (650 LOC)** manages a multi-stage, stateful kernel resource (loop device→mkfs→mount) with explicit teardown ordering — its `atexit()` parent-teardown path (unmount, `LOOP_CLR_FD`, unlink, rmdir) is best-effort/idempotent by design because partial failure is only recoverable by process exit. Loops are bound with `LO_FLAGS_AUTOCLEAR`, so the parent-held loop fd is what keeps each one bound for the run: closing it before teardown unbinds the device on its last close. A child's `LOOP_SET_STATUS(64)` replaces that flag, so `ioctls/loop.c` sets it on every such write aimed at a scratch loop's device node (matched by inode, so a dup counts).
3. **Security/isolation-sensitive providers**: scratch_block.c gates on `shm->isolation.mnt_ready` (post-`unshare(CLONE_NEWNS)` latch) before touching loop devices, so a real host disk node cannot enter the pool; cgroup.c and mount.c operate on `/sys/fs/cgroup` and mount namespaces respectively and are natural blast-radius points if the isolation gate were ever bypassed.
4. **`fds-pick.c`'s `get_new_random_fd()`/`get_random_fd()` retry/decay logic** (lines 19-239) is dense: nested inner (10-try) and outer (64, decaying to 16) retry budgets exist specifically to avoid a documented prior bug where a depleted-pool child could tight-loop burning CPU undetected by the parent's progress watchdog (the syscall record sits in PREP, before the watchdog's BEFORE-onward liveness check applies).
5. **`#ifdef`-gated providers** (bpf.c `USE_BPF`, drm.c `USE_DRM`, iommufd.c `USE_IOMMUFD`, seccomp_notif.c `USE_SECCOMP`) mean the registered-provider set varies by build config; `fds.c` code must never assume a fixed provider count.

## Summary

A registration-by-constructor pattern (`REG_FD_PROV`) turns ~40 independent "how do I get an fd of kind X" implementations into a uniform `fd_provider` interface that `fds.c` drives generically: init all enabled providers once, expose random/typed/pollable/live-fd pickers to argument generation, and protect a small set of trinity-internal fds (kcov, stderr capture) from being clobbered by the same fuzzed syscalls that consume everything else in the pool.
