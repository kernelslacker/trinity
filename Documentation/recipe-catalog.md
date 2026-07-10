# Recipe catalog

Design essays for the recipe_runner supervisor recipes in
`childops/recipe/supervisor.c`.  Each section covers one recipe: the
per-call syscall trace, the kernel paths targeted, how it differs from
adjacent providers, the single-thread rationale, the unsupported-latch
shape, and the per-cycle cleanup ordering.

See `childops/recipe/recipe-runner.c` for the dispatcher-level design
rationale and `childops/recipe/internal.h` for the shared declarations
and macros.


## Recipe 33: ptrace SEIZE+EXITKILL lifecycle

### Per cycle (1..MAX_CYCLES)

```
fork() -> inner child blocks in pause() -> parent runs the
SEIZE-style lifecycle on the tracee:

  ptrace(PTRACE_SEIZE, child, 0,
         PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) ->
  ptrace(PTRACE_INTERRUPT, child, 0, 0) ->
  waitpid(child, &status, __WALL) for the group-stop ->
  ptrace(PTRACE_GETSIGINFO, child, 0, &si) ->
  ptrace(PTRACE_SETOPTIONS, child, 0,
         PTRACE_O_EXITKILL | PTRACE_O_TRACEEXIT) ->
  ptrace(PTRACE_CONT, child, 0, 0) ->
  kill(child, SIGKILL) ->
  waitpid_eintr(child, &status, 0) reaps.
```

### Targets the kernel paths

- `ptrace_attach` (SEIZE branch) vs `ptrace_attach` (legacy ATTACH
  branch).
- The `PTRACE_INTERRUPT` group-stop delivery against a task in
  `TASK_INTERRUPTIBLE` `pause()`.
- The `PTRACE_O_EXITKILL` flag wiring (set on attach via the data
  param, mutated mid-trace via `SETOPTIONS`).
- The `GETSIGINFO` read of the tracee's `last_siginfo` while it's
  group-stopped.
- The SIGKILL-vs-ptrace-stop teardown that exits a tracee out of a
  ptrace stop via `fatal_signal_pending()`.

### Distinct from

The random-syscall ptrace path in `syscalls/ptrace.c` which feeds
isolated requests against arbitrary pids and is gated `AVOID_SYSCALL`.
This recipe drives the structured
SEIZE-then-INTERRUPT-then-GETSIGINFO-then-SETOPTIONS-then-CONT
lifecycle on a tracee the recipe itself owns -- arguments are concrete
and ordered, so the kernel paths between SEIZE and DETACH/teardown are
reachable end-to-end on every cycle.

### Single-thread by design

ptrace state is task-scoped and the SEIZE/INTERRUPT handshake
serialises naturally inside the parent.  Kernel-side concurrency
(signal-vs-ptrace_stop, EXITKILL-on-tracer-exit) is exercised by the
kernel's own task-switch interleaving between our parent's syscalls
and the tracee's `pause()`/wakeup transitions.

EXITKILL is the *attribute* under test even though we tear down the
tracee explicitly with SIGKILL: the flag must be settable on SEIZE,
mutable via `SETOPTIONS`, and not interfere with the normal stop/resume
cycle.  A kernel bug in the EXITKILL plumbing that killed the tracee
prematurely (before our SIGKILL) would land a `WIFSIGNALED` early --
still safe under `waitpid_eintr`.

### Latch shape

Every way the feature can be absent on the very first probe:

- `ptrace SEIZE ENOSYS`  -- kernel < 3.4, vanishingly rare.
- `ptrace SEIZE EPERM`   -- YAMA `ptrace_scope=2/3`, LSM denial.
- `ptrace SEIZE EACCES`  -- LSM denial via
  `security_ptrace_access_check`.

Once latched, the dispatcher stops siblings from re-probing the
unsupported feature on every recipe pick.

Per-cycle fork failure (`EAGAIN` under nproc/thread limits) is
tolerated mid-loop; `FORK_FAIL_LATCH=3` consecutive failures bails for
the rest of the invocation since competing `fork_storm` / `cgroup_churn`
won't lift the limit mid-op.

### Cleanup ordering

On every exit path: SIGKILL the tracee (idempotent if already dead),
`waitpid_eintr` to reap the zombie, return.  The inner child uses
`_exit()` in its (unreachable) tail to skip atexit handlers that could
touch trinity shared state from a stopped tracee context.


## Recipe 34: mount/userns dance

### Per call

```
fork() -> inner child -> unshare(CLONE_NEWUSER | CLONE_NEWNS) ->
write /proc/self/uid_map + setgroups=deny + gid_map ->
mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL) ->
mount("none", "/tmp", "tmpfs", 0, NULL) ->
mount(NULL, "/tmp", NULL, MS_PRIVATE, NULL) ->
mount(NULL, "/tmp", NULL, MS_RDONLY|MS_REMOUNT, NULL) ->
umount2("/tmp", MNT_DETACH) ->
_exit(0); parent waitpid_eintr.
```

### Targets the kernel paths

Fires when a userns and a mount ns are created together with the mount
ns owned by the new userns:

- `copy_user_ns` + `copy_mnt_ns` + the ownership chain that links the
  new `mnt_ns->user_ns` to the freshly-allocated `user_ns`.
- `proc_uid_map_write` / `proc_gid_map_write` / `proc_setgroups_write`
  paths with their `EBUSY`-vs-already-set state machine.
- `do_change_type` (propagation-flag mutation, distinct from initial
  mount creation).
- `do_remount` (superblock `remount_fs` op, `mnt_flags` rewrite under
  `namespace_sem`).
- `do_umount` with `MNT_DETACH` (deferred-cleanup path that decouples
  namespace removal from final `put_mnt_ns`).

### Distinct from

- `childops/misc/userns-fuzzer.c` which enters `CLONE_NEWUSER` but only
  dispatches a single `ns_capable`-gated op.
- `childops/fs/fs-lifecycle.c` which drives mount lifecycles inside
  the trinity child's existing `CLONE_NEWNS` without a fresh userns.

The combination -- fresh userns *and* fresh mountns *and* a multi-step
propagation/remount/detach sequence -- is unreachable through any
single existing op.

### Single-thread by design

Namespace/mount state changes are serialised by `namespace_sem` inside
the kernel and the per-step sequence is the bug surface, not
concurrency.  Forking an inner child contains the userns/mountns
transition so trinity's outer state (caps, original mount tree) is
never disturbed; a crash inside the dance is reaped here as
`WIFSIGNALED` without disturbing sibling recipes.

### Latch shape

Every way the feature can be absent on the very first probe.  The
inner child reports unshare failure via exit code 1, and the parent
treats `WEXITSTATUS(status) == 1` as the unsupported signal:

- `unshare CLONE_NEWUSER EPERM`  -- `user.max_user_namespaces=0`,
  `kernel.unprivileged_userns_clone=0`, LSM denial.
- `unshare CLONE_NEWUSER ENOSYS` -- `CONFIG_USER_NS=n`, very rare.
- `unshare CLONE_NEWNS EPERM`    -- `CONFIG_NAMESPACES=n` -- all
  namespace ops denied.

Once latched, the dispatcher stops siblings from re-probing the
unsupported feature on every recipe pick.

Per-call fork failure (`EAGAIN` under nproc/thread limits) returns
partial; no in-loop tolerance because there's only one fork per recipe
call.  `WIFSIGNALED` on the inner child (e.g. OOM-kill) counts as
ran-the-path but partial.


## Recipe 35: seccomp USER_NOTIF listener + traced exec

### Per call

```
fork() -> supervisor ->
  prctl(PR_SET_NO_NEW_PRIVS, 1) ->
  seccomp(SET_MODE_FILTER, FLAG_NEW_LISTENER, &prog)
    (BPF: __NR_uname -> USER_NOTIF, else ALLOW) ->
  fork() -> inner ->
    syscall(__NR_uname, &u)              [trapped, parks here]
    execl("/bin/true", ...)              [post-trap exec]
    _exit(0)
  supervisor:
    poll(listener, POLLIN, 1s) ->
    ioctl(SECCOMP_IOCTL_NOTIF_RECV, &req) ->
    ioctl(SECCOMP_IOCTL_NOTIF_ID_VALID, &req.id) ->
    ioctl(SECCOMP_IOCTL_NOTIF_SEND, &resp{id, val=0, error=0}) ->
    close(listener) ->
    waitpid_eintr(inner) ->
  _exit(rc)
parent: waitpid_eintr(supervisor); WEXITSTATUS == 1 latches.
```

### Targets the kernel paths

Fires when a `SECCOMP_RET_USER_NOTIF` filter parks a syscall and
userspace drives the listener:

- `prctl PR_SET_NO_NEW_PRIVS` (`task_struct->no_new_privs` flip).
- `do_seccomp(SECCOMP_SET_MODE_FILTER, FLAG_NEW_LISTENER)` ->
  `anon_inode_getfd("seccomp notify")` with the new
  `seccomp_notif_ctx`; filter is installed in
  `current->seccomp.filter` and inherited across the subsequent fork.
- `fork` `copy_process` inherits `seccomp.filter`; the inner's first
  `uname()` hits `__seccomp_filter`, marks the syscall as parked, and
  blocks on the listener's wait queue.
- `SECCOMP_IOCTL_NOTIF_RECV` (`seccomp_notify_recv`: dequeues the
  parked notification, copies `seccomp_notif` to userspace).
- `SECCOMP_IOCTL_NOTIF_ID_VALID` (`seccomp_notify_id_valid`: looks up
  the notif by id under the ctx's mutex).
- `SECCOMP_IOCTL_NOTIF_SEND` (`seccomp_notify_send`: matches the
  response by id, writes `val`/`error` into the parked syscall's
  result, wakes the trapped task).
- `close(listener)` (`seccomp_notify_release`: tears down the
  notification queue, fails any in-flight `ID_VALID` with `ENOENT`).
- `search_binary_handler` / `load_elf_binary` path on the inner's
  `execl()` *after* a seccomp filter has been installed and trapped
  once -- the post-trap exec path is the bug surface that's
  unreachable if you only install a filter or only trap.

### Distinct from

`fds/seccomp_notif.c` which installs the filter inside the trinity
child for ioctl-fuzzing the listener fd from `random_syscall` paths.
That provider never traps (its filter targets `getpid` which the
child doesn't call from the post-install code path) and never drives
the RECV/ID_VALID/SEND lifecycle end-to-end.  This recipe is the only
place trinity exercises the parked-syscall / `NOTIF_SEND` matchup with
a real trapped syscall on the inner.

### Single-thread by design

The seccomp listener model is intrinsically a 1:1 supervisor/tracee
handshake, and the kernel serialises RECV/SEND through the
`notif_ctx` mutex.  The race surface here is
inner-trap-vs-supervisor-RECV / SEND-vs-inner-resume, all driven by
task scheduling between the two processes the recipe owns.

### Latch shape

- `prctl(NO_NEW_PRIVS) ENOSYS` -- `CONFIG_SECCOMP=n`.
- `seccomp() ENOSYS`           -- pre-3.17 kernel.
- `seccomp() EINVAL`           -- `FLAG_NEW_LISTENER` unsupported
  (pre-5.0) or LSM-rewritten.
- `seccomp() EACCES`           -- LSM denial.

The supervisor encodes "any of these triggered" as exit code 1; the
parent translates that to `*unsupported = true` and the dispatcher
stops siblings from re-probing.

### Cleanup ordering

On every supervisor exit path: SIGKILL the inner (idempotent if
already dead/exec'd-and-exited), `waitpid_eintr`, close the listener.
`/bin/true` exits 0 in <1ms on every distro trinity targets; the
supervisor's `waitpid` never blocks for long.

Per-call fork failure (`EAGAIN` under nproc/thread limits) is reported
by the supervisor as exit code 2 -- not unsupported, just transient,
the dispatcher will pick again next cycle.


## Recipe 36: cgroup v2 cgroup.kill + cgroup.events lifecycle

### Per call

```
fork() -> supervisor ->
  mkdir("/sys/fs/cgroup/trinity-kill-PID", 0755) ->
  open("<cg>/cgroup.events", O_RDONLY|O_NONBLOCK) ->
  open("<cg>/cgroup.kill",   O_WRONLY) ->
  pipe2(pipefd, O_CLOEXEC) ->
  fork() -> inner ->
    open("<cg>/cgroup.procs", O_WRONLY) -> write "<pid>\n"
    write(pipefd[1], &ack, 1)            [signal supervisor]
    pause()                              [waits for cgroup.kill SIGKILL]
  supervisor:
    read(pipefd[0], &ack, 1)             [sync with inner]
    poll(events_fd, POLLIN, 0) + read    [pre-kill baseline]
    write(kill_fd, "1\n", 2)             [trigger cgroup.kill]
    poll(events_fd, POLLPRI|POLLIN, 200ms)  [kernfs_notify wake]
    lseek(events_fd, 0, SEEK_SET) + read [post-kill state]
    kill(inner, SIGKILL); waitpid_eintr  [backup reap]
    close fds
    rmdir("<cg>")
  _exit(rc)
parent: waitpid_eintr(supervisor); WEXITSTATUS == 1 latches.
```

### Targets the kernel paths

Fires when cgroup v2's `cgroup.kill` control file is written and
downstream readers observe the populated-state change via
`kernfs_notify`:

- `cgroup_mkdir` + the kernfs node creation that auto-populates
  `cgroup.events` / `cgroup.kill` / `cgroup.procs` /
  `cgroup.controllers`.
- `cgroup_procs_write` (write to `<cg>/cgroup.procs`): the migrate
  path (`cgroup_attach_task` / `cgroup_migrate` / `cgroup_post_fork`
  for the `css_set` move) under `cgroup_mutex`.
- `cgroup_kill_write` -> `cgroup_kill_control` -> `__cgroup_kill`:
  the `css_task_iter` walk that `group_send_sig_info(SIGKILL)`s every
  member task; this is the entire `cgroup.kill` bug surface.
- `kernfs_notify` -> `kernfs_notify_workfn` -> wake the `events_fd`
  waitqueue with `EPOLLPRI`: triggered when `populated` transitions
  `1 -> 0` after the killed inner is reaped.
- `cgroup_events_show` / `cgroup_file_open` / `cgroup_file_release`
  on the read-after-notify path (`lseek(0)` + read drives the
  `seq_file` regenerate path with mutated state).
- `cgroup_rmdir` against a recently-emptied cgroup (`offline_css` for
  each subsys, `kernfs_remove`).

### Distinct from

`childops/misc/cgroup-churn.c` which `mkdir`s/`rmdir`s as fast as
possible to drive `cgroup_mkdir`/`rmdir` under contention but never
populates a cgroup with tasks, never opens `cgroup.events`, and never
exercises `cgroup.kill`.  This recipe is the only place trinity
drives the `cgroup.kill` -> SIGKILL members -> `kernfs_notify` wake
-> `cgroup.events` re-read sequence end-to-end.

### Single-thread by design

cgroup state changes serialise through `cgroup_mutex`, and the
recipe's bug surface is the kill-vs-notify-vs-read ordering, not
concurrent writers to `cgroup.kill`.  The inner-vs-supervisor process
pair gives the kernel a real task to SIGKILL out of the cgroup, which
is the only way to make `populated` transition `1 -> 0` and fire the
`kernfs_notify` wake.

### Latch shape

Every way the feature can be absent on the very first probe.  The
supervisor reports any of these via exit code 1:

- `mkdir EACCES`         -- unprivileged trinity, `/sys/fs/cgroup`
  not delegated to this user.
- `mkdir EPERM`          -- LSM denial.
- `mkdir EROFS`          -- cgroup v1 root mounted read-only.
- `mkdir ENOENT`         -- no `/sys/fs/cgroup/` at all.
- `mkdir ENOTDIR`        -- something is mounted at `/sys/fs/cgroup`
  that isn't cgroupfs.
- `open(cgroup.events) ENOENT` -- no cgroup v2 events interface.
- `open(cgroup.kill)   ENOENT` -- pre-5.14 kernel without
  `cgroup.kill`.

Once latched the dispatcher stops siblings from re-probing.

### Cleanup ordering

On every supervisor exit path: SIGKILL the inner (idempotent if
`cgroup.kill` already reaped it), `waitpid_eintr`, close
events/kill/pipe fds, `rmdir` the cgroup directory.  `rmdir` is
best-effort -- a cgroup with lingering offlining state may return
`EBUSY` transiently; we don't retry, the next recipe call uses a
fresh PID-named directory anyway.

Per-call fork failure (`EAGAIN` under nproc/thread limits) is
reported by the supervisor as exit code 2 (transient); the dispatcher
will pick again next cycle.
