/*
 * Part of the recipe_runner catalogue; see recipe-runner.c for the
 * design rationale and recipe-runner-internal.h for the shared
 * declarations and macros.
 */

#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "syscall-gate.h"
#include "childops-util.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "childops/recipe/internal.h"

#include "kernel/fcntl.h"
#include "kernel/prctl.h"
#include "kernel/seccomp.h"
#include "kernel/mount.h"
#include "kernel/wait.h"
/* Recipe 33: ptrace SEIZE+EXITKILL supervisor. See Documentation/recipe-catalog.md */
#define RECIPE_PTRACE_SEIZE_MAX_CYCLES		4
#define RECIPE_PTRACE_SEIZE_FORK_FAIL_LATCH	3

bool recipe_ptrace_seize_exitkill(bool *unsupported)
{
	unsigned int cycles;
	unsigned int i;
	unsigned int fork_fail_streak = 0;
	unsigned int completed = 0;
	bool fork_latched = false;

	cycles = 1 + rnd_modulo_u32(RECIPE_PTRACE_SEIZE_MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		siginfo_t si;
		pid_t pid;
		long pr;
		int status;

		pid = fork();
		if (pid < 0) {
			if (++fork_fail_streak >=
			    RECIPE_PTRACE_SEIZE_FORK_FAIL_LATCH) {
				fork_latched = true;
				break;
			}
			continue;
		}
		fork_fail_streak = 0;

		if (pid == 0) {
			/* Inner tracee: block in pause() so the parent has
			 * a deterministic stop point to SEIZE+INTERRUPT.
			 * Any SIGKILL from the parent reaps us cleanly.
			 * _exit() skips atexit handlers that could touch
			 * trinity shared state from a stopped-and-resumed
			 * tracee context.
			 *
			 * PR_SET_PDEATHSIG SIGKILL guards against the
			 * parent crashing before it can SEIZE us; without
			 * it the orphaned tracee sticks in pause()
			 * forever under PID 1.  Re-check getppid() in case
			 * the parent already died in the prctl race
			 * window. */
			(void)trinity_raw_syscall(__NR_prctl, PR_SET_PDEATHSIG, SIGKILL,
				      0UL, 0UL, 0UL);
			if (getppid() == 1)
				_exit(0);
			(void)pause();
			_exit(0);
		}

		pr = ptrace(PTRACE_SEIZE, pid, (void *)0,
			    (void *)(unsigned long)
			    (PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD));
		if (pr < 0) {
			if (i == 0 && (errno == ENOSYS || errno == EPERM ||
				       errno == EACCES)) {
				(void)kill(pid, SIGKILL);
				(void)waitpid_eintr(pid, &status, 0);
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			(void)kill(pid, SIGKILL);
			(void)waitpid_eintr(pid, &status, 0);
			continue;
		}

		/* Move the tracee into PTRACE_EVENT_STOP.  SEIZE never
		 * sends an initial SIGSTOP (unlike ATTACH); INTERRUPT is
		 * the only way to drive a SEIZE'd tracee into a stop. */
		(void)ptrace(PTRACE_INTERRUPT, pid, (void *)0, (void *)0);

		if (waitpid_eintr(pid, &status, __WALL) < 0) {
			(void)kill(pid, SIGKILL);
			(void)waitpid_eintr(pid, &status, 0);
			continue;
		}

		/* If the tracee already died (kernel killed it for whatever
		 * reason), there's no live ptrace state to drive -- just
		 * count the cycle and move on.  This also covers the
		 * EXITKILL-fired-early path where the kernel decided to
		 * kill the tracee on attach. */
		if (!WIFSTOPPED(status)) {
			completed++;
			continue;
		}

		/* Light interaction with the stopped tracee.  Both calls
		 * exercise paths gated on the tracee being in a ptrace
		 * stop; failures are best-effort and intentionally ignored
		 * (a kernel bug here is exactly what we want exposed). */
		memset(&si, 0, sizeof(si));
		(void)ptrace(PTRACE_GETSIGINFO, pid, (void *)0, &si);

		(void)ptrace(PTRACE_SETOPTIONS, pid, (void *)0,
			     (void *)(unsigned long)
			     (PTRACE_O_EXITKILL | PTRACE_O_TRACEEXIT));

		(void)ptrace(PTRACE_CONT, pid, (void *)0, (void *)0);

		/* Tear down: SIGKILL bypasses ptrace and reaps the tracee
		 * via fatal_signal_pending() out of pause() / any ptrace
		 * stop.  waitpid_eintr drains the zombie so we don't leak
		 * a child across recipe invocations. */
		(void)kill(pid, SIGKILL);
		(void)waitpid_eintr(pid, &status, 0);

		completed++;
	}

	/* If every cycle was lost to fork() EAGAIN under sibling process
	 * pressure, that's transient nproc/pid exhaustion -- not a recipe
	 * failure.  Skip rather than score a partial, which would keep the
	 * picker re-selecting us against a path we never exercised. */
	if (completed == 0 && fork_latched)
		return true;

	return completed > 0;
}

/*
 * Inner-child helper for recipe_mount_userns_dance: write a single line
 * to the named /proc/self/{uid_map,gid_map,setgroups} file.  Returns
 * true on a complete write, false otherwise.  Best-effort: callers
 * decide whether a partial map is fatal for their op.  Mirrors the
 * write_one_line helper in childops/misc/userns-fuzzer.c -- intentionally
 * duplicated rather than hoisted, since recipe-runner.c is a self-
 * contained dispatcher and the helper is a 10-line inline that would
 * not benefit from a cross-file abstraction.
 */
static bool mount_userns_write_one_line(const char *path, const char *line)
{
	ssize_t wlen;
	size_t len;
	int fd;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return false;

	len = strlen(line);
	wlen = write(fd, line, len);
	close(fd);
	return wlen == (ssize_t)len;
}

/*
 * Inner child of recipe_mount_userns_dance.  Enters a fresh user
 * namespace + mount namespace, establishes the uid/gid 0 mapping
 * inside the userns, then drives the mount lifecycle described in
 * the recipe header below.  Exits with a status code the parent can
 * decode to differentiate "feature unsupported" from "ran to
 * completion".
 *
 * Exit codes:
 *   0  -- ran the dance to completion (some mount calls may have
 *         failed on the way; that's tolerated, the recipe is about
 *         driving the path, not asserting the result)
 *   1  -- unshare(CLONE_NEWUSER | CLONE_NEWNS) failed -- triggers
 *         the *unsupported latch in the parent
 *   2  -- map establishment failed -- not an unsupported signal
 *         (could be transient EBUSY on the maps, or LSM-specific)
 *   3  -- mount("none", "/", MS_PRIVATE) failed -- can't proceed
 *         safely without a private root inside the new mount ns
 */
static void mount_userns_dance_inner(void) __attribute__((noreturn));
static void mount_userns_dance_inner(void)
{
	char buf[64];
	uid_t uid = geteuid();
	gid_t gid = getegid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0)
		_exit(1);

	/* setgroups must be denied before gid_map can be written when
	 * the writer is unprivileged, per Documentation/admin-guide/
	 * namespaces/user.rst.  The uid_map write order doesn't matter
	 * but we stage all three for symmetry. */
	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned int)uid);
	if (!mount_userns_write_one_line("/proc/self/uid_map", buf))
		_exit(2);

	if (!mount_userns_write_one_line("/proc/self/setgroups", "deny\n"))
		_exit(2);

	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned int)gid);
	if (!mount_userns_write_one_line("/proc/self/gid_map", buf))
		_exit(2);

	/* MS_REC | MS_PRIVATE on the root is mandatory before any further
	 * mount() in this ns -- without it, propagation could leak our
	 * tmpfs into the host mount tree on systems where / is MS_SHARED.
	 * The trinity child already did this once on its own CLONE_NEWNS
	 * unshare at startup, but our fresh CLONE_NEWNS resets the
	 * propagation state and we have to redo it. */
	if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
		_exit(3);

	/* tmpfs at /tmp.  Drives the do_new_mount path through the new
	 * userns/mountns, including the ns_capable check against the ns's
	 * owning userns and the superblock allocation. */
	if (mount("none", "/tmp", "tmpfs", 0, NULL) != 0) {
		/* No tmpfs available, or LSM denial -- still exit success
		 * because the unshare/map path itself was driven. */
		_exit(0);
	}

	/* Propagation flag mutation: change /tmp to MS_PRIVATE
	 * explicitly.  Drives the mount-flag-change path
	 * (do_change_type) distinct from the initial mount creation. */
	(void)mount(NULL, "/tmp", NULL, MS_PRIVATE, NULL);

	/* Remount with new flags: MS_RDONLY|MS_REMOUNT.  Drives the
	 * do_remount path which walks the superblock's remount_fs op
	 * and rewrites mnt_flags atomically. */
	(void)mount(NULL, "/tmp", NULL, MS_RDONLY | MS_REMOUNT, NULL);

	/* Lazy unmount: MNT_DETACH.  Drives the do_umount path with
	 * MNT_DETACH semantics -- detaches from the namespace tree
	 * immediately but defers the actual cleanup until the last
	 * reference drops. */
	(void)umount2("/tmp", MNT_DETACH);

	_exit(0);
}

/* Recipe 34: mount/userns dance. See Documentation/recipe-catalog.md */
bool recipe_mount_userns_dance(bool *unsupported)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return false;

	if (pid == 0) {
		mount_userns_dance_inner();
		/* unreachable -- inner uses _exit on every path */
	}

	if (waitpid_eintr(pid, &status, 0) < 0)
		return false;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
		/* unshare(CLONE_NEWUSER | CLONE_NEWNS) failed -- almost
		 * certainly EPERM from a hardened policy.  Latch so the
		 * dispatcher stops picking this recipe. */
		*unsupported = true;
		__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
				   __ATOMIC_RELAXED);
		return false;
	}

	/* Any other exit code -- including WIFSIGNALED, WEXITSTATUS in
	 * {0, 2, 3} -- counts as having driven the path far enough to
	 * be useful.  WEXITSTATUS 2/3 indicate map-write or root-
	 * remount failure after a successful unshare; the unshare itself
	 * is the dominant kernel surface and is exercised in those
	 * paths regardless. */
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/*
 * Compatibility shims for hosts whose linux/seccomp.h predates the
 * USER_NOTIF listener interface (added in 5.0) or the explicit ALLOW
 * "fake-success" response mode.  Defining the constants locally lets
 * recipe-runner.c build everywhere; the *runtime* check is the seccomp()
 * syscall itself, which returns EINVAL on kernels without the feature
 * and is caught by the unsupported latch below.
 */
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER	(1UL << 3)
#endif

/*
 * Inner child of recipe_seccomp_listener_exec.  Inherits the seccomp
 * filter installed by the supervisor; calls uname() (trapped to
 * USER_NOTIF and held until the supervisor responds via NOTIF_SEND)
 * then execve()s /bin/true to drive the post-filter exec path.
 *
 * uname() is the trap point because glibc never calls it implicitly
 * post-fork along any path we care about — picking mypid() (the
 * obvious other "single-arg, side-effect-free" candidate) would risk
 * the supervisor self-deadlocking the moment libc's own bookkeeping
 * called mypid() between seccomp() install and the first NOTIF_RECV.
 *
 * syscall(__NR_uname, ...) bypasses any libc wrapping that might cache
 * the result or route via vDSO; we want the raw seccomp trap, not a
 * cached struct utsname.  /bin/true is a tiny binary that returns 0;
 * the recipe doesn't depend on its output, only on driving execve()
 * through the post-seccomp-filter task_struct.
 */
static void seccomp_listener_inner(void) __attribute__((noreturn));
static void seccomp_listener_inner(void)
{
	struct utsname u;

	(void)trinity_raw_syscall(__NR_uname, &u);

	(void)execl("/bin/true", "/bin/true", (char *)NULL);

	_exit(0);
}

/*
 * Build and install a SECCOMP_RET_USER_NOTIF filter that traps
 * __NR_uname.  Returns the listener fd from the kernel on success,
 * -1 on failure with errno preserved for the caller's latch.
 */
static int seccomp_listener_install(void)
{
	struct sock_filter filter[] = {
		/* A = seccomp_data.nr (syscall number) */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		/* if (A == __NR_uname) goto notify */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
		/* notify: return USER_NOTIF (kernel parks the syscall and
		 * blocks the calling thread until the listener responds) */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* allow: return ALLOW (everything else passes through) */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};

	return (int)trinity_raw_syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
			    SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

/*
 * Supervisor body of recipe_seccomp_listener_exec.  Runs in its own
 * fork() so the seccomp filter never touches trinity's outer child:
 * once SECCOMP_SET_MODE_FILTER is installed, every uname() in the
 * task and its descendants traps through the listener fd, and the
 * filter cannot be removed.
 *
 * Exit codes (consumed by recipe_seccomp_listener_exec):
 *   0  -- ran the full poll/RECV/ID_VALID/SEND/close/waitpid sequence
 *   1  -- prctl(NO_NEW_PRIVS) or seccomp() returned an "unsupported"
 *         errno (ENOSYS / EINVAL / EACCES) — triggers the *unsupported
 *         latch in the parent
 *   2  -- transient failure pre-listener (prctl other errno, fork failure)
 *   3  -- post-listener flow failure (poll timeout, RECV error) — listener
 *         was created so the feature is supported, just didn't complete
 *         this cycle
 */
#define RECIPE_SECCOMP_LISTENER_POLL_MS	1000

static int recipe_seccomp_listener_supervisor(void)
{
	struct seccomp_notif req;
	struct seccomp_notif_resp resp;
	struct pollfd pfd;
	pid_t inner;
	int listener;
	int status;
	int pr;

	/* NO_NEW_PRIVS is the precondition for an unprivileged
	 * SECCOMP_SET_MODE_FILTER.  ENOSYS here means
	 * CONFIG_SECCOMP=n (PR_SET_NO_NEW_PRIVS landed in 3.5; the
	 * separate seccomp(2) syscall in 3.17). */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) != 0) {
		if (errno == ENOSYS)
			return 1;
		return 2;
	}

	listener = seccomp_listener_install();
	if (listener < 0) {
		/* ENOSYS  : pre-3.17 kernel without the seccomp() syscall.
		 * EINVAL  : SECCOMP_FILTER_FLAG_NEW_LISTENER unsupported
		 *           (pre-5.0) or BPF program rejected.
		 * EACCES  : LSM denial / NO_NEW_PRIVS missing on a code path
		 *           that bypassed the prctl above. */
		if (errno == ENOSYS || errno == EINVAL || errno == EACCES)
			return 1;
		return 2;
	}

	inner = fork();
	if (inner < 0) {
		close(listener);
		return 2;
	}

	if (inner == 0) {
		/* Inner does not need its inherited copy of the listener
		 * fd; closing it here keeps the kernel-side reference count
		 * accurate so the supervisor's close() actually releases the
		 * notification queue. */
		close(listener);
		seccomp_listener_inner();
		/* unreachable -- inner uses _exit on every path */
	}

	/* Pre-poll the listener so a wedged/dead inner doesn't park us
	 * inside NOTIF_RECV indefinitely.  POLLIN fires once the kernel
	 * has a notification ready; POLLHUP fires if every task that
	 * could trap has died. */
	pfd.fd = listener;
	pfd.events = POLLIN;
	pfd.revents = 0;
	pr = poll(&pfd, 1, RECIPE_SECCOMP_LISTENER_POLL_MS);
	if (pr <= 0) {
		(void)kill(inner, SIGKILL);
		(void)waitpid_eintr(inner, &status, 0);
		close(listener);
		return 3;
	}

	memset(&req, 0, sizeof(req));
	if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
		(void)kill(inner, SIGKILL);
		(void)waitpid_eintr(inner, &status, 0);
		close(listener);
		return 3;
	}

	/* ID_VALID returns 0 if the notification is still live, ENOENT if
	 * the trapped task died between RECV and now.  Best-effort: a
	 * dead-tracee response from SEND will fail harmlessly with ENOENT
	 * too, and we proceed to teardown either way. */
	(void)ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &req.id);

	memset(&resp, 0, sizeof(resp));
	resp.id = req.id;
	resp.val = 0;
	resp.error = 0;
	resp.flags = 0;
	(void)ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp);

	close(listener);
	(void)waitpid_eintr(inner, &status, 0);
	return 0;
}

/* Recipe 35: seccomp USER_NOTIF listener + traced exec. See Documentation/recipe-catalog.md */
bool recipe_seccomp_listener_exec(bool *unsupported)
{
	pid_t supervisor;
	int status;

	supervisor = fork();
	if (supervisor < 0)
		return false;

	if (supervisor == 0)
		_exit(recipe_seccomp_listener_supervisor());

	if (waitpid_eintr(supervisor, &status, 0) < 0)
		return false;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
		*unsupported = true;
		__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
				   __ATOMIC_RELAXED);
		return false;
	}

	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/*
 * Inner child of recipe_cgroup_kill_events.  Joins the freshly-mkdir'd
 * cgroup by writing its own pid into <cgroup>/cgroup.procs, signals
 * the supervisor that it is in (or attempted to be in) the cgroup via
 * a single byte on the pipe write end, then pause()s waiting for the
 * SIGKILL the supervisor will issue via the cgroup.kill control file.
 *
 * The signal-byte handshake exists so the supervisor doesn't race
 * ahead and write to cgroup.kill before the inner has joined the
 * cgroup -- otherwise __cgroup_kill walks an empty css_task_iter and
 * the populated/frozen state on cgroup.events never changes,
 * defeating the kernfs_notify wake-poll part of the recipe.
 *
 * cgroup.procs write may legitimately fail (EACCES on a non-delegated
 * subtree under unprivileged trinity, EBUSY in the no-internal-procs
 * window, ENOSPC under cgroup.max.descendants, ...); the inner sends
 * the signal byte regardless so the supervisor doesn't stall, and the
 * supervisor's backup SIGKILL covers the "inner not in the cgroup"
 * case.
 */
static void cgroup_kill_inner(const char *cgroup_path, int pipe_w)
	__attribute__((noreturn));
static void cgroup_kill_inner(const char *cgroup_path, int pipe_w)
{
	char procs_path[128];
	char pidbuf[16];
	ssize_t w __unused__;
	int procs_fd;
	int len;
	char ack = '!';

	(void)snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs",
		       cgroup_path);
	procs_fd = open(procs_path, O_WRONLY);
	if (procs_fd >= 0) {
		len = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)getpid());
		w = write(procs_fd, pidbuf, (size_t)len);
		close(procs_fd);
	}

	/* One byte is enough -- the supervisor read()s exactly one byte and
	 * doesn't care about the value, only the wakeup. */
	w = write(pipe_w, &ack, 1);
	close(pipe_w);

	/* PR_SET_PDEATHSIG SIGKILL: if the supervisor crashes before it
	 * can write(kill_fd, "1\n", 2) into cgroup.kill, the inner would
	 * orphan to PID 1 and pause() forever.  Re-check getppid() to
	 * cover the prctl race window where the supervisor died between
	 * fork and this point. */
	(void)trinity_raw_syscall(__NR_prctl, PR_SET_PDEATHSIG, SIGKILL,
		      0UL, 0UL, 0UL);
	if (getppid() == 1)
		_exit(0);

	(void)pause();
	_exit(0);
}

/*
 * Supervisor body of recipe_cgroup_kill_events.  Owns the cgroup
 * lifecycle (mkdir -> ... -> rmdir) and the cgroup.events / cgroup.kill
 * fds.  Forks a single inner that joins the cgroup and pauses, then
 * drives the cgroup.kill -> kernfs_notify -> cgroup.events post-kill
 * read sequence.
 *
 * Exit codes (consumed by recipe_cgroup_kill_events):
 *   0  -- ran the full mkdir/open/fork/kill/notify/read/waitpid/rmdir
 *         sequence
 *   1  -- mkdir or open(cgroup.events|cgroup.kill) returned an
 *         "unsupported" errno -- triggers the *unsupported latch in
 *         the parent
 *   2  -- transient post-cgroup-create failure (pipe2 / fork / open
 *         non-ENOENT) -- not unsupported, just retry next cycle
 */
#define RECIPE_CGROUP_KILL_NOTIFY_MS	200

static int cgroup_kill_setup(const char *cgroup_path,
			     int *events_fd, int *kill_fd,
			     int pipefd[2], pid_t *inner,
			     bool *cgroup_made)
{
	char path[128];

	if (mkdir(cgroup_path, 0755) != 0) {
		if (errno == EACCES || errno == EPERM || errno == EROFS ||
		    errno == ENOENT || errno == ENOTDIR)
			return 1;
		return 2;
	}
	*cgroup_made = true;

	(void)snprintf(path, sizeof(path), "%s/cgroup.events", cgroup_path);
	*events_fd = open(path, O_RDONLY | O_NONBLOCK);
	if (*events_fd < 0) {
		/* cgroup.events appears whenever cgroup v2 is mounted; ENOENT
		 * here means the kernel doesn't expose it (extremely old
		 * cgroup v2, or a controller-less hierarchy). */
		return (errno == ENOENT) ? 1 : 2;
	}

	(void)snprintf(path, sizeof(path), "%s/cgroup.kill", cgroup_path);
	*kill_fd = open(path, O_WRONLY);
	if (*kill_fd < 0) {
		/* cgroup.kill landed in 5.14; ENOENT here is the canonical
		 * "feature absent" signal that latches the recipe off. */
		return (errno == ENOENT) ? 1 : 2;
	}

	if (pipe2(pipefd, O_CLOEXEC) != 0)
		return 2;

	*inner = fork();
	if (*inner < 0)
		return 2;

	if (*inner == 0) {
		/* Inner doesn't need the supervisor's copies of these fds. */
		close(*events_fd);
		close(*kill_fd);
		close(pipefd[0]);
		cgroup_kill_inner(cgroup_path, pipefd[1]);
		/* unreachable -- inner uses _exit on every path */
	}

	return 0;
}

static void cgroup_kill_poll_cycle(int events_fd, int kill_fd,
				   int pipefd[2], pid_t *inner)
{
	char readbuf[256];
	struct pollfd pfd;
	ssize_t r __unused__;
	ssize_t w __unused__;
	char ack;
	int status;

	/* Supervisor closes its write end; only the inner writes. */
	close(pipefd[1]);
	pipefd[1] = -1;

	/* Wait for the inner's "I'm in (or tried) the cgroup" handshake.
	 * read() blocks until the inner write()s; if the inner died
	 * before signalling we get EOF / 0 bytes and proceed regardless --
	 * the backup SIGKILL + waitpid below cleans up. */
	r = read(pipefd[0], &ack, 1);

	/* Pre-kill best-effort baseline read of cgroup.events.  Drives
	 * cgroup_events_show against a freshly-populated cgroup before any
	 * state change so the post-kill read has a comparator. */
	pfd.fd = events_fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	(void)poll(&pfd, 1, 0);
	r = read(events_fd, readbuf, sizeof(readbuf));

	/* Trigger cgroup.kill: write "1\n".  Drives cgroup_kill_write ->
	 * cgroup_kill_control -> __cgroup_kill which walks css_task_iter
	 * and SIGKILLs every task in this cgroup.  Side effect: the
	 * populated state on cgroup.events flips to 0 once the killed
	 * task is reaped, which fires kernfs_notify on the events file. */
	w = write(kill_fd, "1\n", 2);

	/* Wait up to 200ms for the kernfs_notify wake.  POLLPRI is the
	 * documented wake event for cgroup.events (kernfs_notify uses
	 * EPOLLPRI); some kernels also flag POLLIN.  A 200ms ceiling is
	 * generous enough that even a heavily-loaded host wakes here, but
	 * tight enough not to dominate the recipe's wall clock. */
	pfd.fd = events_fd;
	pfd.events = POLLPRI | POLLIN;
	pfd.revents = 0;
	(void)poll(&pfd, 1, RECIPE_CGROUP_KILL_NOTIFY_MS);

	/* Post-kill read: rewind and re-read cgroup.events to drive
	 * cgroup_events_show again, this time with the
	 * populated/frozen/exit state mutated by __cgroup_kill.  lseek
	 * back to 0 because kernfs files are seekable and a re-read
	 * without rewind would just yield EOF. */
	(void)lseek(events_fd, 0, SEEK_SET);
	r = read(events_fd, readbuf, sizeof(readbuf));

	/* Backup SIGKILL: covers the case where the inner failed to join
	 * the cgroup (write to cgroup.procs was denied), so cgroup.kill
	 * walked an empty iter and didn't reap the inner.  kill() on a
	 * pid already-killed-by-cgroup is a harmless no-op. */
	(void)kill(*inner, SIGKILL);
	(void)waitpid_eintr(*inner, &status, 0);
	*inner = -1;
}

static void cgroup_kill_teardown(const char *cgroup_path,
				 int events_fd, int kill_fd,
				 int pipefd[2], pid_t inner,
				 bool cgroup_made)
{
	int status;

	if (inner > 0) {
		(void)kill(inner, SIGKILL);
		(void)waitpid_eintr(inner, &status, 0);
	}
	if (pipefd[0] >= 0)
		close(pipefd[0]);
	if (pipefd[1] >= 0)
		close(pipefd[1]);
	if (kill_fd >= 0)
		close(kill_fd);
	if (events_fd >= 0)
		close(events_fd);
	if (cgroup_made)
		(void)rmdir(cgroup_path);
}

static int recipe_cgroup_kill_supervisor(void)
{
	char cgroup_path[64];
	int events_fd = -1;
	int kill_fd = -1;
	int pipefd[2] = { -1, -1 };
	pid_t inner = -1;
	int rc;
	bool cgroup_made = false;

	(void)snprintf(cgroup_path, sizeof(cgroup_path),
		       "/sys/fs/cgroup/trinity-kill-%d", (int)getpid());

	rc = cgroup_kill_setup(cgroup_path, &events_fd, &kill_fd,
			       pipefd, &inner, &cgroup_made);
	if (rc != 0)
		goto out;

	cgroup_kill_poll_cycle(events_fd, kill_fd, pipefd, &inner);
	rc = 0;

out:
	cgroup_kill_teardown(cgroup_path, events_fd, kill_fd,
			     pipefd, inner, cgroup_made);
	return rc;
}

/* Recipe 36: cgroup.kill + cgroup.events supervisor. See Documentation/recipe-catalog.md */
bool recipe_cgroup_kill_events(bool *unsupported)
{
	pid_t supervisor;
	int status;

	supervisor = fork();
	if (supervisor < 0)
		return false;

	if (supervisor == 0)
		_exit(recipe_cgroup_kill_supervisor());

	if (waitpid_eintr(supervisor, &status, 0) < 0)
		return false;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
		*unsupported = true;
		__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
				   __ATOMIC_RELAXED);
		return false;
	}

	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
