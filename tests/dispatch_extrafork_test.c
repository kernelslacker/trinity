/*
 * Self-check for EXTRA_FORK dispatch (dispatch/syscall.c).  A live call
 * reports back from its throwaway grandchild through the shared record.  A
 * --dry-run call has nothing to contain, so its synthesized outcome has to
 * land in the caller's own record; routed through do_extrafork() it is lost
 * wherever that is compiled out (ASAN).  The fchdir, fchroot and setns
 * sanitisers run in the child, so the fd they open has to be closed there,
 * and only that one.  The coupling validator that runs on the final argument
 * slots must keep an fcntl F_SETSIG from routing a SIGIO the parent would not
 * ignore, whatever rewrote the slots after the sanitiser.  A live call whose
 * fork fails because the child's forks were moved into a pid namespace that
 * has lost its init has to recycle the child.
 */

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "args-internal.h"	/* nested_address_scrub */
#include "child.h"
#include "child-internal.h"	/* pidns_note_fork_target, pidns_init_lost */
#include "debug.h"		/* BUG */
#include "fd-event.h"		/* fd_event_enqueue */
#include "kcov.h"
#include "params.h"		/* dry_run, frontier_noise_sample */
#include "sanitise.h"		/* get_argval */
#include "signals.h"		/* parent_ignores_sigio_as */
#include "syscall.h"
#include "syscalls/syscalls.h"	/* syscall_fchdir, syscall_fchroot */
#include "tmpdir.h"		/* change_tmp_dir */
#include "utils.h"		/* get_num_fds */

/* Owned by main/params/, which the test binary does not link. */
bool dry_run;
unsigned int frontier_noise_sample;

/* How many dispatches went through do_extrafork(). */
static unsigned int extrafork_notes;

/*
 * What __do_syscall() and do_extrafork() reach that the test binary does
 * not link.  None of it matters to the calls made here; kcov_note_extrafork()
 * also counts.
 */
void kcov_enable_trace(struct kcov_child *kc) { (void)kc; }
void kcov_enable_cmp(struct kcov_child *kc) { (void)kc; }
void kcov_enable_remote(struct kcov_child *kc, unsigned int id, unsigned int nr)
{
	(void)kc; (void)id; (void)nr;
}
void kcov_disable(struct kcov_child *kc) { (void)kc; }

void kcov_note_extrafork(struct kcov_child *kc, unsigned int nr)
{
	(void)kc; (void)nr;
	extrafork_notes++;
}

void validator_rejected_bump(void) { }

/*
 * What validate_arg_coupling() reaches.  Nothing is tracked unless a test
 * registers a region with fake_track_region(), so no base has an extent to
 * clamp a length to here.
 */
unsigned long get_argval(struct syscallrecord *rec, unsigned int argnum)
{
	switch (argnum) {
	case 1: return rec->a1;
	case 2: return rec->a2;
	case 3: return rec->a3;
	case 4: return rec->a4;
	case 5: return rec->a5;
	case 6: return rec->a6;
	}
	return 0;
}

void nested_address_scrub(struct syscallentry *entry, struct syscallrecord *rec)
{
	(void)entry; (void)rec;
}

bool fd_event_enqueue(struct fd_event_ring *ring, enum fd_event_type type, int fd1)
{
	(void)ring; (void)type; (void)fd1;
	return false;
}

/* Shared, as in production: a write by the grandchild is visible to us. */
static struct childdata *map_child(void)
{
	struct childdata *child = mmap(NULL, sizeof(*child), PROT_READ | PROT_WRITE,
				       MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if (child == MAP_FAILED)
		BUG("dispatch_extrafork: cannot map a childdata");
	child->fail_nth_fd = -1;
	__atomic_store_n(&child->syscall.state, PREP, __ATOMIC_RELAXED);
	return child;
}

static void selftest_dry_run(void)
{
	struct syscallentry entry = { .name = "probe", .flags = EXTRA_FORK };
	struct childdata *child = map_child();
	struct syscallrecord *rec = &child->syscall;

	dry_run = true;
	extrafork_notes = 0;
	do_syscall(rec, &entry, &child->kcov, child);
	dry_run = false;

	if (extrafork_notes != 0)
		BUG("dispatch_extrafork: a dry-run EXTRA_FORK call spawned a grandchild");
	if (__atomic_load_n(&rec->state, __ATOMIC_ACQUIRE) != AFTER ||
	    rec->retval != (unsigned long)-1L || rec->errno_post != ENOSYS)
		BUG("dispatch_extrafork: a dry-run EXTRA_FORK call recorded no outcome");

	munmap(child, sizeof(*child));
}

/* getppid() in the grandchild answers with this process. */
static void selftest_live(void)
{
#ifdef __SANITIZE_ADDRESS__
	printf("(do_extrafork is compiled out under ASAN, skipping the live call) ");
#else
	struct syscallentry entry = { .name = "probe", .flags = EXTRA_FORK };
	struct childdata *child = map_child();
	struct syscallrecord *rec = &child->syscall;

	rec->nr = __NR_getppid;
	extrafork_notes = 0;
	do_syscall(rec, &entry, &child->kcov, child);

	if (extrafork_notes != 1)
		BUG("dispatch_extrafork: a live EXTRA_FORK call did not go through do_extrafork");
	if (__atomic_load_n(&rec->state, __ATOMIC_ACQUIRE) != AFTER ||
	    rec->retval != (unsigned long)getpid() || rec->errno_post != 0)
		BUG("dispatch_extrafork: the grandchild's outcome did not reach the caller's record");

	munmap(child, sizeof(*child));
#endif
}

/* How the namespace helper exits when it cannot unshare them. */
#define NO_USERNS	77

/*
 * A child holding CAP_SYS_ADMIN in a user namespace can have a fuzzed
 * unshare(CLONE_NEWPID) move its forks into a new namespace.  The first
 * fork there becomes its pid 1; once that has exited, the next EXTRA_FORK
 * call's fork fails with ENOMEM, and the child has to recycle rather than
 * fuzz on without forks.
 */
static void selftest_dead_pidns(void)
{
#ifdef __SANITIZE_ADDRESS__
	printf("(do_extrafork is compiled out under ASAN, skipping the dead pid namespace) ");
#else
	pid_t helper = fork();
	int status;

	if (helper < 0)
		BUG("dispatch_extrafork: fork failed");
	if (helper == 0) {
		struct syscallentry entry = { .name = "probe", .flags = EXTRA_FORK };
		struct childdata *child;
		pid_t first;

		/* Don't outlive the test binary if the check aborts. */
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (unshare(CLONE_NEWUSER) != 0)
			_exit(NO_USERNS);
		pidns_note_fork_target();
		if (unshare(CLONE_NEWPID) != 0)
			_exit(NO_USERNS);
		first = fork();
		if (first == 0)
			_exit(0);
		if (first < 0 || waitpid_eintr(first, NULL, 0) != first)
			BUG("dispatch_extrafork: cannot fork pid 1 of the new namespace");

		child = map_child();
		child->syscall.nr = __NR_getppid;
		do_syscall(&child->syscall, &entry, &child->kcov, child);
		if (!pidns_init_lost())
			BUG("dispatch_extrafork: a fork's ENOMEM in a dead pid namespace kept the child");
		_exit(0);
	}
	if (waitpid_eintr(helper, &status, 0) != helper)
		BUG("dispatch_extrafork: cannot reap the namespace helper");
	if (WIFEXITED(status) && WEXITSTATUS(status) == NO_USERNS) {
		printf("(no unprivileged user namespaces, skipping the dead pid namespace) ");
		return;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		BUG("dispatch_extrafork: the dead pid namespace check failed");
#endif
}

#define NR_FD_CALLS	100

/*
 * Take @entry through sanitise, dispatch and cleanup the way dispatch_step()
 * does.  The dispatcher runs .post only for a call that reached AFTER with an
 * accepted return value, so @post_runs says whether it does here; .cleanup
 * always runs.  A /dev/null fd stands in for the pool fd the generator leaves
 * in a1 when the sanitiser keeps its draw: it must come through open.
 */
static void owned_fd_closed_after_call(struct syscallentry *entry, bool post_runs)
{
	struct childdata *child = map_child();
	struct syscallrecord *rec = &child->syscall;
	int pool_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	int before, opened = 0;
	unsigned int i;

	if (pool_fd < 0)
		BUG("dispatch_extrafork: cannot open /dev/null");
	before = get_num_fds();

	dry_run = true;
	for (i = 0; i < NR_FD_CALLS; i++) {
		int fd;

		rec->post_state = 0;
		rec->a1 = (unsigned long) pool_fd;
		entry->sanitise(rec);

		/* An fd the sanitiser opened is neither the pool fd nor a sentinel. */
		fd = (int) rec->a1;
		if (fd < 0 || fd == pool_fd) {
			fd = -1;
		} else {
			opened++;
			/*
			 * A chain splice can overwrite the slot after the
			 * sanitiser ran: what gets closed has to be the fd it
			 * opened, not whatever a1 holds now.
			 */
			if (opened % 2 == 0)
				rec->a1 = (unsigned long) pool_fd;
		}

		do_syscall(rec, entry, &child->kcov, child);
		if (fd >= 0 && fcntl(fd, F_GETFD) < 0)
			BUG("dispatch_extrafork: the fd was closed before the call returned");

		if (post_runs && entry->post != NULL)
			entry->post(rec);
		if (entry->cleanup != NULL)
			entry->cleanup(rec);
		if (fd >= 0 && fcntl(fd, F_GETFD) >= 0)
			BUG("dispatch_extrafork: the sanitiser's fd is still open after the call");
	}
	dry_run = false;

	/* A call whose open failed has opened nothing and left the pool fd in a1. */
	rec->post_state = 0;
	rec->a1 = (unsigned long) pool_fd;
	if (post_runs && entry->post != NULL)
		entry->post(rec);
	if (entry->cleanup != NULL)
		entry->cleanup(rec);

	if (fcntl(pool_fd, F_GETFD) < 0)
		BUG("dispatch_extrafork: closed a descriptor the sanitiser did not open");
	if (opened == 0)
		BUG("dispatch_extrafork: the sanitiser never opened an fd, so nothing was checked");
	if (get_num_fds() != before)
		BUG("dispatch_extrafork: the calls left descriptors open");

	close(pool_fd);
	munmap(child, sizeof(*child));
}

/*
 * fchdir and fchroot open trinity_tmpdir_abs(); tmpdir_test.c leaves it at a
 * tmp/ it removed.  setns needs none of this.
 */
static void selftest_owned_fds(void)
{
	char base[] = "/tmp/trinity-extrafork-test.XXXXXX";
	char tmp[sizeof(base) + sizeof("/tmp")];
	int cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	struct syscallentry *entries[] = {
		&syscall_fchdir, &syscall_fchroot, &syscall_setns,
	};
	unsigned int i;

	if (cwd < 0 || mkdtemp(base) == NULL || chdir(base) != 0 ||
	    mkdir("tmp", 0700) != 0)
		BUG("dispatch_extrafork: cannot set up a tmp/");
	change_tmp_dir();

	for (i = 0; i < ARRAY_SIZE(entries); i++) {
		owned_fd_closed_after_call(entries[i], true);
		owned_fd_closed_after_call(entries[i], false);
	}

	if (fchdir(cwd) != 0)
		BUG("dispatch_extrafork: cannot return to the starting directory");
	close(cwd);
	snprintf(tmp, sizeof(tmp), "%s/tmp", base);
	if (rmdir(tmp) != 0 || rmdir(base) != 0)
		BUG("dispatch_extrafork: cannot remove the test tree");
}

/*
 * Dispatch an fcntl whose cmd and arg slots hold @cmd and @arg, as chain
 * substitution or the RedQueen pin leave them after the sanitiser has
 * run, and return the arg the kernel is handed.  F_SETSIG makes the kernel
 * route an fd's SIGIO to the signal in the arg, and the owner can be the
 * parent.
 */
static unsigned long dispatch_fcntl(struct syscallentry *entry,
				    unsigned long cmd, unsigned long arg)
{
	struct childdata *child = map_child();
	struct syscallrecord *rec = &child->syscall;
	unsigned long handed;

	rec->entry = entry;
	rec->a2 = cmd;
	rec->a3 = arg;

	dry_run = true;
	do_syscall(rec, entry, &child->kcov, child);
	dry_run = false;

	if (rec->validator_rejected)
		BUG("dispatch_extrafork: the coupling validator rejected an fcntl it could repair");
	handed = rec->a3;
	munmap(child, sizeof(*child));
	return handed;
}

/*
 * Every signal through the real validator, then the slot shapes the kernel
 * reads differently from the 64-bit record: do_fcntl() takes the cmd as an
 * unsigned int and the arg as an int.
 */
static void selftest_fcntl_setsig(void)
{
	struct syscallentry fcntl_entry = { .name = "fcntl", .num_args = 3,
					    .is_fcntl = true };
	struct syscallentry other_entry = { .name = "probe", .num_args = 3 };
	unsigned long sig, handed;

	for (sig = 0; sig <= 128; sig++) {
		handed = dispatch_fcntl(&fcntl_entry, F_SETSIG, sig);
		if (parent_ignores_sigio_as(sig)) {
			if (handed != sig)
				BUG("dispatch_extrafork: F_SETSIG lost a signal the parent ignores");
		} else if (handed != 0) {
			BUG("dispatch_extrafork: F_SETSIG routes a SIGIO the parent would not ignore");
		}
	}

	/* The upper half of the arg never reaches the kernel's int. */
	handed = dispatch_fcntl(&fcntl_entry, F_SETSIG, (1UL << 32) | SIGKILL);
	if (handed != 0)
		BUG("dispatch_extrafork: F_SETSIG hid SIGKILL in the upper half of the arg");
	handed = dispatch_fcntl(&fcntl_entry, F_SETSIG, (1UL << 40) | SIGUSR1);
	if (handed != ((1UL << 40) | SIGUSR1))
		BUG("dispatch_extrafork: F_SETSIG lost a signal the parent ignores behind upper bits");

	/* A negative int is an EINVAL for the kernel, not a signal. */
	handed = dispatch_fcntl(&fcntl_entry, F_SETSIG, 0xfffffff7UL);
	if (handed != 0xfffffff7UL)
		BUG("dispatch_extrafork: F_SETSIG repaired an arg the kernel refuses anyway");

	/* Nor does the upper half of the cmd hide an F_SETSIG. */
	handed = dispatch_fcntl(&fcntl_entry, (1UL << 32) | F_SETSIG, SIGKILL);
	if (handed != 0)
		BUG("dispatch_extrafork: F_SETSIG hid its cmd in the upper half of the slot");

	/* Only F_SETSIG routes a signal, and only fcntl has an F_SETSIG. */
	handed = dispatch_fcntl(&fcntl_entry, F_SETFD, SIGKILL);
	if (handed != SIGKILL)
		BUG("dispatch_extrafork: an fcntl cmd other than F_SETSIG had its arg rewritten");
	handed = dispatch_fcntl(&other_entry, F_SETSIG, SIGKILL);
	if (handed != SIGKILL)
		BUG("dispatch_extrafork: a syscall other than fcntl had its arg rewritten");
}

void dispatch_extrafork_self_check(void);
void dispatch_extrafork_self_check(void)
{
	selftest_dry_run();
	selftest_live();
	selftest_dead_pidns();
	selftest_owned_fds();
	selftest_fcntl_setsig();
}
