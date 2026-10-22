/*
 * Self-check for EXTRA_FORK dispatch (dispatch/syscall.c).  A live call
 * reports back from its throwaway grandchild through the shared record.  A
 * --dry-run call has nothing to contain, so its synthesized outcome has to
 * land in the caller's own record; routed through do_extrafork() it is lost
 * wherever that is compiled out (ASAN).  The fchdir and fchroot sanitisers
 * run in the child, so the dirfd they open has to be closed there.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "args-internal.h"	/* nested_address_scrub */
#include "arg_coupling.h"	/* validate_arg_coupling */
#include "child.h"
#include "debug.h"		/* BUG */
#include "fd-event.h"		/* fd_event_enqueue */
#include "kcov.h"
#include "params.h"		/* dry_run, frontier_noise_sample */
#include "syscall.h"
#include "syscalls/syscalls.h"	/* syscall_fchdir, syscall_fchroot */
#include "tables.h"		/* deactivate_syscall_nolock */
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

int validate_arg_coupling(struct syscallrecord *rec)
{
	(void)rec;
	return 0;
}

void validator_rejected_bump(void) { }

void nested_address_scrub(struct syscallentry *entry, struct syscallrecord *rec)
{
	(void)entry; (void)rec;
}

bool fd_event_enqueue(struct fd_event_ring *ring, enum fd_event_type type, int fd1)
{
	(void)ring; (void)type; (void)fd1;
	return false;
}

void deactivate_syscall_nolock(unsigned int calln, bool do32bit)
{
	(void)calln; (void)do32bit;
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

#define NR_DIRFD_CALLS	100

/*
 * Take @entry through sanitise, dispatch and cleanup the way dispatch_step()
 * does.  A /dev/null fd stands in for the pool fd the generator leaves in a1
 * when the sanitiser keeps its draw: it must come through every call open.
 */
static void dirfd_closed_after_call(struct syscallentry *entry)
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
	for (i = 0; i < NR_DIRFD_CALLS; i++) {
		int fd;

		rec->post_state = 0;
		rec->a1 = (unsigned long) pool_fd;
		entry->sanitise(rec);

		/* A dirfd the sanitiser opened is neither the pool fd nor the sentinel. */
		fd = (int) rec->a1;
		if (fd < 0 || fd == pool_fd) {
			fd = -1;
		} else {
			opened++;
			/*
			 * A chain splice can overwrite the slot after the
			 * sanitiser ran: what gets closed has to be the dirfd
			 * it opened, not whatever a1 holds now.
			 */
			if (opened % 2 == 0)
				rec->a1 = (unsigned long) pool_fd;
		}

		do_syscall(rec, entry, &child->kcov, child);
		if (fd >= 0 && fcntl(fd, F_GETFD) < 0)
			BUG("dispatch_extrafork: the dirfd was closed before the call returned");

		if (entry->cleanup != NULL)
			entry->cleanup(rec);
		if (fd >= 0 && fcntl(fd, F_GETFD) >= 0)
			BUG("dispatch_extrafork: the dirfd is still open after the call");
	}
	dry_run = false;

	if (fcntl(pool_fd, F_GETFD) < 0)
		BUG("dispatch_extrafork: closed a descriptor the sanitiser did not open");
	if (opened == 0)
		BUG("dispatch_extrafork: the sanitiser never opened a dirfd, so nothing was checked");
	if (get_num_fds() != before)
		BUG("dispatch_extrafork: the calls left descriptors open");

	close(pool_fd);
	munmap(child, sizeof(*child));
}

/* The sanitisers open trinity_tmpdir_abs(); tmpdir_test.c leaves it at a tmp/ it removed. */
static void selftest_dirfd_cleanup(void)
{
	char base[] = "/tmp/trinity-extrafork-test.XXXXXX";
	char tmp[sizeof(base) + sizeof("/tmp")];
	int cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (cwd < 0 || mkdtemp(base) == NULL || chdir(base) != 0 ||
	    mkdir("tmp", 0700) != 0)
		BUG("dispatch_extrafork: cannot set up a tmp/");
	change_tmp_dir();

	dirfd_closed_after_call(&syscall_fchdir);
	dirfd_closed_after_call(&syscall_fchroot);

	if (fchdir(cwd) != 0)
		BUG("dispatch_extrafork: cannot return to the starting directory");
	close(cwd);
	snprintf(tmp, sizeof(tmp), "%s/tmp", base);
	if (rmdir(tmp) != 0 || rmdir(base) != 0)
		BUG("dispatch_extrafork: cannot remove the test tree");
}

void dispatch_extrafork_self_check(void);
void dispatch_extrafork_self_check(void)
{
	selftest_dry_run();
	selftest_live();
	selftest_dirfd_cleanup();
}
