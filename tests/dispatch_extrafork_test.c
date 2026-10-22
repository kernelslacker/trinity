/*
 * Self-check for how do_syscall() (dispatch/syscall.c) accounts an
 * EXTRA_FORK entry.  A live call reports back from its throwaway
 * grandchild through the shared record.  A --dry-run call has nothing to
 * contain, so its synthesized outcome has to land in the caller's own
 * record; routed through do_extrafork() it is lost wherever that is
 * compiled out (ASAN).
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/mman.h>
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
#include "tables.h"		/* deactivate_syscall_nolock */
#include "utils.h"

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

void dispatch_extrafork_self_check(void);
void dispatch_extrafork_self_check(void)
{
	selftest_dry_run();
	selftest_live();
}
