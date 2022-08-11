/*
 * SYSCALL_DEFINE6(futex, u32 __user *, uaddr, int, op, u32, val,
	 struct timespec __user *, utime, u32 __user *, uaddr2, u32, val3)
 */
#include <linux/futex.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <inttypes.h>
#include "futex.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"

#define FUTEX_UNLOCKED (0)
#define FUTEX_LOCKED (!FUTEX_UNLOCKED)
#define NFUTEXES (5 * num_online_cpus)

static unsigned long futex_ops[] = {
	FUTEX_WAIT, FUTEX_WAKE, FUTEX_FD, FUTEX_REQUEUE,
	FUTEX_CMP_REQUEUE, FUTEX_WAKE_OP, FUTEX_LOCK_PI,
	FUTEX_UNLOCK_PI, FUTEX_TRYLOCK_PI, FUTEX_WAIT_BITSET,
	FUTEX_WAKE_BITSET, FUTEX_WAIT_REQUEUE_PI, FUTEX_CMP_REQUEUE_PI,
	FUTEX_WAIT_PRIVATE, FUTEX_WAKE_PRIVATE, FUTEX_REQUEUE_PRIVATE,
	FUTEX_CMP_REQUEUE_PRIVATE, FUTEX_WAKE_OP_PRIVATE, FUTEX_LOCK_PI_PRIVATE,
	FUTEX_UNLOCK_PI_PRIVATE, FUTEX_TRYLOCK_PI_PRIVATE,
	FUTEX_WAIT_BITSET_PRIVATE, FUTEX_WAKE_BITSET_PRIVATE,
	FUTEX_WAIT_REQUEUE_PI_PRIVATE,
};

static inline bool futex_pi_cmd(int cmd)
{
	switch (cmd) {
	case FUTEX_LOCK_PI:
	case FUTEX_LOCK_PI_PRIVATE:
	case FUTEX_TRYLOCK_PI:
	case FUTEX_TRYLOCK_PI_PRIVATE:
	case FUTEX_UNLOCK_PI:
	case FUTEX_UNLOCK_PI_PRIVATE:
	case FUTEX_CMP_REQUEUE_PI:
	case FUTEX_CMP_REQUEUE_PI_PRIVATE:
	case FUTEX_WAIT_REQUEUE_PI:
	case FUTEX_WAIT_REQUEUE_PI_PRIVATE:
		return TRUE;
	default:
		return FALSE;
	}
}

struct __lock * get_random_lock(void)
{
	struct object *obj;
	bool global;

	/*
	 * If a child creates a futex, it should add it to OBJ_LOCAL
	 * list instead, because if it segfaults, we'll end up with
	 * a stale address in a global list.
	 */
	if (this_child() == NULL)
		global = OBJ_GLOBAL;
	else
		global = OBJ_LOCAL;

	obj = get_random_object(OBJ_FUTEX, global);
	if (!obj)
		obj = get_random_object(OBJ_MMAP_ANON, OBJ_GLOBAL);

	return &obj->lock;
}

static uint32_t * get_futex_mmap(void)
{
	struct object *obj;
	struct map *map;
	bool global;

	/*
	 * If a child creates a futex, it should add it to OBJ_LOCAL
	 * list instead, because if it segfaults, we'll end up with
	 * a stale address in a global list.
	 */
	if (this_child() == NULL)
		global = OBJ_GLOBAL;
	else
		global = OBJ_LOCAL;

	obj = get_random_object(OBJ_MMAP_ANON, global);
	if (!obj)
		obj = get_random_object(OBJ_MMAP_ANON, OBJ_GLOBAL);

	map = &obj->map;
	return (uint32_t *)map->ptr;

}

/*
 * Ok, so futexes aren't actually created/destroyed, at least not in the
 * traditional way, such how we handle fds.
 *
 * However, create a special area in the shared memory playground dedicated
 * to futexes; such that we have "clean" (zero-initialized) list of aligned
 * 32-bit uaddresses to provide to futex(2).
 */
static inline void futex_init_lock(struct __lock *thislock)
{
	thislock->futex = 0;
	thislock->owner_pid = 0;
}

static void dump_futex(struct object *obj, __unused__ bool global)
{
	output(0, "futex: %x owner:%d global:%d\n", obj->lock.futex, obj->lock.owner_pid, global);
}

void create_futexes(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FUTEX);
	head->dump = dump_futex;

	for (i = 0; i < NFUTEXES; i++) {
		struct object *obj = alloc_object();
		struct __lock *thislock = &obj->lock;

		futex_init_lock(thislock);
		add_object(obj, OBJ_GLOBAL, OBJ_FUTEX);
	}

	output(0, "Reserved/initialized %d futexes.\n", NFUTEXES);
}

static inline uint32_t
__cmpxchg(uint32_t *uaddr, uint32_t oldval, uint32_t newval)
{
	return __sync_val_compare_and_swap(uaddr, oldval, newval);
}

static bool futex_trylock_or_wait(struct __lock *thislock, struct syscallrecord *rec)
{
	int status = thislock->futex;

	if (status == FUTEX_UNLOCKED) {
		status = __cmpxchg(&thislock->futex, FUTEX_UNLOCKED, FUTEX_LOCKED);
		if (status == FUTEX_UNLOCKED) {
			/*
			 * Boring scenario: uncontended lock, acquired it in
			 * userspace; so do whatever trinity was going to do
			 * anyway in the first place.
			 */
			thislock->owner_pid = getpid();
			return TRUE;
		}
	}

	/*
	 * The lock condition could have raced by the time we are here, but
	 * whatever, this is a fuzzy tester and a concurrency is part of the mix.
	 * For the FUTEX_LOCK_PI, we'd be setting the waiters bit.
	 */
	if (!futex_pi_cmd(rec->a2) && RAND_BOOL()) {
		rec->a2 = RAND_BOOL() ? FUTEX_WAIT : FUTEX_WAIT_PRIVATE;
		rec->a3 = FUTEX_LOCKED;
	} else
		rec->a2 = FUTEX_LOCK_PI;

	return FALSE;
}

static inline void futex_unlock(struct __lock *thislock)
{
	int status = thislock->futex;

	if (status == FUTEX_LOCKED) {
		thislock->owner_pid = 0;
		__cmpxchg(&thislock->futex, FUTEX_LOCKED, FUTEX_UNLOCKED);

		/*
		 * Blindly wakeup anyone blocked waiting on the lock.
		 *
		 * Could perfectly well be a bogus wakeup; don't even bother
		 * checking return val...
		 */
		syscall(SYS_futex, &thislock->futex, FUTEX_WAKE, 1, NULL, 0, 0);
		syscall(SYS_futex, &thislock->futex, FUTEX_UNLOCK_PI, 1, NULL, 0, 0);
	}
}

static inline int random_futex_wake_op(void)
{
	const unsigned int op_flags[] = {
		FUTEX_OP_SET, FUTEX_OP_ADD, FUTEX_OP_OR,
		FUTEX_OP_ANDN, FUTEX_OP_XOR,
	};
	const unsigned int cmp_flags[] = {
		FUTEX_OP_CMP_EQ, FUTEX_OP_CMP_NE, FUTEX_OP_CMP_LT,
		FUTEX_OP_CMP_LE, FUTEX_OP_CMP_GT, FUTEX_OP_CMP_GE,
	};

	return RAND_ARRAY(op_flags) | RAND_ARRAY(cmp_flags);
}

static int toggle_futex_fail_inj(__unused__ bool on)
{
	int err = 0;
#if 0

	if (access("/proc/self/make-it-fail", W_OK) == -1)
		goto done;

	if (!on) {
		err = system("echo 0 > /proc/self/make-it-fail");
		goto done;
	} else
		err = system("echo 1 > /proc/self/make-it-fail");

	/*
	 * Even if we can, do not always fiddle with the fail_futex debugfs
	 * config entries. In most cases, setting make-it-fail above, and
	 * clearing it after the futex call, will be enough.
	 */
	if (RAND_BOOL())
		goto done;

	/* probably no permissions or lack of debugfs/error injection support */
	if (access("/sys/kernel/debug/fail_futex/", W_OK) == -1)
		goto done;

	err = system("echo Y > /sys/kernel/debug/fail_futex/ignore-private");
	err = system("echo Y > /sys/kernel/debug/fail_futex/task-filter");
	err = system("echo 1 > /sys/kernel/debug/fail_futex/times");
done:
#endif
	return err;
}

/*
 * Roughly half the calls will use the generic arguments,
 * with the occasional exception of using CLOCK_REALTIME,
 * when applicable to the correct cmd (avoid -ENOSYS).
 *
 * The other half can perform anyone of the following
 * operations, each with a ~25% chance, acting on at most
 * two uaddresses from a small pool selected randomly.
 *
 * (1) Perform a pseudo trylock/unlock. Contended scenarios
 * involve immediately blocking or doing a pi lock.
 *
 * (2) Wait/requeue, which pairs with one of the below wakes.

 * (3) WAKE_OP, or,
 * (4) a regular wake or directly requeueing.
 */
static void sanitise_futex(struct syscallrecord *rec)
{
	struct __lock *lock1, *lock2;

	if (RAND_BOOL() && futex_pi_cmd(rec->a2))
		setpriority(PRIO_PROCESS, 0,
			    RAND_RANGE(PRIO_MIN, PRIO_MAX - 1));

	/*
	 * We can either use one of our reserved futexes, or grab an
	 * address from the mmap playground -- which spices things up
	 * from a memory point of view, but should still be pretty
	 * trivial for the actual futex subsystem.
	 */
	if (RAND_BOOL()) {
		lock1 = get_random_lock();
		lock2 = get_random_lock();

		rec->a1 = (unsigned long) &lock1->futex; /* uaddr */
		/* ^^ no, we do not have 64-bit futexes :P */
		rec->a5 = (unsigned long) &lock2->futex; /* uaddr2 */
	} else {
		rec->a1 = (unsigned long) get_futex_mmap();
		rec->a5 = (unsigned long) get_futex_mmap();
		goto out_setclock;
	}

	switch (rnd() % 4) {
	case 0:
		if (futex_trylock_or_wait(lock1, rec))
			futex_unlock(lock1);
		break;
	case 1:
		rec->a2 = FUTEX_WAIT_REQUEUE_PI;
		rec->a3 = 0;
		break;
	case 2:
		rec->a2 = FUTEX_WAKE_OP;
		rec->a3 = 1;
		rec->a6 = random_futex_wake_op();
		break;
	case 3:
		if (RAND_BOOL()) {
			rec->a2 = FUTEX_WAKE;
		} else  {
			rec->a2 = FUTEX_CMP_REQUEUE_PI;
		}

		/*
		 * In the case of cmp requeue_pi, val (nr_wakeups) should
		 * normally be 1, but be naughty.
		 */
		rec->a3 = INT_MAX;
		break;
	default:
		break;
	}

	if (ONE_IN(100))
		(void)toggle_futex_fail_inj(TRUE);

out_setclock:
	switch (rec->a2) {
	case FUTEX_WAIT:
	case FUTEX_WAIT_PRIVATE:
	case FUTEX_WAIT_BITSET:
	case FUTEX_WAIT_BITSET_PRIVATE:
	case FUTEX_WAIT_REQUEUE_PI:
	case FUTEX_WAIT_REQUEUE_PI_PRIVATE:
		if (RAND_BOOL())
			rec->a2 |= FUTEX_CLOCK_REALTIME;
		break;
	default:
		break;
	}
}

static void post_futex(struct syscallrecord *rec)
{
	/*
	 * Restore back to original priority; only useful
	 * if root, otherwise the prio cannot be set back
	 * (lowered) to zero.
	 */
	if (futex_pi_cmd(rec->a2))
		setpriority(PRIO_PROCESS, 0, 0);

	(void)toggle_futex_fail_inj(FALSE);
}

struct syscallentry syscall_futex = {
	.name = "futex",
	.num_args = 6,
	.arg1name = "uaddr",
	.arg2name = "op",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(futex_ops),
	.arg3name = "val",
	.arg4name = "utime",
	.arg4type = ARG_ADDRESS,
	.arg5name = "uaddr2",
	.arg5type = ARG_ADDRESS,
	.arg6name = "val3",
	.rettype = RET_FD,		// FIXME: Needs to mutate depending on 'op' value
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.sanitise = sanitise_futex,
	.post = post_futex,
};
