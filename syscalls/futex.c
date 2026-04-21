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
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"

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
	FUTEX_WAIT_REQUEUE_PI_PRIVATE, FUTEX_CMP_REQUEUE_PI_PRIVATE,
	FUTEX_LOCK_PI2, FUTEX_LOCK_PI2_PRIVATE,
};

static inline bool futex_pi_cmd(int cmd)
{
	switch (cmd) {
	case FUTEX_LOCK_PI:
	case FUTEX_LOCK_PI_PRIVATE:
	case FUTEX_LOCK_PI2:
	case FUTEX_LOCK_PI2_PRIVATE:
	case FUTEX_TRYLOCK_PI:
	case FUTEX_TRYLOCK_PI_PRIVATE:
	case FUTEX_UNLOCK_PI:
	case FUTEX_UNLOCK_PI_PRIVATE:
	case FUTEX_CMP_REQUEUE_PI:
	case FUTEX_CMP_REQUEUE_PI_PRIVATE:
	case FUTEX_WAIT_REQUEUE_PI:
	case FUTEX_WAIT_REQUEUE_PI_PRIVATE:
		return true;
	default:
		return false;
	}
}

struct __lock * get_random_lock(void)
{
	struct object *obj;
	enum obj_scope scope;

	/*
	 * If a child creates a futex, it should add it to OBJ_LOCAL
	 * list instead, because if it segfaults, we'll end up with
	 * a stale address in a global list.
	 */
	if (this_child() == NULL)
		scope = OBJ_GLOBAL;
	else
		scope = OBJ_LOCAL;

	obj = get_random_object(OBJ_FUTEX, scope);
	if (!obj)
		return NULL;

	return &obj->lock;
}

static uint32_t * get_futex_mmap(void)
{
	struct object *obj;
	struct map *map;
	enum obj_scope scope;

	/*
	 * If a child creates a futex, it should add it to OBJ_LOCAL
	 * list instead, because if it segfaults, we'll end up with
	 * a stale address in a global list.
	 */
	if (this_child() == NULL)
		scope = OBJ_GLOBAL;
	else
		scope = OBJ_LOCAL;

	obj = get_random_object(OBJ_MMAP_ANON, scope);
	if (!obj)
		return NULL;

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

static void dump_futex(struct object *obj, __unused__ enum obj_scope scope)
{
	output(0, "futex: %x owner:%d scope:%d\n", obj->lock.futex, obj->lock.owner_pid, scope);
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

REG_GLOBAL_OBJ(futexes, create_futexes);

/*
 * Seed a child's local OBJ_FUTEX pool from the global pool at fork time.
 * Mirrors init_child_mappings(): walk the global list under a capacity cap,
 * allocate a fresh local object per entry, copy the lock fields, and add to
 * OBJ_LOCAL.  Children then read only their own pool — no global list access,
 * no shm->objlock from child context.
 */
void init_child_futexes(void)
{
	struct list_head *globallist, *node;
	struct objhead *head;

	head = get_objhead(OBJ_LOCAL, OBJ_FUTEX);
	head->dump = dump_futex;

	globallist = shm->global_objects[OBJ_FUTEX].list;
	if (globallist == NULL)
		return;

	{
		unsigned int seen = 0;
		const unsigned int max_iter = GLOBAL_OBJ_MAX_CAPACITY + 1;

		list_for_each(node, globallist) {
			struct object *globalobj, *newobj;
			struct __lock *src, *dst;

			if (node == NULL)
				break;

			if (++seen > max_iter) {
				outputerr("init_child_futexes: global futex list looks corrupt (>%u entries), bailing\n",
					  max_iter);
				break;
			}

			globalobj = (struct object *) node;
			src = &globalobj->lock;

			newobj = alloc_object();
			dst = &newobj->lock;
			dst->futex = src->futex;
			dst->owner_pid = src->owner_pid;
			add_object(newobj, OBJ_LOCAL, OBJ_FUTEX);
		}
	}
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
			return true;
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

	return false;
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
	unsigned int op = RAND_ARRAY(op_flags) | RAND_ARRAY(cmp_flags);

	/* Exercise the shift path: bit 3 of op field uses (1 << oparg) */
	if (RAND_BOOL())
		op |= FUTEX_OP_OPARG_SHIFT;

	return op;
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
		if (!lock1 || !lock2)
			goto out_setclock;

		rec->a1 = (unsigned long) &lock1->futex; /* uaddr */
		/* ^^ no, we do not have 64-bit futexes :P */
		rec->a5 = (unsigned long) &lock2->futex; /* uaddr2 */
	} else {
		rec->a1 = (unsigned long) get_futex_mmap();
		rec->a5 = (unsigned long) get_futex_mmap();
		goto out_setclock;
	}

	switch (rand() % 4) {
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
	switch (rec->a2 & FUTEX_CMD_MASK) {
	case FUTEX_FD:
		rec->rettype = RET_FD;
		break;
	default:
		rec->rettype = RET_ZERO_SUCCESS;
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
}

struct syscallentry syscall_futex = {
	.name = "futex",
	.num_args = 6,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_OP, [3] = ARG_ADDRESS, [4] = ARG_ADDRESS },
	.argname = { [0] = "uaddr", [1] = "op", [2] = "val", [3] = "utime", [4] = "uaddr2", [5] = "val3" },
	.arg_params[1].list = ARGLIST(futex_ops),
	.flags = NEED_ALARM | IGNORE_ENOSYS,
	.sanitise = sanitise_futex,
	.post = post_futex,
	.group = GROUP_IPC,
};
