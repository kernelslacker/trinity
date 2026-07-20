/*
 * SYSCALL_DEFINE3(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
 *
 * For a successful call, the return value depends on the operation:
 *
 *     F_DUPFD The new descriptor.
 *     F_GETFD Value of file descriptor flags.
 *     F_GETFL Value of file status flags.
 *     F_GETLEASE Type of lease held on file descriptor.
 *     F_GETOWN Value of descriptor owner.
 *     F_GETSIG Value of signal sent when read or write becomes possible, or zero for traditional SIGIO behavior.
 *     F_GETPIPE_SZ The pipe capacity.
 *
 *     All other commands
 *              Zero.
 *
 *     On error, -1 is returned, and errno is set appropriately.
 */

#include <signal.h>
#include <stdbool.h>
#include <fcntl.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "../syscalls.h"
#include "trinity.h"

#include "kernel/fcntl.h"
#if F_GETLK64 != F_GETLK
#define HAVE_LK64
#endif

/*
 * Per-child ring of fds we've successfully F_SETLEASE'd on, so that the
 * sibling F_GETLEASE picker can aim at a fd with a known prior lease
 * instead of rolling a random fd that returns F_UNLCK ~always.  Cross-
 * child kernel state means the recorded lease type is a hint for the
 * picker, not authoritative — another child can have replaced or
 * cleared the lease since.  __thread keeps the slot per-child without
 * adding a shm field for a single feature.
 */
#define FCNTL_LEASE_RING_SIZE	16
struct fcntl_lease_slot {
	int fd;
	int lease_type;
};
static __thread struct fcntl_lease_slot lease_ring[FCNTL_LEASE_RING_SIZE];
static __thread unsigned int lease_ring_head;
static __thread unsigned int lease_ring_count;

static void lease_ring_record(int fd, int lease_type)
{
	lease_ring[lease_ring_head].fd = fd;
	lease_ring[lease_ring_head].lease_type = lease_type;
	lease_ring_head = (lease_ring_head + 1) % FCNTL_LEASE_RING_SIZE;
	if (lease_ring_count < FCNTL_LEASE_RING_SIZE)
		lease_ring_count++;
}

static bool lease_ring_pick(int *fd)
{
	unsigned int idx;

	if (lease_ring_count == 0)
		return false;
	idx = rnd_modulo_u32(lease_ring_count);
	*fd = lease_ring[idx].fd;
	return true;
}

/*
 * Per-child ring of fds where a prior SET-side fcntl (F_SETLK,
 * F_SETLKW, F_OFD_SETLK, F_OFD_SETLKW, or the 64-bit variants)
 * returned 0 with a non-F_UNLCK lock type, so a sibling SET on the
 * same fd actually hits posix_lock_inode()'s overlap walk instead of
 * short-circuiting on an empty fl_list.  Without this the SETLK fd
 * was uniform-random across the whole fd pool and the range-compare
 * paths (start/end/whence) almost never fired.  Same pattern as the
 * F_GETLEASE selection bias above — cross-child kernel state means a
 * recorded fd is a hint, not a guarantee.  No lock_type field: the
 * active kernel state at the next SET is what matters, not what we
 * asked for here.
 */
#define FCNTL_SETLK_RING_SIZE	16
static __thread int setlk_ring[FCNTL_SETLK_RING_SIZE];
static __thread unsigned int setlk_ring_head;
static __thread unsigned int setlk_ring_count;

static void setlk_ring_record(int fd)
{
	setlk_ring[setlk_ring_head] = fd;
	setlk_ring_head = (setlk_ring_head + 1) % FCNTL_SETLK_RING_SIZE;
	if (setlk_ring_count < FCNTL_SETLK_RING_SIZE)
		setlk_ring_count++;
}

static bool setlk_ring_pick(int *fd)
{
	unsigned int idx;

	if (setlk_ring_count == 0)
		return false;
	idx = rnd_modulo_u32(setlk_ring_count);
	*fd = setlk_ring[idx];
	return true;
}

static const unsigned long fcntl_o_flags[] = {
	O_APPEND, O_ASYNC, O_DIRECT, O_NOATIME, O_NONBLOCK,
};

unsigned int random_fcntl_setfl_flags(void)
{
	return set_rand_bitmask(ARRAY_SIZE(fcntl_o_flags), fcntl_o_flags);
}

/*
 * Stratified cmd picker.  Uniform sampling across the full cmd list under-
 * exercises the rarer kernel paths (lease/OFD-lock/owner_ex/seals/notify),
 * because most of the cmds in fcntl_flags[] route into a small set of common
 * file_struct accessors.  Bias the picker so the rare paths get hit ~30% of
 * the time, and also drop in a fully random cmd ~10% of the time to cover
 * out-of-table values that exercise the kernel's input validation.
 */
static const unsigned long fcntl_cmds_common[] = {
	F_GETFD, F_SETFD, F_DUPFD, F_GETFL, F_SETFL,
};

static const unsigned long fcntl_cmds_rare[] = {
	F_SETLEASE, F_GETLEASE,
	F_GETOWN_EX, F_SETOWN_EX,
	F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW,
	F_NOTIFY,
	F_ADD_SEALS, F_GET_SEALS,
	F_SETSIG, F_GETSIG,
	F_SETPIPE_SZ,
};

static unsigned long pick_fcntl_cmd(void)
{
	unsigned int r = rnd_modulo_u32(100);

	if (r < 60)
		return fcntl_cmds_common[rnd_modulo_u32(ARRAY_SIZE(fcntl_cmds_common))];
	if (r < 90)
		return fcntl_cmds_rare[rnd_modulo_u32(ARRAY_SIZE(fcntl_cmds_rare))];
	return (unsigned long) rand32();
}

/*
 * Fill a struct flock with a plausible lock request.  The SET-side
 * cmds (F_SETLK/W, F_OFD_SETLK/W, F_CANCELLK) all consume this shape;
 * passing a raw uninitialised pointer EINVAL's before the kernel ever
 * reaches the per-fs flock code, so the SET paths were going unfuzzed.
 * l_pid is zeroed because F_OFD_SETLK requires it.
 */
static void build_flock(struct flock *fl)
{
	static const int lock_types[]  = { F_RDLCK, F_WRLCK, F_UNLCK };
	static const int whence_vals[] = { SEEK_SET, SEEK_CUR, SEEK_END };

	fl->l_type   = lock_types[rnd_modulo_u32(ARRAY_SIZE(lock_types))];
	fl->l_whence = whence_vals[rnd_modulo_u32(ARRAY_SIZE(whence_vals))];
	fl->l_start  = RAND_RANGE(0LL, 1LL << 30);	/* [0, 1 GB] */
	fl->l_len    = RAND_RANGE(0LL, 64LL << 20);	/* [0, 64 MB] */
	fl->l_pid    = 0;
}

#ifdef HAVE_LK64
static void build_flock64(struct flock64 *fl)
{
	static const int lock_types[]  = { F_RDLCK, F_WRLCK, F_UNLCK };
	static const int whence_vals[] = { SEEK_SET, SEEK_CUR, SEEK_END };

	fl->l_type   = lock_types[rnd_modulo_u32(ARRAY_SIZE(lock_types))];
	fl->l_whence = whence_vals[rnd_modulo_u32(ARRAY_SIZE(whence_vals))];
	fl->l_start  = RAND_RANGE(0LL, 1LL << 30);
	fl->l_len    = RAND_RANGE(0LL, 64LL << 20);
	fl->l_pid    = 0;
}
#endif

static void fcntl_lease(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case F_SETLEASE: {
		int lease_types[] = { F_RDLCK, F_WRLCK, F_UNLCK };
		rec->a3 = lease_types[rnd_modulo_u32(3)];
		break;
	}

	case F_GETLEASE: {
		int fd;

		/*
		 * Half the time, target a fd we've previously F_SETLEASE'd on
		 * so the kernel actually has lease state to return.  Cross-
		 * child kernel state is real, so this is a hint to the picker
		 * — F_UNLCK is still a valid outcome if a sibling cleared it.
		 */
		if (rnd_modulo_u32(2) == 0 && lease_ring_pick(&fd))
			rec->a1 = (unsigned long) fd;
		break;
	}
	}
}

static void fcntl_lock(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case F_GETLK:
	case F_OFD_GETLK:
		avoid_shared_buffer_inout(&rec->a3, sizeof(struct flock));
		break;
	case F_SETLK:
	case F_SETLKW:
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
	case F_CANCELLK: {
		struct flock *fl = get_writable_struct(sizeof(struct flock));
		int fd;
		if (fl) {
			build_flock(fl);
			rec->a3 = (unsigned long) fl;
		}
		/*
		 * Half the time, target a fd a prior SETLK has run on so
		 * posix_lock_inode() actually has lock state to walk and
		 * range-compare against instead of an empty fl_list.
		 */
		if (rnd_modulo_u32(2) == 0 && setlk_ring_pick(&fd))
			rec->a1 = (unsigned long) fd;
		break;
	}
#ifdef HAVE_LK64
	case F_GETLK64:
		avoid_shared_buffer_inout(&rec->a3, sizeof(struct flock64));
		break;
	case F_SETLK64:
	case F_SETLKW64: {
		struct flock64 *fl = get_writable_struct(sizeof(struct flock64));
		int fd;
		if (fl) {
			build_flock64(fl);
			rec->a3 = (unsigned long) fl;
		}
		if (rnd_modulo_u32(2) == 0 && setlk_ring_pick(&fd))
			rec->a1 = (unsigned long) fd;
		break;
	}
#endif
	}
}

static void fcntl_owner(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case F_SETOWN:
		rec->a3 = (unsigned long) get_pid();
		break;

	/* arg = struct f_owner_ex *) */
	case F_GETOWN_EX:
		avoid_shared_buffer_out(&rec->a3, sizeof(struct f_owner_ex));
		break;
	case F_SETOWN_EX: {
		struct f_owner_ex *ex = get_writable_struct(sizeof(*ex));
		static const int owner_types[] = {
			F_OWNER_TID, F_OWNER_PID, F_OWNER_PGRP,
		};
		if (ex) {
			ex->type = owner_types[rnd_modulo_u32(ARRAY_SIZE(owner_types))];
			ex->pid  = get_pid();
			rec->a3 = (unsigned long) ex;
		}
		break;
	}

	case F_SETSIG:
		rec->a3 = (unsigned long) rand32();
		if (rec->a3 == SIGINT)
			rec->a3 = 0; /* restore default (SIGIO) */
		break;
	}
}

static void fcntl_rw_hint(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case F_GET_RW_HINT:
	case F_GET_FILE_RW_HINT:
		avoid_shared_buffer_out(&rec->a3, sizeof(uint64_t));
		break;
	case F_SET_RW_HINT:
	case F_SET_FILE_RW_HINT: {
		uint64_t *hint = get_writable_struct(sizeof(*hint));
		if (hint) {
			*hint = rnd_modulo_u32(6);	/* RWH_WRITE_LIFE_* in [0, 5] */
			rec->a3 = (unsigned long) hint;
		}
		break;
	}
	}
}

static void fcntl_seals(struct syscallrecord *rec)
{
	static const unsigned long seal_bits[] = {
		F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_GROW,
		F_SEAL_WRITE, F_SEAL_FUTURE_WRITE, F_SEAL_EXEC,
	};
	rec->a3 = set_rand_bitmask(ARRAY_SIZE(seal_bits), seal_bits);
}

static void fcntl_notify(struct syscallrecord *rec)
{
	rec->a3 = 0L;
	if (RAND_BOOL())
		rec->a3 |= DN_ACCESS;
	if (RAND_BOOL())
		rec->a3 |= DN_MODIFY;
	if (RAND_BOOL())
		rec->a3 |= DN_CREATE;
	if (RAND_BOOL())
		rec->a3 |= DN_DELETE;
	if (RAND_BOOL())
		rec->a3 |= DN_RENAME;
	if (RAND_BOOL())
		rec->a3 |= DN_ATTRIB;
}

static void sanitise_fcntl(struct syscallrecord *rec)
{
	rec->a2 = pick_fcntl_cmd();

	switch (rec->a2) {
	/* arg = fd */
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
		rec->a3 = (unsigned long) get_random_fd();
		break;

	case F_SETLEASE:
	case F_GETLEASE:
		fcntl_lease(rec);
		break;

	/* no arg */
	case F_GETFD:
	case F_GETFL:
	case F_GETOWN:
	case F_GETSIG:
	case F_GETPIPE_SZ:
	case F_GETOWNER_UIDS:
		break;

	case F_SETFD:	/* arg = flags */
		rec->a3 = (unsigned int) rand32();
		break;

	case F_SETFL:
		rec->a3 = (unsigned long) random_fcntl_setfl_flags();
		break;

	/* arg = (struct flock *) */
	case F_GETLK:
	case F_OFD_GETLK:
	case F_SETLK:
	case F_SETLKW:
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
	case F_CANCELLK:
#ifdef HAVE_LK64
	case F_GETLK64:
	case F_SETLK64:
	case F_SETLKW64:
#endif
		fcntl_lock(rec);
		break;

	case F_SETOWN:
	/* arg = struct f_owner_ex *) */
	case F_GETOWN_EX:
	case F_SETOWN_EX:
	case F_SETSIG:
		fcntl_owner(rec);
		break;

	/* arg = (uint64_t *) */
	case F_GET_RW_HINT:
	case F_GET_FILE_RW_HINT:
	case F_SET_RW_HINT:
	case F_SET_FILE_RW_HINT:
		fcntl_rw_hint(rec);
		break;

	case F_ADD_SEALS:
		fcntl_seals(rec);
		break;

	/* arg = (int *) */
	case F_DUPFD_QUERY:
	case F_CREATED_QUERY:
		avoid_shared_buffer_out(&rec->a3, sizeof(int));
		break;

	case F_NOTIFY:
		fcntl_notify(rec);
		break;

	case F_SETPIPE_SZ:
		rec->a3 = rand32();
		break;

	default:
		break;
	}

	/*
	 * Per-cmd rec->rettype publication for the dispatcher-level
	 * reject_corrupt_retfd / rzs gates.  The default for an op-
	 * multiplexed syscall is to leave rec->rettype at the entry's
	 * RET_NONE (set by generate_syscall_args() before sanitise runs)
	 * so neither gate fires -- fcntl cmds whose retval is not a fd
	 * and not constrained to 0 (F_GETOWN returns a pid, F_GETFD a
	 * close-on-exec bit, F_GETFL a flags word, F_GETPIPE_SZ a byte
	 * count, F_GETLEASE a 3-valued enum, F_GET_SEALS a bitmask,
	 * F_SETPIPE_SZ the new pipe size, ...) carry their own .post
	 * oracle for the value range and would mis-fire the rzs gate as
	 * a "non-zero RET_ZERO_SUCCESS return" -- a false positive that
	 * coerces a perfectly valid pid/flags/bitmask back to EINVAL.
	 *
	 * Only publish RET_FD for the two cmds that actually return a
	 * fd, and RET_ZERO_SUCCESS for the enumerated set whose kernel-
	 * side handler returns 0 on success (the F_SET* family plus the
	 * value-result F_GET ops that write their answer into the user
	 * buffer at *arg).  Anything else -- F_SETPIPE_SZ, F_GETFD,
	 * F_GETFL, F_GETOWN, F_GETSIG, F_GETLEASE, F_GETPIPE_SZ,
	 * F_GET_SEALS, F_DUPFD_QUERY, F_CREATED_QUERY, F_GETDELEG -- is
	 * left at RET_NONE so the dispatcher gates skip it; per-cmd
	 * post_fcntl already has bespoke value-range checks for the ops
	 * whose return shape is well-defined enough to bound.
	 */
	switch (rec->a2) {
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
		rec->rettype = RET_FD;
		break;
	case F_SETFD:
	case F_SETFL:
	case F_SETLK:
	case F_SETLKW:
#ifdef HAVE_LK64
	case F_SETLK64:
	case F_SETLKW64:
#endif
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
	case F_SETOWN:
	case F_SETOWN_EX:
	case F_SETSIG:
	case F_SETLEASE:
	case F_NOTIFY:
	case F_ADD_SEALS:
	case F_SET_RW_HINT:
	case F_SET_FILE_RW_HINT:
	case F_CANCELLK:
	case F_SETDELEG:
	/* F_GET* ops below return 0 on success and write their result into
	 * the user buffer at *arg, so the kernel-side rettype IS zero-success. */
	case F_GETLK:
#ifdef HAVE_LK64
	case F_GETLK64:
#endif
	case F_OFD_GETLK:
	case F_GETOWN_EX:
	case F_GETOWNER_UIDS:
	case F_GET_RW_HINT:
	case F_GET_FILE_RW_HINT:
		rec->rettype = RET_ZERO_SUCCESS;
		break;
	default:
		/* Leave rec->rettype at entry->rettype (RET_NONE) for value-
		 * returning ops: F_GETFD (cloexec bit), F_GETFL (flags),
		 * F_GETOWN (pid, possibly negative for pgrp), F_GETSIG, F_GETLEASE,
		 * F_GETPIPE_SZ, F_GET_SEALS, F_DUPFD_QUERY, F_CREATED_QUERY,
		 * F_SETPIPE_SZ (new pipe size), F_GETDELEG, ... */
		break;
	}
}

static unsigned long fcntl_flags[] = {
	F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_GETLK, F_SETLK,
	F_SETLKW, F_GETOWN, F_SETOWN, F_GETOWN_EX, F_SETOWN_EX, F_GETSIG, F_SETSIG, F_GETLEASE,
	F_SETLEASE, F_NOTIFY, F_SETPIPE_SZ, F_GETPIPE_SZ, F_GETOWNER_UIDS,
#ifdef HAVE_LK64
	F_GETLK64, F_SETLK64, F_SETLKW64,
#endif
	F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW,
	F_DUPFD_QUERY, F_CREATED_QUERY, F_CANCELLK,
	F_ADD_SEALS, F_GET_SEALS,
	F_GET_RW_HINT, F_SET_RW_HINT, F_GET_FILE_RW_HINT, F_SET_FILE_RW_HINT,
	F_GETDELEG, F_SETDELEG,
};

static void post_fcntl_dupfd(unsigned long retval)
{
	if ((long) retval < 0 || (long) retval >= (1 << 20))
		return;
	__atomic_add_fetch(&shm->stats.fd.duped, 1, __ATOMIC_RELAXED);
}

static void post_fcntl_getfd(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns the FD_CLOEXEC bit only — value 0 or 1.
	 * Anything else is a torn read of fdtable->close_on_exec or a
	 * sign-extension shape leaking upper bits into the success path.
	 */
	if (retval > 1UL) {
		output(0, "post_fcntl: F_GETFD rejected retval 0x%lx outside [0, 1]\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_fcntl_getfl(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns file->f_flags via an unsigned int — the
	 * upper 32 bits of the syscall return must be zero on success.
	 * Anything above 0xFFFFFFFF is a -errno leak through the return
	 * path or a wider read of the file_struct field.
	 */
	if (retval > 0xFFFFFFFFUL) {
		output(0, "post_fcntl: F_GETFL rejected retval 0x%lx with bits above 32\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_fcntl_getlease(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns one of F_RDLCK (0), F_WRLCK (1) or
	 * F_UNLCK (2) — the fl_type field on the active file_lease.
	 * A larger value means a torn read, dispatch into the wrong
	 * getter, or a clobbered fl_type.
	 */
	if (retval > 2UL) {
		output(0, "post_fcntl: F_GETLEASE rejected retval 0x%lx outside {F_RDLCK, F_WRLCK, F_UNLCK}\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_fcntl_setlk(unsigned long a1, unsigned long a3)
{
	/*
	 * Record so a sibling SETLK can target this fd's fl_list.
	 * F_UNLCK and F_CANCELLK remove the lock state that sibling
	 * SETLK calls would otherwise target, so do not register them
	 * as interesting lock holders.
	 */
	struct flock *fl = (struct flock *) a3;
	if (fl && fl->l_type != F_UNLCK)
		setlk_ring_record((int) a1);
}

#ifdef HAVE_LK64
static void post_fcntl_setlk64(unsigned long a1, unsigned long a3)
{
	struct flock64 *fl = (struct flock64 *) a3;
	if (fl && fl->l_type != F_UNLCK)
		setlk_ring_record((int) a1);
}
#endif

static void post_fcntl_getsig(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns 0 (default SIGIO behaviour) or a signal
	 * number bounded by _NSIG (64 on Linux). A larger value means
	 * fown->signum was clobbered or the wrong fasync field was read.
	 */
	if (retval > 64UL) {
		output(0, "post_fcntl: F_GETSIG rejected retval 0x%lx outside [0, _NSIG=64]\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_fcntl_getpipesz(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns pipe->max_usage * PAGE_SIZE — a positive
	 * int bounded by the pipe-max-size sysctl, which itself caps to
	 * fit in a signed int. The failure path is filtered above by
	 * the (long)<0 guard, so success retvals must fit in INT_MAX.
	 */
	if (retval > 0x7FFFFFFFUL) {
		output(0, "post_fcntl: F_GETPIPE_SZ rejected retval 0x%lx outside [0, INT_MAX]\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_fcntl_getseals(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns the shmem inode's ->seals field — a small
	 * bitmask of F_SEAL_* flags. Even with future additions the
	 * field stays well under a byte; anything above 0xFF is a torn
	 * read or a dispatch into the wrong getter.
	 */
	if (retval > 0xFFUL) {
		output(0, "post_fcntl: F_GET_SEALS rejected retval 0x%lx outside seal bitmask\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_fcntl_ofdgetlk(struct syscallrecord *rec, unsigned long retval)
{
	/*
	 * Kernel ABI: returns 0 on success — the lock info is written
	 * into the caller's struct flock. Any non-zero non-error retval
	 * is a dispatch / sign-extension shape, not a real ABI value.
	 */
	if (retval != 0UL) {
		output(0, "post_fcntl: F_OFD_GETLK rejected retval 0x%lx (must be 0 on success)\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

static void post_fcntl_setfl(unsigned long a1, unsigned long a3)
{
	long got;

	/*
	 * Oracle: flags we just set must survive a round-trip through
	 * F_GETFL.  A missing bit means the kernel silently dropped a
	 * status flag — a sign of fd-table or file-struct corruption.
	 */
	got = fcntl((int) a1, F_GETFL);
	if (got >= 0 && (got & a3) != a3) {
		output(0, "fd oracle: fcntl(%lu, F_SETFL, 0x%lx) "
		       "but F_GETFL=0x%lx (missing bits: 0x%lx)\n",
		       a1, a3, (unsigned long) got,
		       a3 & ~(unsigned long) got);
		__atomic_add_fetch(&shm->stats.oracle.fd_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

static void post_fcntl(struct syscallrecord *rec)
{
	unsigned long retval, a2, a1, a3;

	if ((long) rec->retval < 0)
		return;

	/*
	 * Read cmd/args via the arg_shadow accessor: the post-oracle
	 * dispatches on the cmd the kernel actually saw and validates
	 * retval against bounds derived from that cmd.  Reading live
	 * rec->aN would let a sibling stomp between syscall return and
	 * this handler swing the switch into a different case and
	 * mis-attribute the retval check against the wrong cmd's bound.
	 * arg_snapshot_mask on syscall_fcntl opts a1/a2/a3 into the
	 * shadow; get_arg_snapshot() returns the dispatch-time value and
	 * bumps arg_shadow_stomp from inside the accessor on mismatch.
	 */
	retval = rec->retval;
	a2 = get_arg_snapshot(rec, 2);
	a1 = get_arg_snapshot(rec, 1);
	a3 = get_arg_snapshot(rec, 3);

	switch (a2) {
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
		post_fcntl_dupfd(retval);
		break;

	case F_GETFD:
		post_fcntl_getfd(rec, retval);
		break;

	case F_GETFL:
		post_fcntl_getfl(rec, retval);
		break;

	case F_GETLEASE:
		post_fcntl_getlease(rec, retval);
		break;

	case F_SETLEASE:
		/* Record so a sibling F_GETLEASE can target this fd. */
		lease_ring_record((int) a1, (int) a3);
		break;

	case F_SETLK:
	case F_SETLKW:
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
		post_fcntl_setlk(a1, a3);
		break;
#ifdef HAVE_LK64
	case F_SETLK64:
	case F_SETLKW64:
		post_fcntl_setlk64(a1, a3);
		break;
#endif

	case F_GETSIG:
		post_fcntl_getsig(rec, retval);
		break;

	case F_GETPIPE_SZ:
		post_fcntl_getpipesz(rec, retval);
		break;

	case F_GET_SEALS:
		post_fcntl_getseals(rec, retval);
		break;

	case F_OFD_GETLK:
		post_fcntl_ofdgetlk(rec, retval);
		break;

	case F_SETFL:
		post_fcntl_setfl(a1, a3);
		break;
	}
}

struct syscallentry syscall_fcntl = {
	.name = "fcntl",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_OP, [2] = ARG_STRUCT_PTR_INOUT },
	.argname = { [0] = "fd", [1] = "cmd", [2] = "arg" },
	.arg_params[1].list = ARGLIST(fcntl_flags),
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_fcntl,
	.post = post_fcntl,
	/* a1/a2/a3 (fd/cmd/arg) all feed post_fcntl's oracle: the cmd
	 * selects the switch arm, the fd is logged on F_SETFL anomalies
	 * and recorded into the lease/setlk rings, and arg carries the
	 * lease type / SETFL flag set the oracle round-trips against.
	 * Shadow all three so a sibling stomp between dispatch and post
	 * cannot redirect the oracle to a different cmd or a fabricated
	 * fd/arg value -- mismatch bumps arg_shadow_stomp from inside
	 * get_arg_snapshot() and the handler still sees the dispatch
	 * values the kernel actually executed against. */
	.arg_snapshot_mask = (1u << 0) | (1u << 1) | (1u << 2),
};
