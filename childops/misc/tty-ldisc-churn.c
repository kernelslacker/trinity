/*
 * tty_ldisc_churn -- pty pair lifecycle + TIOCSETD line-discipline rotation.
 *
 * Five recently-disclosed crash families converge on the tty ldisc rebind
 * + receive-buf path: the kernel-side line discipline state machine is
 * torn down and replaced from underneath an in-flight receive while the
 * caller still holds a reference, and the various N_* implementations
 * differ enough that one ldisc's flush path overlaps another's setup
 * path:
 *
 *   1. n_tty_receive_buf_standard KMSAN.  Master end writes data, the
 *      slave's ldisc receive_buf walks an uninitialised flow-control
 *      bookkeeping cursor when the ldisc was just rebound under TIOCSETD
 *      and the prior owner left the bookkeeping in a half-set state.
 *
 *   2. n_tty_lookahead_flow_ctrl uninit.  Same shape; the lookahead path
 *      reads a buffered byte before n_tty's open() call has finished
 *      zeroing the per-tty struct n_tty_data.
 *
 *   3. do_con_write slab-OOB.  Console write path on a tty whose ldisc
 *      was just swapped to / from N_TTY walks past the end of the
 *      per-tty write buffer when the sizing fields didn't get re-init.
 *      Reachable via the same TIOCSETD churn -- console paths share the
 *      tty layer dispatch.
 *
 *   4 & 5. kbd_event UAF (input subsystem) x2.  The keyboard input path
 *      hands events to a tty whose ldisc has been freed mid-rebind.  The
 *      pure-pty surface here doesn't reach the input subsystem directly
 *      but the underlying ldisc lifecycle race is the same shape; running
 *      the rotation across all 25 N_* values exercises the swap path the
 *      kbd code rides on.
 *
 * Per-iteration shape:
 *   1. posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC) -- master end.
 *   2. grantpt() / unlockpt() / ptsname_r() -- standard pty handshake.
 *   3. open() of the slave path with O_RDWR | O_NOCTTY | O_NONBLOCK |
 *      O_CLOEXEC.  O_NONBLOCK keeps a misconfigured ldisc from blocking
 *      the iter on flow control after TIOCSETD.
 *   4. ioctl(slave, TIOCSETD, &ldisc) with ldisc randomly picked from
 *      the 24-entry table (0..24 minus N_GSM=21, which the test kernel
 *      kernel is built without -- '# CONFIG_N_GSM is not set').  Per-disc
 *      success counter feeds shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc
 *      so the operator can see which line disciplines are landing the
 *      most ldisc_set_ok hits.
 *   5. write() of <=256 random bytes at the master end so the slave's
 *      newly-rebound ldisc receive_buf path runs across attacker-shaped
 *      payload.
 *   6. read() at the slave end to drain whatever the ldisc passed
 *      through.  O_NONBLOCK means EAGAIN is the common return; that's
 *      counted as a non-success and the iter rolls.
 *   7. close(slave); close(master) -- close in that order so the master
 *      sees the slave hangup right before its own teardown, opening the
 *      teardown-vs-rebind race window.
 *
 * Self-bounding: every iteration owns its own pair of fds and closes
 * them before returning, so child.c's SIGALRM(1s) safety net always
 * reaches a clean state.  Rates are clamped via BUDGETED(... CHURN_ITERS_BASE)
 * -- adapt_budget is free to scale up on productive runs.
 *
 * Setup-failure latch: posix_openpt() failures are non-fatal at first
 * (transient ENOMEM / EMFILE) but a sustained streak gets tracked under
 * tty_ldisc_churn_setup_failed for visibility.  No "unsupported" latch:
 * /dev/ptmx is always present on a Linux fuzz target with devpts mounted,
 * and CONFIG_TTY=y is verified for the fleet kernel.
 *
 * DORMANT in dormant_op_disabled[].  Dave smoke-tests before fleet enable
 * per the dormant-cadence rule.  Some N_* values (N_HCI / N_X25 /
 * N_PROFIBUS_FDL) trigger module autoload at TIOCSETD time and have a
 * first-touch latency cost; the SIGALRM(1s) cap at child.c level catches
 * the wedge if an autoload completes too slowly.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<asm/ioctls.h>) || __has_include(<sys/ioctl.h>)

#include "jitter.h"
#include "random.h"

#include "kernel/fcntl.h"
/*
 * The test kernel config has '# CONFIG_N_GSM is not set' -- exclude
 * N_GSM (21) from the rotation table to keep iters from burning on a
 * known -EINVAL.  Every other slot in 0..24 stays in the rotation.  The
 * per-disc histogram in stats keeps slot 21 wired up at zero so dump
 * format stays stable when the gating flips.
 */
#define N_GSM_SLOT		21U
#define LDISC_TABLE_SLOTS	25U

#define CHURN_ITERS_BASE	4U
#define CHURN_IO_BUF_MAX	256U

/*
 * The 24 ldisc slots reachable on the test kernel, populated at
 * load time from the contiguous 0..24 range with N_GSM_SLOT skipped.
 * Keeping it const + module-scope means the picker is a single rand32 %
 * 24 + table lookup with no branch on the gated slot.
 */
static const unsigned char tty_ldisc_table[LDISC_TABLE_SLOTS - 1] = {
	0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
	10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
	20, /* 21 = N_GSM gated out */ 22, 23, 24,
};
#define NR_TTY_LDISCS		((unsigned int)(sizeof(tty_ldisc_table)))

/*
 * Open the master end + drive the standard grantpt/unlockpt/ptsname_r
 * handshake + open the slave end.  Returns 0 on success and stores the
 * two fds via out-pointers; -1 on any failure (caller bumps the
 * setup_failed counter and rolls).  The slave gets O_NONBLOCK so a
 * post-TIOCSETD I/O can't wedge the iter on flow control inside a
 * misconfigured line discipline.
 */
static int tty_open_pty_pair(int *out_master, int *out_slave)
{
	char pts_path[64];
	int master, slave;

	master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (master < 0)
		return -1;

	if (grantpt(master) < 0)
		goto fail_master;
	if (unlockpt(master) < 0)
		goto fail_master;
	if (ptsname_r(master, pts_path, sizeof(pts_path)) != 0)
		goto fail_master;

	slave = open(pts_path,
		     O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
	if (slave < 0)
		goto fail_master;

	*out_master = master;
	*out_slave = slave;
	return 0;

fail_master:
	close(master);
	return -1;
}

/*
 * Pick one ldisc number from the 24-slot table (N_GSM gated out at
 * compile time) and try to TIOCSETD the slave to it.  On accept, bump
 * the per-disc histogram so the operator can see which line disciplines
 * the kernel is letting through; on reject, bump ldisc_set_failed.
 *
 * Returns the picked ldisc number so the caller can use it for
 * downstream decisions (currently none -- the I/O path is ldisc-agnostic
 * and just feeds whatever the rebind landed on).
 */
static unsigned int tty_set_random_ldisc(int slave)
{
	unsigned int ldisc;
	int ldisc_int;

	ldisc = tty_ldisc_table[rnd_modulo_u32(NR_TTY_LDISCS)];
	ldisc_int = (int)ldisc;

	if (ioctl(slave, TIOCSETD, &ldisc_int) < 0) {
		__atomic_add_fetch(&shm->stats.tty_ldisc_churn_ldisc_set_failed,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.tty_ldisc_churn_ldisc_set_ok,
				   1, __ATOMIC_RELAXED);
		if (ldisc < LDISC_TABLE_SLOTS)
			__atomic_add_fetch(&shm->stats.tty_ldisc_churn_ldisc_set_ok_per_disc[ldisc],
					   1, __ATOMIC_RELAXED);
	}
	return ldisc;
}

/*
 * One full churn cycle: open a pty pair, swap the slave's ldisc, push
 * a random write down the master end so the slave's freshly-rebound
 * ldisc receive_buf runs, drain via a non-blocking read at the slave,
 * tear down.  Close slave first so the master sees a hangup right
 * before its own close -- that's the teardown-vs-rebind window the
 * upstream KMSAN/UAF reports landed in.
 */
static void tty_churn_cycle(void)
{
	unsigned char buf[CHURN_IO_BUF_MAX];
	unsigned int io_len;
	int master = -1, slave = -1;
	ssize_t n;

	if (tty_open_pty_pair(&master, &slave) < 0) {
		__atomic_add_fetch(&shm->stats.tty_ldisc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	(void)tty_set_random_ldisc(slave);

	io_len = 1U + rnd_modulo_u32(CHURN_IO_BUF_MAX);
	generate_rand_bytes(buf, io_len);

	/* Push at the master: drives the slave's ldisc receive_buf path
	 * on the freshly-rebound ldisc.  EAGAIN here is fine -- the
	 * rebind itself is the bug surface, not the byte count delivered. */
	n = write(master, buf, io_len);
	if (n > 0)
		__atomic_add_fetch(&shm->stats.tty_ldisc_churn_write_ok, 1,
				   __ATOMIC_RELAXED);

	/* Drain at the slave with O_NONBLOCK so a flow-stalled ldisc
	 * doesn't pin the iter past the SIGALRM cap. */
	n = read(slave, buf, sizeof(buf));
	if (n > 0)
		__atomic_add_fetch(&shm->stats.tty_ldisc_churn_read_ok, 1,
				   __ATOMIC_RELAXED);

	close(slave);
	close(master);
}

bool tty_ldisc_churn(struct childdata *child)
{
	unsigned int iters, i;

	__atomic_add_fetch(&shm->stats.tty_ldisc_churn_runs, 1,
			   __ATOMIC_RELAXED);

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	{
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES) {
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		}
	}

	iters = BUDGETED(CHILD_OP_TTY_LDISC_CHURN, JITTER_RANGE(CHURN_ITERS_BASE));
	for (i = 0; i < iters; i++)
		tty_churn_cycle();

	return true;
}

#else  /* no <sys/ioctl.h> (shouldn't happen on Linux, but stay safe) */

bool tty_ldisc_churn(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.tty_ldisc_churn_runs, 1,
			   __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.tty_ldisc_churn_setup_failed, 1,
			   __ATOMIC_RELAXED);
	return true;
}

#endif
