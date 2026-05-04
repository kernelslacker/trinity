/*
 * keyring_spam - sustained add_key/keyctl burst against the per-process
 * and per-thread keyrings.
 *
 * Trinity's random_syscall path issues add_key(2) and keyctl(2) with
 * arbitrary args, but the keyring subsystem is small, low-traffic, and
 * has its own slab caches (key_jar, user_key_payload) plus a refcount
 * lifecycle (key_get / key_put / RCU teardown of struct user_key_payload
 * on user_revoke()) that rarely sees sustained valid-args coverage.
 * Most random_syscall keyctl calls fault out at the per-op argument
 * validator (-EINVAL / -EFAULT / -ENOKEY) before reaching the per-key
 * handler.  keyring_spam closes that gap by:
 *
 *   - Anchoring on the per-process and per-thread keyrings
 *     (KEY_SPEC_PROCESS_KEYRING / KEY_SPEC_THREAD_KEYRING).  These are
 *     two separate refcount/slab paths -- the per-process keyring is
 *     installed lazily on first use and lives until the process exits;
 *     the per-thread keyring is installed lazily per task_struct and
 *     is reaped on thread exit.  Hammering both drives install_*_keyring
 *     paths plus the keyring refcount machinery sibling-style.
 *   - Picking one of {add_key, KEYCTL_READ, KEYCTL_DESCRIBE,
 *     KEYCTL_REVOKE, KEYCTL_INVALIDATE, KEYCTL_UNLINK} per iteration
 *     and applying it to either a freshly-added key or one of the
 *     recently-added serials this op is tracking.  The serial ring is
 *     small (LIVE_KEYS_RING) so KEYCTL_REVOKE / KEYCTL_INVALIDATE land
 *     on keys with a recent allocation history rather than always
 *     hitting an old/cold key.
 *   - Using "user" key payloads.  user is the safest payload type: it
 *     accepts arbitrary bytes, has no auth/instantiate dance (unlike
 *     the asymmetric or trusted types), is unconditionally compiled in,
 *     and has the most-exercised serial-number lifecycle.  Other types
 *     (logon, keyring as a payload type, big_key) drive different slab
 *     paths but require either privilege (logon -- CAP_SYS_ADMIN to
 *     read) or extra setup that pollutes the inner loop.
 *
 * KEYCTL_INVALIDATE is a 3.5+ syscall; some build hosts' libc/headers
 * predate it.  Mirror the value here so we can compile cleanly without
 * pulling extra namespace.
 *
 * Per-iteration failures (-EDQUOT under kernel.keys.maxkeys pressure,
 * -EKEYREVOKED on a key we already revoked, -ENOKEY on a serial whose
 * unlink raced ahead of the read) are expected and counted.  The call
 * itself still exercised the per-op validator and refcount path, which
 * is the fuzz-relevant entry point.
 *
 * No private allocation: this op is keyring-only -- no mmap, no
 * get_map() draw, no FDs to close.  The per-process and per-thread
 * keyrings persist beyond this op's return and are reaped by the
 * kernel on process/thread exit, so there is nothing to tear down.
 *
 * Self-bounding:
 *   - MAX_ITERATIONS caps inner-loop iterations.
 *   - BUDGET_NS (200 ms) sits in the same band as the other lifecycle/
 *     refcount thrash ops (iouring_flood, close_racer, madvise_cycler).
 *   - alarm(1) is armed by child.c around every non-syscall op, so a
 *     wedged keyctl path here still trips the SIGALRM stall detector.
 */

#include <errno.h>
#include <linux/keyctl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/* KEYCTL_INVALIDATE was added in 3.5; older libc/header builds may
 * lack it even though the running kernel supports it.  Define the
 * canonical value locally so the call still compiles. */
#ifndef KEYCTL_INVALIDATE
#define KEYCTL_INVALIDATE	21
#endif

/* Wall-clock ceiling for the inner cycle loop.  Same band as
 * madvise_cycler / pidfd_storm so dump_stats keeps ticking and SIGALRM
 * stall detection still has headroom. */
#define BUDGET_NS	200000000L	/* 200 ms */

/* Hard cap on inner cycle iterations.  Each iteration is one syscall
 * (sometimes two -- add_key plus a tracking-ring update), all cheap. */
#define MAX_ITERATIONS	64

/* Recently-added key serials this invocation has produced.  Small ring:
 * the point is to pin REVOKE / INVALIDATE / UNLINK / READ / DESCRIBE on
 * keys with a recent allocation history, not to maintain a long-lived
 * pool.  An entry of 0 means "empty slot". */
#define LIVE_KEYS_RING	8

/* Curated per-key op set.  add_key is the producer; the rest are
 * consumers / lifecycle terminators.  KEYCTL_READ and KEYCTL_DESCRIBE
 * exercise the type->read / type->describe paths; REVOKE and
 * INVALIDATE drive the refcount/RCU teardown of user_key_payload;
 * UNLINK detaches from the anchor keyring (gc_works progress). */
enum keyring_op {
	OP_ADD_KEY = 0,
	OP_READ,
	OP_DESCRIBE,
	OP_REVOKE,
	OP_INVALIDATE,
	OP_UNLINK,
	NR_KEYRING_OPS,
};

/* Anchor keyrings.  Both are per-task lazily-installed keyrings backed
 * by separate install paths (install_process_keyring_to_cred /
 * install_thread_keyring_to_cred).  Picking randomly between the two
 * across iterations spreads coverage across both install paths and
 * both refcount/lifetime regimes. */
static const int anchor_keyrings[] = {
	KEY_SPEC_PROCESS_KEYRING,
	KEY_SPEC_THREAD_KEYRING,
};

static bool budget_elapsed(const struct timespec *start)
{
	struct timespec now;
	long elapsed_ns;

	clock_gettime(CLOCK_MONOTONIC, &now);
	elapsed_ns = (now.tv_sec  - start->tv_sec)  * 1000000000L
		   + (now.tv_nsec - start->tv_nsec);
	return elapsed_ns >= BUDGET_NS;
}

/* Insert a fresh serial into the ring.  Overwrites a random slot when
 * full -- old serials age out naturally as the loop runs.  serial==0
 * is reserved as "empty"; the kernel never returns 0 from add_key. */
static void ring_insert(int32_t *ring, int32_t serial)
{
	unsigned int i, slot;

	for (i = 0; i < LIVE_KEYS_RING; i++) {
		if (ring[i] == 0) {
			ring[i] = serial;
			return;
		}
	}
	slot = (unsigned int) rand() % LIVE_KEYS_RING;
	ring[slot] = serial;
}

/* Pick a live serial from the ring.  Returns 0 if the ring is empty,
 * which the caller treats as "skip this iteration's per-key op". */
static int32_t ring_pick(const int32_t *ring)
{
	unsigned int i, count = 0;
	unsigned int picks[LIVE_KEYS_RING];

	for (i = 0; i < LIVE_KEYS_RING; i++) {
		if (ring[i] != 0)
			picks[count++] = i;
	}
	if (count == 0)
		return 0;
	return ring[picks[(unsigned int) rand() % count]];
}

/* Drop a serial from the ring (post-revoke/invalidate/unlink).  No-op
 * if the serial isn't present -- another iteration may have already
 * overwritten this slot. */
static void ring_drop(int32_t *ring, int32_t serial)
{
	unsigned int i;

	for (i = 0; i < LIVE_KEYS_RING; i++) {
		if (ring[i] == serial) {
			ring[i] = 0;
			return;
		}
	}
}

bool keyring_spam(struct childdata *child)
{
	int32_t live[LIVE_KEYS_RING];
	struct timespec start;
	unsigned int iter;
	unsigned int iters = JITTER_RANGE(MAX_ITERATIONS);
	unsigned char payload[16];

	(void) child;

	__atomic_add_fetch(&shm->stats.keyring_spam_runs, 1, __ATOMIC_RELAXED);

	memset(live, 0, sizeof(live));
	memset(payload, 0xa5, sizeof(payload));

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (iter = 0; iter < iters; iter++) {
		enum keyring_op op;
		int anchor;
		long rc;
		int32_t serial;

		op = (enum keyring_op) ((unsigned int) rand() % NR_KEYRING_OPS);
		anchor = anchor_keyrings[(unsigned int) rand()
					 % ARRAY_SIZE(anchor_keyrings)];

		__atomic_add_fetch(&shm->stats.keyring_spam_calls,
				   1, __ATOMIC_RELAXED);

		switch (op) {
		case OP_ADD_KEY: {
			char desc[64];

			/* Per-iteration unique description so add_key creates
			 * a fresh serial rather than updating an existing
			 * key (the latter exercises a different, narrower
			 * path -- key_update -- and we want allocation
			 * pressure here). */
			snprintf(desc, sizeof(desc),
				 "trinity-keyring-spam-%u-%u",
				 (unsigned int) getpid(), iter);
			rc = syscall(__NR_add_key, "user", desc,
				     payload, (size_t) sizeof(payload),
				     (unsigned long) anchor);
			if (rc < 0) {
				__atomic_add_fetch(&shm->stats.keyring_spam_failed,
						   1, __ATOMIC_RELAXED);
				/* -EDQUOT (kernel.keys.maxkeys), -EPERM
				 * (LSM), -ENOSYS (CONFIG_KEYS=n) all
				 * expected; fall through. */
			} else {
				ring_insert(live, (int32_t) rc);
			}
			break;
		}

		case OP_READ: {
			unsigned char buf[64];

			serial = ring_pick(live);
			if (serial == 0)
				break;
			rc = syscall(__NR_keyctl,
				     (unsigned long) RAND_NEGATIVE_OR(KEYCTL_READ),
				     (unsigned long) serial,
				     (unsigned long) buf,
				     (unsigned long) sizeof(buf), 0UL);
			if (rc < 0)
				__atomic_add_fetch(&shm->stats.keyring_spam_failed,
						   1, __ATOMIC_RELAXED);
			break;
		}

		case OP_DESCRIBE: {
			char buf[128];

			serial = ring_pick(live);
			if (serial == 0)
				break;
			rc = syscall(__NR_keyctl, (unsigned long) KEYCTL_DESCRIBE,
				     (unsigned long) serial,
				     (unsigned long) buf,
				     (unsigned long) sizeof(buf), 0UL);
			if (rc < 0)
				__atomic_add_fetch(&shm->stats.keyring_spam_failed,
						   1, __ATOMIC_RELAXED);
			break;
		}

		case OP_REVOKE:
			serial = ring_pick(live);
			if (serial == 0)
				break;
			rc = syscall(__NR_keyctl, (unsigned long) KEYCTL_REVOKE,
				     (unsigned long) serial, 0UL, 0UL, 0UL);
			if (rc < 0)
				__atomic_add_fetch(&shm->stats.keyring_spam_failed,
						   1, __ATOMIC_RELAXED);
			/* Revoked keys are still readable as -EKEYREVOKED;
			 * keep them in the ring so subsequent READ/DESCRIBE
			 * exercise the revoked-key validate path. */
			break;

		case OP_INVALIDATE:
			serial = ring_pick(live);
			if (serial == 0)
				break;
			rc = syscall(__NR_keyctl,
				     (unsigned long) KEYCTL_INVALIDATE,
				     (unsigned long) serial, 0UL, 0UL, 0UL);
			if (rc < 0) {
				__atomic_add_fetch(&shm->stats.keyring_spam_failed,
						   1, __ATOMIC_RELAXED);
			} else {
				/* Invalidated keys are scheduled for GC and
				 * the serial becomes unusable; drop it so we
				 * don't waste budget on guaranteed-ENOKEY
				 * follow-ups. */
				ring_drop(live, serial);
			}
			break;

		case OP_UNLINK:
			serial = ring_pick(live);
			if (serial == 0)
				break;
			/* Unlink from the same anchor we added against where
			 * possible.  We don't track per-serial anchor here:
			 * try the picked anchor first, and if it wasn't the
			 * key's parent the kernel returns -ENOENT, which
			 * still exercises keyring_search_aux on the wrong
			 * keyring -- a useful negative path. */
			rc = syscall(__NR_keyctl, (unsigned long) KEYCTL_UNLINK,
				     (unsigned long) serial,
				     (unsigned long) anchor, 0UL, 0UL);
			if (rc < 0) {
				__atomic_add_fetch(&shm->stats.keyring_spam_failed,
						   1, __ATOMIC_RELAXED);
			} else {
				ring_drop(live, serial);
			}
			break;

		case NR_KEYRING_OPS:
			break;
		}

		if (budget_elapsed(&start))
			break;
	}

	return true;
}
