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
#include <sys/syscall.h>
#include <string.h>
#include <time.h>

#include "child.h"
#include "syscall-gate.h"
#include "childops-util.h"
#include "pids.h"
#include "jitter.h"
#include "name-pool.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/keyctl.h"
/* Wall-clock ceiling for the inner cycle loop.  Same band as
 * madvise_cycler / pidfd_storm so dump_stats keeps ticking and SIGALRM
 * stall detection still has headroom. */
#define BUDGET_NS	200000000L	/* 200 ms */

/* Hard cap on inner cycle iterations.  Each iteration is one syscall
 * (sometimes two -- add_key plus a tracking-ring update), all cheap. */
#define MAX_ITERATIONS	64

/* "user" payload bytes per add_key.  Small and fixed -- the point is to
 * drive the user_key_payload slab path, not to vary payload size. */
#define KEYRING_PAYLOAD_BYTES	16

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
	slot = rnd_modulo_u32(LIVE_KEYS_RING);
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
	return ring[picks[rnd_modulo_u32(count)]];
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

/* OP_ADD_KEY: produce a fresh serial against the picked anchor and
 * record it in the live ring.  Per-iteration unique description so
 * add_key creates a new key rather than updating an existing one --
 * key_update is a narrower path and we want allocation pressure here.
 * -EDQUOT / -EPERM / -ENOSYS are expected and counted; the call still
 * exercised the per-op validator. */
static void keyring_spam_iter_add_key(int32_t *live,
				      const unsigned char *payload,
				      unsigned int iter, int anchor)
{
	char desc[64];
	long rc;
	size_t got = 0;

	/* Minority arm: replay a previously-recorded description (possibly
	 * mutated) so this add_key collides with an earlier one in
	 * keyring_search_iterator / __key_link_check_live_key paths -- those
	 * only light up when two descriptions share dcache slots, which the
	 * fresh "<pid>-<iter>" form almost never does.  Fall through to the
	 * fresh path (and record it) when the pool is empty. */
	if (ONE_IN(8))
		got = name_pool_draw_mutated(NAME_KIND_KEY_DESC,
					     desc, sizeof(desc));

	if (got > 0) {
		if (got >= sizeof(desc))
			got = sizeof(desc) - 1;
		desc[got] = '\0';
	} else {
		snprintf(desc, sizeof(desc),
			 "trinity-keyring-spam-%u-%u",
			 (unsigned int) mypid(), iter);
		name_pool_record(NAME_KIND_KEY_DESC, desc, strlen(desc));
	}

	rc = trinity_raw_syscall(__NR_add_key, "user", desc,
		     payload, (size_t) KEYRING_PAYLOAD_BYTES,
		     (unsigned long) anchor);
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.keyring_spam.failed,
				   1, __ATOMIC_RELAXED);
	} else {
		ring_insert(live, (int32_t) rc);
	}
}

/* OP_READ: pull payload bytes out of a live serial via KEYCTL_READ.
 * Skips when the ring is empty.  RAND_NEGATIVE_OR(KEYCTL_READ) sometimes
 * flips the opcode negative to exercise the keyctl op dispatcher's
 * out-of-range path; the kernel returns -ENOTTY/-EOPNOTSUPP there and
 * we count it as expected. */
static void keyring_spam_iter_read(int32_t *live)
{
	unsigned char buf[64];
	int32_t serial;
	long rc;

	serial = ring_pick(live);
	if (serial == 0)
		return;
	rc = trinity_raw_syscall(__NR_keyctl,
		     (unsigned long) RAND_NEGATIVE_OR(KEYCTL_READ),
		     (unsigned long) serial,
		     (unsigned long) buf,
		     (unsigned long) sizeof(buf), 0UL);
	if (rc < 0)
		__atomic_add_fetch(&shm->stats.keyring_spam.failed,
				   1, __ATOMIC_RELAXED);
}

/* OP_DESCRIBE: KEYCTL_DESCRIBE drives the type->describe path with a
 * generous 128-byte buffer (the kernel returns "type;uid;gid;perm;desc"
 * truncated to fit).  Skips when the ring is empty. */
static void keyring_spam_iter_describe(int32_t *live)
{
	char buf[128];
	int32_t serial;
	long rc;

	serial = ring_pick(live);
	if (serial == 0)
		return;
	rc = trinity_raw_syscall(__NR_keyctl, (unsigned long) KEYCTL_DESCRIBE,
		     (unsigned long) serial,
		     (unsigned long) buf,
		     (unsigned long) sizeof(buf), 0UL);
	if (rc < 0)
		__atomic_add_fetch(&shm->stats.keyring_spam.failed,
				   1, __ATOMIC_RELAXED);
}

/* OP_REVOKE: mark a serial revoked.  Deliberately kept in the ring
 * afterwards -- revoked keys are still queryable as -EKEYREVOKED, so
 * subsequent READ/DESCRIBE iterations exercise the revoked-key validate
 * path. */
static void keyring_spam_iter_revoke(int32_t *live)
{
	int32_t serial;
	long rc;

	serial = ring_pick(live);
	if (serial == 0)
		return;
	rc = trinity_raw_syscall(__NR_keyctl, (unsigned long) KEYCTL_REVOKE,
		     (unsigned long) serial, 0UL, 0UL, 0UL);
	if (rc < 0)
		__atomic_add_fetch(&shm->stats.keyring_spam.failed,
				   1, __ATOMIC_RELAXED);
}

/* OP_INVALIDATE: schedule the key for GC.  Unlike revoke, an
 * invalidated serial becomes unusable immediately, so on success we
 * drop it from the ring -- otherwise subsequent iterations would burn
 * budget on guaranteed -ENOKEY follow-ups. */
static void keyring_spam_iter_invalidate(int32_t *live)
{
	int32_t serial;
	long rc;

	serial = ring_pick(live);
	if (serial == 0)
		return;
	rc = trinity_raw_syscall(__NR_keyctl,
		     (unsigned long) KEYCTL_INVALIDATE,
		     (unsigned long) serial, 0UL, 0UL, 0UL);
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.keyring_spam.failed,
				   1, __ATOMIC_RELAXED);
	} else {
		ring_drop(live, serial);
	}
}

/* OP_UNLINK: detach a serial from the picked anchor keyring.  We do
 * not track per-serial anchor, so the anchor we pass here may not be
 * the key's parent -- the kernel returns -ENOENT in that case, which
 * still exercises keyring_search_aux on the wrong keyring (a useful
 * negative path).  Successful unlinks drop the serial from the ring. */
static void keyring_spam_iter_unlink(int32_t *live, int anchor)
{
	int32_t serial;
	long rc;

	serial = ring_pick(live);
	if (serial == 0)
		return;
	rc = trinity_raw_syscall(__NR_keyctl, (unsigned long) KEYCTL_UNLINK,
		     (unsigned long) serial,
		     (unsigned long) anchor, 0UL, 0UL);
	if (rc < 0) {
		__atomic_add_fetch(&shm->stats.keyring_spam.failed,
				   1, __ATOMIC_RELAXED);
	} else {
		ring_drop(live, serial);
	}
}

bool keyring_spam(struct childdata *child)
{
	int32_t live[LIVE_KEYS_RING];
	struct timespec start;
	unsigned int iter;
	unsigned int iters = JITTER_RANGE(MAX_ITERATIONS);
	unsigned char payload[KEYRING_PAYLOAD_BYTES];

	__atomic_add_fetch(&shm->stats.keyring_spam.runs, 1, __ATOMIC_RELAXED);

	memset(live, 0, sizeof(live));
	memset(payload, 0xa5, sizeof(payload));

	clock_gettime(CLOCK_MONOTONIC, &start);

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op_type = child->op_type;
	const bool valid_op = ((int) op_type >= 0 && op_type < NR_CHILD_OP_TYPES);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op_type],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op_type],
				   1, __ATOMIC_RELAXED);
	}

	for (iter = 0; iter < iters; iter++) {
		enum keyring_op op;
		int anchor;

		op = (enum keyring_op) rnd_modulo_u32(NR_KEYRING_OPS);
		anchor = anchor_keyrings[rnd_modulo_u32(ARRAY_SIZE(anchor_keyrings))];

		__atomic_add_fetch(&shm->stats.keyring_spam.calls,
				   1, __ATOMIC_RELAXED);

		switch (op) {
		case OP_ADD_KEY:
			keyring_spam_iter_add_key(live, payload, iter, anchor);
			break;

		case OP_READ:
			keyring_spam_iter_read(live);
			break;

		case OP_DESCRIBE:
			keyring_spam_iter_describe(live);
			break;

		case OP_REVOKE:
			keyring_spam_iter_revoke(live);
			break;

		case OP_INVALIDATE:
			keyring_spam_iter_invalidate(live);
			break;

		case OP_UNLINK:
			keyring_spam_iter_unlink(live, anchor);
			break;

		case NR_KEYRING_OPS:
			break;
		}

		if (budget_elapsed_ns(&start, BUDGET_NS))
			break;
	}

	return true;
}
