/*
 * SYSCALL_DEFINE2(capset, cap_user_header_t, header, const cap_user_data_t, data)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <linux/capability.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "deferred-free.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Pick a header.version with a distribution biased toward the kernel's
 * current preferred version (_3).  Random version values trip
 * cap_validate_magic() with -EINVAL immediately, so the per-task cap
 * install path (security_capset / __capable / ...) is never reached.
 *   ~80% _LINUX_CAPABILITY_VERSION_3 (current preferred).
 *   ~10% _LINUX_CAPABILITY_VERSION_2 (legacy 64-bit).
 *   ~5%  _LINUX_CAPABILITY_VERSION_1 (legacy 32-bit; 1 data datum).
 *   ~5%  bogus so the EINVAL gate stays exercised.
 */
static unsigned int pick_cap_version(void)
{
	unsigned int bucket = rnd_modulo_u32(100);

	if (bucket < 80)
		return _LINUX_CAPABILITY_VERSION_3;
	if (bucket < 90)
		return _LINUX_CAPABILITY_VERSION_2;
	if (bucket < 95)
		return _LINUX_CAPABILITY_VERSION_1;
	return rand32();
}

/*
 * Fill one cap_user_data_struct with a (effective, permitted, inheritable)
 * triple.  The kernel's cap_capset() enforces `effective subset of
 * permitted` and `inheritable subset of (permitted | bset)`; random
 * 32-bit masks satisfy the former roughly 1/2^32 of the time, so almost
 * every random sample short-circuits before security_capset() runs.
 * Distribution:
 *   ~70% legal: effective subset of permitted (we just mask
 *        effective &= permitted), inheritable left random (kernel
 *        already gates inheritable against bset separately).
 *   ~20% intentional violation: effective carries bits permitted does
 *        not, exercising the subset-check refusal path.
 *   ~10% pure-random masks for the long tail.
 */
static void fill_cap_datum(struct __user_cap_data_struct *d)
{
	unsigned int bucket = rnd_modulo_u32(10);
	__u32 permitted = rand32();
	__u32 effective = rand32();

	if (bucket < 7) {
		effective &= permitted;
	} else if (bucket < 9) {
		/* Force at least one effective bit outside permitted. */
		effective |= (~permitted) & rand32();
		if ((effective & ~permitted) == 0)
			effective ^= 1u;
	}
	/* else: leave both random. */

	d->effective = effective;
	d->permitted = permitted;
	d->inheritable = rand32();
}

/*
 * Snapshot of the two capset input args read by the post oracle, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign data buffer and forge a
 * clean compare against poisoned memory.
 */
#define CAPSET_POST_STATE_MAGIC	0x43415053UL	/* "CAPS" */
struct capset_post_state {
	unsigned long magic;
	unsigned long header;
	unsigned long data;
};

/*
 * Fill header with valid version and pid.
 * Fill data with random capability bitmasks.
 * v3 uses two __user_cap_data_struct entries (64-bit capability sets).
 */
static void sanitise_capset(struct syscallrecord *rec)
{
	struct __user_cap_header_struct *hdr;
	struct __user_cap_data_struct *data;
	struct capset_post_state *snap;
	unsigned int version;

	rec->post_state = 0;

	hdr = (struct __user_cap_header_struct *) get_writable_struct(sizeof(*hdr));
	if (!hdr)
		return;
	version = pick_cap_version();
	hdr->version = version;
	/*
	 * Target self / controlled children only.  The kernel's capset
	 * enforces hdr->pid == 0 or hdr->pid == current->pid -- any other
	 * pid returns -EPERM immediately, before any cap-mask validation
	 * runs.  get_pid() is biased toward live children but also returns
	 * the broader pool; restrict to {0, mypid()} to keep the per-task
	 * cap install path warm.
	 */
	hdr->pid = RAND_BOOL() ? 0 : mypid();
	rec->a1 = (unsigned long) hdr;
	/* Relocate + memcpy the curated header bytes (version, pid) onto a
	 * fresh pool page so the post-sanitise blanket address scrub no-ops on
	 * this slot.  Must precede the snap->header = rec->a1 capture below so
	 * the oracle snapshots the relocated pointer the kernel will see. */
	avoid_shared_buffer_inout(&rec->a1, sizeof(*hdr));

	/* v1 uses 1 data struct, v2/v3 use 2.  Bogus version sizes the
	 * buffer at 2 -- the kernel rejects with -EINVAL before reading
	 * past the header anyway. */
	if (version == _LINUX_CAPABILITY_VERSION_1) {
		data = (struct __user_cap_data_struct *) get_writable_struct(sizeof(*data));
		if (!data)
			return;
		fill_cap_datum(&data[0]);
	} else {
		data = (struct __user_cap_data_struct *) get_writable_struct(2 * sizeof(*data));
		if (!data)
			return;
		fill_cap_datum(&data[0]);
		fill_cap_datum(&data[1]);
	}
	rec->a2 = (unsigned long) data;
	/* Relocate + memcpy the curated cap_data bytes onto a fresh pool page
	 * so the post-sanitise blanket address scrub no-ops on this slot.
	 * Size mirrors the v1 vs v2/v3 alloc above.  Must precede the
	 * snap->data = rec->a2 capture below so the oracle snapshots the
	 * relocated pointer the kernel will see. */
	avoid_shared_buffer_inout(&rec->a2,
		(version == _LINUX_CAPABILITY_VERSION_1 ? 1 : 2) * sizeof(*data));

	/*
	 * Snapshot the two input args for the post oracle.  Without this
	 * the post handler reads rec->a1/a2 at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original
	 * buffer pointers, so the data[0].effective read would touch a
	 * foreign allocation.  post_state is private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic  = CAPSET_POST_STATE_MAGIC;
	snap->header = rec->a1;
	snap->data   = rec->a2;
	/*
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_capset() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	post_state_install(rec, snap);
}

/*
 * Oracle (drop-only): after capset() succeeds, inspect the new effective
 * cap set the syscall just installed.  If a chosen cap is NOT in the new
 * effective set, then a syscall gated on that cap MUST fail with EPERM.
 * If it succeeds anyway, the kernel's permission check disagrees with
 * its own stored cap state — exactly the silent-priv-escalation shape
 * that crash sanitisers miss.
 *
 * settimeofday(NULL, NULL) is the chosen probe: the kernel runs the
 * CAP_SYS_TIME LSM hook unconditionally before doing anything, so with
 * the cap it returns 0 and without it returns -EPERM.  No side effects
 * either way.  We invoke the syscall directly via syscall(2) rather than
 * the libc wrapper because glibc's settimeofday() compiles to a path
 * that, when tz is NULL, falls through to imul $0x3e8, 0x8(%rdi) without
 * first checking tv -- so settimeofday(NULL, NULL) SIGSEGVs in libc
 * before reaching the syscall boundary.  The kernel itself handles a
 * NULL tv/tz pair safely (security_settime64() runs first, returns
 * -EPERM without touching the args), so the direct syscall preserves
 * the no-side-effect probe semantic.
 *
 * We can only check the drop direction because Trinity isn't root and
 * never had the cap to begin with — gain checks would always show
 * "still EPERM" and tell us nothing.  A future enhancement is the full
 * cap-matrix oracle that walks every CAP_* after every cap-related
 * syscall and verifies its effective state matches our model.
 *
 * Scribble defeat: the two input args (header, data) are snapshotted at
 * sanitise time into a heap struct in rec->post_state, so a sibling that
 * scribbles rec->aN between syscall return and post entry cannot redirect
 * us at a foreign data buffer.
 */
static void post_capset(struct syscallrecord *rec)
{
	struct capset_post_state *snap;
	struct __user_cap_header_struct *hdr;
	struct __user_cap_data_struct *data;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, CAPSET_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_free;
	if (!ONE_IN(20))
		goto out_free;

	hdr = (struct __user_cap_header_struct *) snap->header;
	data = (struct __user_cap_data_struct *) snap->data;
	if (!hdr || !data)
		goto out_free;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner pointer fields.  Reject
	 * pid-scribbled header/data before deref.
	 */
	if (looks_like_corrupted_ptr(rec, hdr) || looks_like_corrupted_ptr(rec, data)) {
		outputerr("post_capset: rejected suspicious header=%p data=%p (post_state-scribbled?)\n",
			  hdr, data);
		goto out_free;
	}

	/* CAP_SYS_TIME == 25 lives in data[0] for v1/v2/v3. */
	if ((data[0].effective & (1u << CAP_SYS_TIME)) != 0)
		goto out_free;

	if (syscall(SYS_settimeofday, NULL, NULL) == 0) {
		output(0, "cred oracle: capset cleared CAP_SYS_TIME from effective "
		       "set but settimeofday(NULL, NULL) succeeded\n");
		__atomic_add_fetch(&shm->stats.oracle.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
	/* EPERM (or any other failure) means the kernel agrees with itself. */

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_capset = {
	.name = "capset",
	.num_args = 2,
	.argname = { [0] = "header", [1] = "data" },
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.sanitise = sanitise_capset,
	.post = post_capset,
};
