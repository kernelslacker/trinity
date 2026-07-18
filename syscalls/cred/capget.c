/*
 * SYSCALL_DEFINE2(capget, cap_user_header_t, header, cap_user_data_t, dataptr)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <linux/capability.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "deferred-free.h"
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "utils-mem.h"

/*
 * Pick a header.version with a distribution biased toward the kernel's
 * current preferred version (_3).  Random version values trip the
 * SYSCALL_GET_ARGS / cap_validate_magic() gate immediately with -EINVAL
 * (and the kernel writes the preferred version back into header.version
 * as a hint), so any per-task cap-mask code path is never reached.
 * Distribution:
 *   ~80% _LINUX_CAPABILITY_VERSION_3 (current preferred).
 *   ~10% _LINUX_CAPABILITY_VERSION_2 (legacy 64-bit).
 *   ~5%  _LINUX_CAPABILITY_VERSION_1 (legacy 32-bit; 1 data datum).
 *   ~5%  bogus version so the EINVAL gate stays exercised.
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
 * Snapshot of the two capget input args read by the post oracle, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign header / data buffer
 * and forge a clean compare against poisoned memory.
 */
#define CAPGET_POST_STATE_MAGIC	0x43415047UL	/* "CAPG" */
/*
 * Fixed poison sentinel stamped across the dataptr OUT buffer at
 * sanitise time and matched byte-for-byte in the post handler.  Fixed
 * rather than rnd_u64() so the sanitise pass draws no RNG bytes on
 * this leg: --dry-run output with a fixed seed stays byte-identical
 * to a build without this oracle.
 */
#define CAPGET_POISON_PATTERN	0xC4C4C4C4C4C4C4C4ULL

struct capget_post_state {
	unsigned long magic;
	unsigned long header;
	unsigned long data;
	uint64_t poison_seed;
};

/* Fill a __user_cap_header_struct with a valid version and pid. */
static void sanitise_capget(struct syscallrecord *rec)
{
	struct __user_cap_header_struct *hdr;
	struct capget_post_state *snap;

	rec->post_state = 0;

	hdr = (struct __user_cap_header_struct *) get_writable_address(sizeof(*hdr));
	if (hdr == NULL)
		return;
	hdr->version = pick_cap_version();
	hdr->pid = get_pid();

	rec->a1 = (unsigned long) hdr;
	/* Relocate + memcpy the curated header bytes (version, pid) onto a
	 * fresh pool page so the post-sanitise blanket address scrub no-ops on
	 * this slot.  Must precede the snap->header = rec->a1 capture below so
	 * the oracle snapshots the relocated pointer the kernel will see. */
	avoid_shared_buffer_inout(&rec->a1, sizeof(*hdr));
	avoid_shared_buffer_out(&rec->a2, 2 * sizeof(struct __user_cap_data_struct));

	/*
	 * Snapshot the two input args for the post oracle.  Without this
	 * the post handler reads rec->a1/a2 at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * buffer pointers, so the memcpy / re-call would touch a foreign
	 * allocation.  post_state is private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic  = CAPGET_POST_STATE_MAGIC;
	snap->header = rec->a1;
	snap->data   = rec->a2;
	snap->poison_seed = 0;

	/*
	 * Stamp a fixed poison pattern across the dataptr OUT buffer.  On a
	 * retval==0 return the kernel is contractually obliged to have
	 * written the effective/permitted/inheritable cap masks; a
	 * byte-for-byte match against the poison pattern in the post handler
	 * means the kernel returned success without copying any output --
	 * the caller would then read stale poison bytes as capability masks.
	 * The recall/divergence oracle below can only probabilistically
	 * detect this (both reads would see poison and compare equal), so
	 * this arm is a genuine additive check.  Gate on range_readable_user
	 * so a writable-pool draw that avoid_shared_buffer_out moved to an
	 * address no longer provably mapped does not SIGSEGV the sanitiser
	 * inside poison_output_struct's byte-walk; on skip poison_seed
	 * stays 0 and the post handler no-ops the arm.
	 */
	if (rec->a2 != 0) {
		void *buf = (void *)(unsigned long) rec->a2;
		size_t sz = 2 * sizeof(struct __user_cap_data_struct);

		if (range_readable_user(buf, sz))
			snap->poison_seed =
				poison_output_struct(buf, sz,
						     CAPGET_POISON_PATTERN);
	}
	/*
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_capget() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	post_state_install(rec, snap);
}

/*
 * Oracle: capget(header, dataptr) writes the calling task's effective,
 * permitted, and inheritable capability masks out to the user buffer.
 * The masks for a given task are stable across consecutive calls — they
 * mutate only via capset(), the setresuid()-tracking ambient/keep flow,
 * or exec's cap-clear path.  Trinity children don't call capset on
 * themselves and don't exec, so per-task cap masks are effectively
 * immutable across the nanosecond window between the original syscall
 * return and our post-hook re-call.  Two reads from the same task
 * therefore must produce byte-identical mask sets.  A divergence is not
 * benign drift — it points at one of:
 *
 *   - copy_to_user mis-write that leaves torn cap masks in the user
 *     buffer.
 *   - 32-bit-on-64-bit compat sign-extension on the __u32 cap mask
 *     fields (e.g. a small effective sign-extending to 0xFFFFFFFF).
 *   - struct-layout mismatch shifting effective into the permitted slot.
 *   - sibling-thread scribble of the user receive buffer between syscall
 *     return and post-hook re-read.
 *
 * TOCTOU defeat (two buffers worth of it): both the input header and the
 * output data pages are user memory and a sibling thread can scribble
 * either between the original syscall return and our re-issue.  The two
 * input args (header, data) are snapshotted at sanitise time into a heap
 * struct in rec->post_state, so a sibling that scribbles rec->aN between
 * syscall return and post entry cannot redirect us at a foreign header /
 * data buffer.  We still snapshot BOTH user buffers' contents into stack-
 * locals before the re-call (NOT pointing the re-call at the original
 * data buffer -- a sibling could mutate the user buffer mid-syscall and
 * forge a clean compare).  If the re-call fails, give up rather than
 * report.  Compare each mask field individually with no early-return so
 * multi-field corruption surfaces in a single sample, but bump the
 * anomaly counter only once per sample.  Sample one in a hundred to stay
 * in line with the rest of the oracle family.
 *
 * The header.version field determines the data slot count per the
 * capability UAPI: _LINUX_CAPABILITY_VERSION_1 is a single slot,
 * _LINUX_CAPABILITY_VERSION_2 and _3 are two slots (the high half of a
 * 64-bit cap set).  Snapshot and compare the right amount; reading or
 * comparing slot 1 on a v1 call is meaningless.  The kernel may rewrite
 * header.version on EINVAL but we only got here on retval==0 so first
 * and recall versions should match exactly.
 */
static void post_capget(struct syscallrecord *rec)
{
	struct capget_post_state *snap;
	struct __user_cap_header_struct hdr_first, hdr_recall;
	struct __user_cap_data_struct data_first[2] = { { 0 } };
	struct __user_cap_data_struct data_recall[2] = { { 0 } };
	unsigned int slots;
	int diverged = 0;
	unsigned int i;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, CAPGET_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	/*
	 * Poison writeback oracle: fires on every retval==0 call.  Cheap
	 * byte-compare with no kernel re-entry; catches a kernel
	 * success-without-write that the recall/divergence oracle below
	 * can only probabilistically detect (both reads would see the
	 * untouched poison and compare equal).  Placed BEFORE the
	 * ONE_IN(100) sampling gate so it runs at full rate; the gate
	 * itself is left in place for the expensive recall arm.  Guarded
	 * by snap->poison_seed != 0 so a sanitise-time skip (buffer no
	 * longer provably readable) silently no-ops here.
	 */
	if ((long) rec->retval == 0 && snap->data != 0 &&
	    snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip(
			(void *)(unsigned long) snap->data,
			2 * sizeof(struct __user_cap_data_struct),
			snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->header == 0 || snap->data == 0)
		goto out_free;

	if (!post_snapshot_or_skip(&hdr_first,
				   (const void *)(unsigned long) snap->header,
				   sizeof(hdr_first)))
		goto out_free;
	slots = (hdr_first.version == _LINUX_CAPABILITY_VERSION_1) ? 1 : 2;
	if (!post_snapshot_or_skip(data_first,
				   (const void *)(unsigned long) snap->data,
				   slots * sizeof(struct __user_cap_data_struct)))
		goto out_free;

	hdr_recall = hdr_first;
	if (syscall(SYS_capget, &hdr_recall, data_recall) != 0)
		goto out_free;

	if (hdr_first.version != hdr_recall.version)
		diverged = 1;

	for (i = 0; i < slots; i++) {
		if (data_first[i].effective   != data_recall[i].effective ||
		    data_first[i].permitted   != data_recall[i].permitted ||
		    data_first[i].inheritable != data_recall[i].inheritable)
			diverged = 1;
	}

	if (!diverged)
		goto out_free;

	if (slots == 2) {
		output(0,
		       "capget oracle anomaly: ver=%u/%u pid=%d "
		       "first[0]={eff=%x,perm=%x,inh=%x} "
		       "recall[0]={eff=%x,perm=%x,inh=%x} "
		       "first[1]={eff=%x,perm=%x,inh=%x} "
		       "recall[1]={eff=%x,perm=%x,inh=%x}\n",
		       hdr_first.version, hdr_recall.version, hdr_first.pid,
		       data_first[0].effective, data_first[0].permitted,
		       data_first[0].inheritable,
		       data_recall[0].effective, data_recall[0].permitted,
		       data_recall[0].inheritable,
		       data_first[1].effective, data_first[1].permitted,
		       data_first[1].inheritable,
		       data_recall[1].effective, data_recall[1].permitted,
		       data_recall[1].inheritable);
	} else {
		output(0,
		       "capget oracle anomaly: ver=%u/%u pid=%d "
		       "first[0]={eff=%x,perm=%x,inh=%x} "
		       "recall[0]={eff=%x,perm=%x,inh=%x}\n",
		       hdr_first.version, hdr_recall.version, hdr_first.pid,
		       data_first[0].effective, data_first[0].permitted,
		       data_first[0].inheritable,
		       data_recall[0].effective, data_recall[0].permitted,
		       data_recall[0].inheritable);
	}

	__atomic_add_fetch(&shm->stats.oracle.capget_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_capget = {
	.name = "capget",
	.num_args = 2,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_ADDRESS },
	.argname = { [0] = "header", [1] = "dataptr" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
	.group = GROUP_PROCESS,
	.sanitise = sanitise_capget,
	.post = post_capget,
};
