/*
 * SYSCALL_DEFINE2(capget, cap_user_header_t, header, cap_user_data_t, dataptr)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <linux/capability.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static const unsigned int cap_versions[] = {
	_LINUX_CAPABILITY_VERSION_1,
	_LINUX_CAPABILITY_VERSION_2,
	_LINUX_CAPABILITY_VERSION_3,
};

/*
 * Snapshot of the two capget input args read by the post oracle, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign header / data buffer
 * and forge a clean compare against poisoned memory.
 */
struct capget_post_state {
	unsigned long header;
	unsigned long data;
};

/* Fill a __user_cap_header_struct with a valid version and pid. */
static void sanitise_capget(struct syscallrecord *rec)
{
	struct __user_cap_header_struct *hdr;
	struct capget_post_state *snap;

	rec->post_state = 0;

	hdr = (struct __user_cap_header_struct *) get_writable_address(sizeof(*hdr));
	hdr->version = RAND_ARRAY(cap_versions);
	hdr->pid = get_pid();

	rec->a1 = (unsigned long) hdr;
	avoid_shared_buffer(&rec->a2, 2 * sizeof(struct __user_cap_data_struct));

	/*
	 * Snapshot the two input args for the post oracle.  Without this
	 * the post handler reads rec->a1/a2 at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * buffer pointers, so the memcpy / re-call would touch a foreign
	 * allocation.  post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->header = rec->a1;
	snap->data   = rec->a2;
	rec->post_state = (unsigned long) snap;
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
	struct capget_post_state *snap = (struct capget_post_state *) rec->post_state;
	struct __user_cap_header_struct hdr_first, hdr_recall;
	struct __user_cap_data_struct data_first[2] = { { 0 } };
	struct __user_cap_data_struct data_recall[2] = { { 0 } };
	unsigned int slots;
	int diverged = 0;
	unsigned int i;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_capget: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->header == 0 || snap->data == 0)
		goto out_free;

	{
		void *hdr_p = (void *)(unsigned long) snap->header;
		void *data_p = (void *)(unsigned long) snap->data;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled header/data before deref.
		 */
		if (looks_like_corrupted_ptr(hdr_p) ||
		    looks_like_corrupted_ptr(data_p)) {
			outputerr("post_capget: rejected suspicious header=%p dataptr=%p (post_state-scribbled?)\n",
				  hdr_p, data_p);
			__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
			goto out_free;
		}
	}

	memcpy(&hdr_first, (void *)(unsigned long) snap->header, sizeof(hdr_first));
	slots = (hdr_first.version == _LINUX_CAPABILITY_VERSION_1) ? 1 : 2;
	memcpy(data_first, (void *)(unsigned long) snap->data,
	       slots * sizeof(struct __user_cap_data_struct));

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

	__atomic_add_fetch(&shm->stats.capget_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_capget = {
	.name = "capget",
	.num_args = 2,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_ADDRESS },
	.argname = { [0] = "header", [1] = "dataptr" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.sanitise = sanitise_capget,
	.post = post_capget,
};
