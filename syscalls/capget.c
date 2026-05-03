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

/* Fill a __user_cap_header_struct with a valid version and pid. */
static void sanitise_capget(struct syscallrecord *rec)
{
	struct __user_cap_header_struct *hdr;

	hdr = (struct __user_cap_header_struct *) get_writable_address(sizeof(*hdr));
	hdr->version = RAND_ARRAY(cap_versions);
	hdr->pid = get_pid();

	rec->a1 = (unsigned long) hdr;
	avoid_shared_buffer(&rec->a2, 2 * sizeof(struct __user_cap_data_struct));
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
 * either between the original syscall return and our re-issue.  If we
 * re-call with whatever rec->a1's payload happens to hold by then we may
 * resolve a different version/pid combination, get different masks, and
 * report a false divergence; if we read rec->a2 after a sibling scribble
 * we'd compare against poisoned data.  Snapshot BOTH buffers into stack-
 * locals before the re-call.  If the re-call fails, give up rather than
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
	struct __user_cap_header_struct hdr_first, hdr_recall;
	struct __user_cap_data_struct data_first[2] = { { 0 } };
	struct __user_cap_data_struct data_recall[2] = { { 0 } };
	unsigned int slots;
	int diverged = 0;
	unsigned int i;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a1 == 0 || rec->a2 == 0)
		return;

	{
		void *hdr_p = (void *)(unsigned long) rec->a1;
		void *data_p = (void *)(unsigned long) rec->a2;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a1/a2. */
		if (looks_like_corrupted_ptr(hdr_p) ||
		    looks_like_corrupted_ptr(data_p)) {
			outputerr("post_capget: rejected suspicious header=%p dataptr=%p (pid-scribbled?)\n",
				  hdr_p, data_p);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	memcpy(&hdr_first, (void *)(unsigned long) rec->a1, sizeof(hdr_first));
	slots = (hdr_first.version == _LINUX_CAPABILITY_VERSION_1) ? 1 : 2;
	memcpy(data_first, (void *)(unsigned long) rec->a2,
	       slots * sizeof(struct __user_cap_data_struct));

	hdr_recall = hdr_first;
	if (syscall(SYS_capget, &hdr_recall, data_recall) != 0)
		return;

	if (hdr_first.version != hdr_recall.version)
		diverged = 1;

	for (i = 0; i < slots; i++) {
		if (data_first[i].effective   != data_recall[i].effective ||
		    data_first[i].permitted   != data_recall[i].permitted ||
		    data_first[i].inheritable != data_recall[i].inheritable)
			diverged = 1;
	}

	if (!diverged)
		return;

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
