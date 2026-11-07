/*
 * SYSCALL_DEFINE3(sched_getaffinity, pid_t, pid, unsigned int, len,
	 unsigned long __user *, user_mask_ptr)
 */
#include <ctype.h>
#include <sched.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "arch.h"
#include "deferred-free.h"
#include "proc-status.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/sched.h"
/*
 * Snapshot of the sched_getaffinity mask buffer read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the oracle at a foreign mask buffer.
 * The pid and len are read from the slots the kernel was handed instead.
 */
#define SCHED_GETAFFINITY_POST_STATE_MAGIC	0x5343484741464659UL	/* "SCHGAFFY" */
struct sched_getaffinity_post_state {
	unsigned long magic;
	unsigned long mask;
};

static void sanitise_sched_getaffinity(struct syscallrecord *rec)
{
	cpu_set_t *mask;
	struct sched_getaffinity_post_state *snap;

	rec->post_state = 0;

	mask = (cpu_set_t *) get_writable_address(sizeof(*mask));
	if (mask == NULL) {
		rec->a3 = 0;
		return;
	}

	/*
	 * Length bucket biased toward kernel-acceptable sizes.  70% land
	 * on a real cpumask-sized buffer (canonical sizeof or the long-
	 * aligned cpumask_size() round-up of num_online_cpus()); 20% are
	 * oversized; 10% are deliberately too small for the validation
	 * path.  Random small lengths otherwise EINVAL the request
	 * before the kernel can copy any bytes back.
	 */
	{
		unsigned int roll = rnd_modulo_u32(100);
		unsigned int aligned;

		if (roll < 70) {
			if (RAND_BOOL()) {
				rec->a2 = sizeof(*mask);
			} else {
				aligned = (cached_online_cpus() + 7) / 8;
				aligned = (aligned + sizeof(long) - 1) &
					~(sizeof(long) - 1);
				if (aligned == 0)
					aligned = sizeof(long);
				rec->a2 = aligned;
			}
		} else if (roll < 90) {
			rec->a2 = sizeof(*mask) * 2;
		} else {
			rec->a2 = 1 + rnd_modulo_u32(sizeof(long));
		}
	}

	rec->a3 = (unsigned long) mask;

	avoid_shared_buffer_out(&rec->a3, page_size);

	/*
	 * Snapshot the mask pointer for the post oracle.  Without this
	 * the post handler reads rec->a3 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original
	 * user mask pointer.  post_state is private to the post handler.
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_sched_getaffinity() will then gate the snap
	 * through post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = SCHED_GETAFFINITY_POST_STATE_MAGIC;
	snap->mask = rec->a3;
	post_state_install(rec, snap);
}

/*
 * Oracle: sched_getaffinity() copies the calling task's CPU affinity mask
 * (task->cpus_ptr / task->cpus_mask) out to userspace as a cpumask sized
 * by the kernel's cpumask_size().  The procfs view of the same fact is
 * /proc/self/status, which exposes the same mask as "Cpus_allowed:" via
 * proc_pid_status() -> task_cpus_allowed() formatted with %*pb (hex
 * 32-bit chunks separated by commas, leftmost chunk = highest word).
 * Both views read the same cpus_mask but through different code paths —
 * the syscall takes a memcpy_to_sockptr of the live mask, procfs walks
 * the seq_file render with bitmap_string() — so a divergence between
 * the two for the same task is its own corruption shape: a torn write
 * to cpus_mask during a parallel sched_setaffinity, a stale rcu pointer
 * to cpus_ptr after a cpuset migration, or a copy_to_user that wrote
 * past/before the live mask.  Mirror of the rt_sigpending procfs oracle
 * pattern, applied to the affinity mask side.
 */
static void post_sched_getaffinity(struct syscallrecord *rec)
{
	struct sched_getaffinity_post_state *snap;
	unsigned long retval = rec->retval;
	long ret = (long) retval;
	pid_t pid;
	char buf[2048];
	cpu_set_t syscall_buf, proc_buf;
	size_t copied, cmp_len;
	const char *value, *p;
	uint32_t chunks[sizeof(cpu_set_t) / sizeof(uint32_t)];
	int nchunks = 0, i;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, SCHED_GETAFFINITY_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if (!ONE_IN(100))
		goto out_free;

	if (ret <= 0)
		goto out_free;

	/* pid argument, as the kernel read it; sanitise leaves it
	 * caller-init.  Treat 0 as "self" (kernel maps 0 -> current); skip if
	 * it names another task. */
	pid = (pid_t) get_arg_snapshot(rec, 1);
	if (pid != 0 && pid != gettid())
		goto out_free;

	copied = (size_t)retval;
	if (copied > sizeof(cpu_set_t))
		copied = sizeof(cpu_set_t);

	memset(&syscall_buf, 0, sizeof(syscall_buf));
	if (!post_snapshot_or_skip(&syscall_buf,
				   (const void *)(unsigned long) snap->mask,
				   copied))
		goto out_free;

	if (proc_status_read(buf, sizeof(buf)) < 0)
		goto out_free;
	/* The trailing ':' in the helper's anchor keeps the sibling
	 * Cpus_allowed_list: line from matching. */
	value = proc_status_find_field(buf, "Cpus_allowed");
	if (value == NULL)
		goto out_free;

	memset(chunks, 0, sizeof(chunks));
	/* Walk the comma-separated hex chunks the kernel emits via %*pb.
	 * Stop at the trailing newline so the walker cannot stride into the
	 * next field's value.  Kept local rather than in the helper because
	 * the chunk format is specific to bitmap-style status rows. */
	p = value;
	while (*p && *p != '\n') {
		while (*p && *p != '\n' && !isxdigit((unsigned char)*p))
			p++;
		if (!*p || *p == '\n')
			break;
		if (nchunks >= (int)(sizeof(chunks) / sizeof(chunks[0])))
			break;
		chunks[nchunks++] = (uint32_t)strtoul(p, NULL, 16);
		while (*p && isxdigit((unsigned char)*p))
			p++;
	}

	if (nchunks == 0)
		goto out_free;

	memset(&proc_buf, 0, sizeof(proc_buf));
	/* Reverse order: leftmost printed chunk is the highest 32-bit word. */
	for (i = 0; i < nchunks; i++) {
		size_t dst = (size_t)(nchunks - 1 - i) * sizeof(uint32_t);
		if (dst + sizeof(uint32_t) > sizeof(proc_buf))
			continue;
		memcpy((char *)&proc_buf + dst, &chunks[i], sizeof(uint32_t));
	}

	cmp_len = copied;
	if (cmp_len > sizeof(proc_buf))
		cmp_len = sizeof(proc_buf);

	if (memcmp(&syscall_buf, &proc_buf, cmp_len) != 0) {
		const unsigned long *s = (const unsigned long *)&syscall_buf;
		const unsigned long *q = (const unsigned long *)&proc_buf;
		output(0, "sched_getaffinity oracle: syscall=%016lx %016lx %016lx %016lx but "
		       "/proc/self/status Cpus_allowed=%016lx %016lx %016lx %016lx "
		       "(cmp_len=%zu)\n",
		       s[0], s[1], s[2], s[3],
		       q[0], q[1], q[2], q[3],
		       cmp_len);
		__atomic_add_fetch(&shm->stats.oracle.sched_getaffinity_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_sched_getaffinity = {
	.name = "sched_getaffinity",
	.group = GROUP_SCHED,
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_LEN, [2] = ARG_ADDRESS },
	.argname = { [0] = "pid", [1] = "len", [2] = "user_mask_ptr" },
	.sanitise = sanitise_sched_getaffinity,
	/* sanitise_sched_getaffinity() points the mask at a pool buffer, or
	 * NULL, on every path. */
	.sanitiser_owned_mask = (1u << 2),
	.post = post_sched_getaffinity,
	.bound_arg = 2,
	/* pid (a1) and len (a2): the oracle compares only a call on this
	 * task, and enforce_count_bound() holds the return to the len, as
	 * the kernel was handed them. */
	.arg_snapshot_mask = (1u << 0) | (1u << 1),
	.rettype = RET_NUM_BYTES,
	.flags = REEXEC_SANITISE_OK,
};
