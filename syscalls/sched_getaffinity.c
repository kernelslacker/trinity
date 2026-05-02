/*
 * SYSCALL_DEFINE3(sched_getaffinity, pid_t, pid, unsigned int, len,
	 unsigned long __user *, user_mask_ptr)
 */
#include <ctype.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_sched_getaffinity(struct syscallrecord *rec)
{
	cpu_set_t *mask;

	mask = (cpu_set_t *) get_writable_address(sizeof(*mask));

	/* len must be at least sizeof(cpumask_t) for success, but exercise
	 * various sizes including too-small for error paths. */
	switch (rand() % 4) {
	case 0: rec->a2 = sizeof(*mask); break;
	case 1: rec->a2 = 4; break;		/* too small on most systems */
	case 2: rec->a2 = 8; break;		/* might work on small systems */
	default: rec->a2 = sizeof(*mask) * 2; break;	/* oversized */
	}

	rec->a3 = (unsigned long) mask;
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
	FILE *f;
	char line[4096];
	cpu_set_t syscall_buf, proc_buf;
	size_t copied, cmp_len;
	bool have_line = false;
	const char *p;
	uint32_t chunks[sizeof(cpu_set_t) / sizeof(uint32_t)];
	int nchunks = 0, i;

	if (!ONE_IN(100))
		return;

	if ((long)rec->retval <= 0)
		return;

	/* a1 is the pid argument; sanitise leaves it caller-init.  Treat 0
	 * as "self" (kernel maps 0 -> current); skip if it names another task. */
	if (rec->a1 != 0 && rec->a1 != (unsigned long)gettid())
		return;

	copied = (size_t)rec->retval;
	if (copied > sizeof(cpu_set_t))
		copied = sizeof(cpu_set_t);

	memset(&syscall_buf, 0, sizeof(syscall_buf));
	memcpy(&syscall_buf, (void *)(unsigned long)rec->a3, copied);

	f = fopen("/proc/self/status", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Cpus_allowed:", 13) == 0) {
			have_line = true;
			break;
		}
	}
	fclose(f);

	if (!have_line)
		return;

	memset(chunks, 0, sizeof(chunks));
	p = line + 13;
	while (*p) {
		while (*p && !isxdigit((unsigned char)*p))
			p++;
		if (!*p)
			break;
		if (nchunks >= (int)(sizeof(chunks) / sizeof(chunks[0])))
			break;
		chunks[nchunks++] = (uint32_t)strtoul(p, NULL, 16);
		while (*p && isxdigit((unsigned char)*p))
			p++;
	}

	if (nchunks == 0)
		return;

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
		__atomic_add_fetch(&shm->stats.sched_getaffinity_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_sched_getaffinity = {
	.name = "sched_getaffinity",
	.group = GROUP_SCHED,
	.num_args = 3,
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid", [1] = "len", [2] = "user_mask_ptr" },
	.sanitise = sanitise_sched_getaffinity,
	.post = post_sched_getaffinity,
};
