/*
 * KCOV coverage collection for coverage-guided fuzzing.
 *
 * Each child tries to open /sys/kernel/debug/kcov at startup. If the
 * kernel supports KCOV, per-thread trace buffers are mmapped and PC
 * tracing is enabled around each syscall. Collected PCs are hashed
 * into a global shared bitmap to track edge coverage.
 *
 * When KCOV_REMOTE_ENABLE is available, a fraction of syscalls use
 * remote mode to also collect coverage from softirqs, threaded IRQ
 * handlers, and kthreads triggered by the syscall — deferred work
 * that per-thread KCOV_ENABLE would miss.
 *
 * If KCOV is not available, everything is silently skipped with no
 * runtime overhead beyond the initial open() attempt per child.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "edgepair.h"
#include "kcov.h"
#include "trinity.h"
#include "utils.h"

/* KCOV ioctl commands (from linux/kcov.h). */
#define KCOV_INIT_TRACE    _IOR('c', 1, unsigned long)
#define KCOV_ENABLE        _IO('c', 100)
#define KCOV_DISABLE       _IO('c', 101)
#define KCOV_REMOTE_ENABLE _IOW('c', 102, struct kcov_remote_arg)

/*
 * Userspace copy of struct kcov_remote_arg from linux/kcov.h.
 * We define it here to avoid requiring kernel headers at build time.
 */
struct kcov_remote_arg {
	uint32_t	trace_mode;
	uint32_t	area_size;
	uint32_t	num_handles;
	uint32_t	__pad;
	uint64_t	common_handle;
	uint64_t	handles[];
};

struct kcov_shared *kcov_shm = NULL;

void kcov_init_global(void)
{
	int fd;

	/* Probe whether KCOV is available before allocating shared memory. */
	fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (fd < 0)
		return;
	close(fd);

	kcov_shm = alloc_shared(sizeof(struct kcov_shared));
	memset(kcov_shm, 0, sizeof(struct kcov_shared));
	output(0, "KCOV: coverage collection enabled (%d KB bitmap)\n",
		KCOV_BITMAP_SIZE / 1024);

	edgepair_init_global();
}

void kcov_init_child(struct kcov_child *kc, unsigned int child_id)
{
	kc->fd = -1;
	kc->trace_buf = NULL;
	kc->active = false;
	kc->cmp_mode = false;
	kc->remote_mode = false;
	kc->remote_capable = false;
	kc->child_id = child_id;

	if (kcov_shm == NULL)
		return;

	kc->fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kc->fd < 0)
		return;

	if (ioctl(kc->fd, KCOV_INIT_TRACE, KCOV_TRACE_SIZE) < 0) {
		close(kc->fd);
		kc->fd = -1;
		return;
	}

	kc->trace_buf = mmap(NULL,
		KCOV_TRACE_SIZE * sizeof(unsigned long),
		PROT_READ | PROT_WRITE, MAP_SHARED,
		kc->fd, 0);

	if (kc->trace_buf == MAP_FAILED) {
		close(kc->fd);
		kc->fd = -1;
		kc->trace_buf = NULL;
		return;
	}

	kc->active = true;

	/* Probe for KCOV_REMOTE_ENABLE support.  Try a remote enable/disable
	 * cycle — if the ioctl succeeds, the kernel supports it. */
	{
		struct kcov_remote_arg *arg;

		arg = calloc(1, sizeof(*arg));
		if (arg != NULL) {
			arg->trace_mode = KCOV_TRACE_PC;
			arg->area_size = KCOV_TRACE_SIZE;
			arg->num_handles = 0;
			arg->common_handle = KCOV_SUBSYSTEM_COMMON | (child_id + 1);
			if (ioctl(kc->fd, KCOV_REMOTE_ENABLE, arg) == 0) {
				if (ioctl(kc->fd, KCOV_DISABLE, 0) == 0) {
					kc->remote_capable = true;
				} else {
					/* fd stuck in enabled state — close
					 * and reopen to reset. */
					close(kc->fd);
					munmap(kc->trace_buf,
						KCOV_TRACE_SIZE * sizeof(unsigned long));
					kc->trace_buf = NULL;
					kc->fd = open("/sys/kernel/debug/kcov", O_RDWR);
					if (kc->fd < 0 ||
					    ioctl(kc->fd, KCOV_INIT_TRACE, KCOV_TRACE_SIZE) < 0) {
						if (kc->fd >= 0) {
							close(kc->fd);
							kc->fd = -1;
						}
						kc->active = false;
					} else {
						kc->trace_buf = mmap(NULL,
							KCOV_TRACE_SIZE * sizeof(unsigned long),
							PROT_READ | PROT_WRITE, MAP_SHARED,
							kc->fd, 0);
						if (kc->trace_buf == MAP_FAILED) {
							kc->trace_buf = NULL;
							close(kc->fd);
							kc->fd = -1;
							kc->active = false;
						}
					}
				}
			}
			free(arg);
		}
	}
}

void kcov_cleanup_child(struct kcov_child *kc)
{
	if (kc->trace_buf != NULL) {
		munmap(kc->trace_buf, KCOV_TRACE_SIZE * sizeof(unsigned long));
		kc->trace_buf = NULL;
	}
	if (kc->fd >= 0) {
		close(kc->fd);
		kc->fd = -1;
	}
	kc->active = false;
}

void kcov_enable_trace(struct kcov_child *kc)
{
	if (kc == NULL || !kc->active)
		return;

	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);
	if (ioctl(kc->fd, KCOV_ENABLE, KCOV_TRACE_PC) < 0)
		kc->active = false;
}

void kcov_enable_cmp(struct kcov_child *kc)
{
	if (kc == NULL || !kc->active)
		return;

	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);
	if (ioctl(kc->fd, KCOV_ENABLE, KCOV_TRACE_CMP) < 0)
		kc->active = false;
}

void kcov_enable_remote(struct kcov_child *kc)
{
	struct kcov_remote_arg *arg;

	if (kc == NULL || !kc->active || !kc->remote_capable)
		return;

	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);

	arg = calloc(1, sizeof(*arg));
	if (arg == NULL)
		return;

	arg->trace_mode = KCOV_TRACE_PC;
	arg->area_size = KCOV_TRACE_SIZE;
	arg->num_handles = 0;
	arg->common_handle = KCOV_SUBSYSTEM_COMMON | (kc->child_id + 1);

	if (ioctl(kc->fd, KCOV_REMOTE_ENABLE, arg) < 0) {
		/* Fall back to per-thread mode if remote fails at runtime. */
		kc->remote_capable = false;
		free(arg);
		if (ioctl(kc->fd, KCOV_ENABLE, KCOV_TRACE_PC) < 0)
			kc->active = false;
		return;
	}

	free(arg);
}

void kcov_disable(struct kcov_child *kc)
{
	if (kc == NULL || kc->fd < 0 || kc->trace_buf == NULL)
		return;

	ioctl(kc->fd, KCOV_DISABLE, 0);
}

/*
 * Hash a kernel PC value into a bitmap index.
 *
 * The previous xor-shift mixed too few of the bits in a typical kernel PC.
 * Two PCs that landed within the same cacheline (low 6 bits identical) and
 * shared the same upper bits ended up hashed to indices differing only in
 * the low 7 bits, clustering thousands of distinct PCs into a tiny bitmap
 * range and triggering false coverage saturation.
 *
 * Murmur3's 64-bit finalizer mixes every input bit into every output bit
 * with a single multiply/xor pair per round, which is enough to avoid the
 * cacheline clustering without breaking the PC's locality for the rest of
 * the pipeline.
 */
static unsigned int pc_to_bit(unsigned long pc)
{
	pc ^= pc >> 33;
	pc *= 0xff51afd7ed558ccdUL;
	pc ^= pc >> 33;
	pc *= 0xc4ceb9fe1a85ec53UL;
	pc ^= pc >> 33;
	return (unsigned int)(pc % (KCOV_BITMAP_SIZE * 8));
}

bool kcov_collect(struct kcov_child *kc, unsigned int nr)
{
	unsigned long count;
	unsigned long idx;
	unsigned long call_nr;
	bool found_new = false;

	if (!kc->active)
		return false;

	call_nr = __atomic_fetch_add(&kcov_shm->total_calls,
		1, __ATOMIC_RELAXED);

	if (kc->remote_mode)
		__atomic_fetch_add(&kcov_shm->remote_calls,
			1, __ATOMIC_RELAXED);

	count = __atomic_load_n(&kc->trace_buf[0], __ATOMIC_RELAXED);
	if (count > KCOV_TRACE_SIZE - 1)
		count = KCOV_TRACE_SIZE - 1;

	for (idx = 0; idx < count; idx++) {
		unsigned long pc_val = kc->trace_buf[idx + 1];
		unsigned int bit = pc_to_bit(pc_val);
		unsigned int byte_idx = bit / 8;
		unsigned char bit_mask = 1U << (bit % 8);
		unsigned char old;

		old = __atomic_fetch_or(&kcov_shm->bitmap[byte_idx],
			bit_mask, __ATOMIC_RELAXED);

		if (!(old & bit_mask)) {
			__atomic_fetch_add(&kcov_shm->edges_found,
				1, __ATOMIC_RELAXED);
			found_new = true;
		}
	}

	__atomic_fetch_add(&kcov_shm->total_pcs, count, __ATOMIC_RELAXED);

	if (nr < MAX_NR_SYSCALL) {
		__atomic_fetch_add(&kcov_shm->per_syscall_calls[nr],
			1, __ATOMIC_RELAXED);
		if (found_new) {
			__atomic_fetch_add(&kcov_shm->per_syscall_edges[nr],
				1, __ATOMIC_RELAXED);
			__atomic_store_n(&kcov_shm->last_edge_at[nr],
				call_nr, __ATOMIC_RELAXED);
		}
	}

	return found_new;
}

unsigned int kcov_syscall_cold_skip_pct(unsigned int nr)
{
	unsigned long edges, gap;
	unsigned int pct;

	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return 0;

	edges = __atomic_load_n(&kcov_shm->per_syscall_edges[nr],
		__ATOMIC_RELAXED);

	if (edges == 0) {
		/* Never produced an edge.  Until this syscall has had
		 * KCOV_COLD_THRESHOLD attempts of its own, leave it alone —
		 * total_calls grows from every other syscall too, so basing
		 * the cutoff on total_calls would prematurely retire any
		 * syscall that the dispatch loop happens to under-pick.
		 * Once it has clearly had a fair shot, skip aggressively. */
		gap = __atomic_load_n(&kcov_shm->per_syscall_calls[nr],
			__ATOMIC_RELAXED);
	} else {
		unsigned long total, last;

		total = __atomic_load_n(&kcov_shm->total_calls,
			__ATOMIC_RELAXED);
		last = __atomic_load_n(&kcov_shm->last_edge_at[nr],
			__ATOMIC_RELAXED);
		if (total <= last)
			return 0;
		gap = total - last;
	}

	if (gap <= KCOV_COLD_THRESHOLD)
		return 0;

	/* Graduated skip: the further past the threshold, the more we skip.
	 * Each additional KCOV_COLD_THRESHOLD-sized step adds 10 percentage
	 * points on top of the 50% baseline that the old flat heuristic used,
	 * capped at 90% so even the deadest syscall still gets called once
	 * every ~10 attempts in case kernel state changes underneath us. */
	pct = 50 + (unsigned int)((gap / KCOV_COLD_THRESHOLD) * 10);
	if (pct > 90)
		pct = 90;
	return pct;
}

bool kcov_syscall_is_cold(unsigned int nr)
{
	return kcov_syscall_cold_skip_pct(nr) > 0;
}
