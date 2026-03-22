/*
 * KCOV coverage collection for coverage-guided fuzzing.
 *
 * Each child tries to open /sys/kernel/debug/kcov at startup. If the
 * kernel supports KCOV, per-thread trace buffers are mmapped and PC
 * tracing is enabled around each syscall. Collected PCs are hashed
 * into a global shared bitmap to track edge coverage.
 *
 * If KCOV is not available, everything is silently skipped with no
 * runtime overhead beyond the initial open() attempt per child.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "kcov.h"
#include "trinity.h"
#include "utils.h"

/* KCOV ioctl commands (from linux/kcov.h). */
#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE     _IO('c', 100)
#define KCOV_DISABLE    _IO('c', 101)

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
}

void kcov_init_child(struct kcov_child *kc)
{
	kc->fd = -1;
	kc->trace_buf = NULL;
	kc->active = false;
	kc->cmp_mode = false;

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
	if (!kc->active)
		return;

	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);
	ioctl(kc->fd, KCOV_ENABLE, KCOV_TRACE_PC);
}

void kcov_enable_cmp(struct kcov_child *kc)
{
	if (!kc->active)
		return;

	__atomic_store_n(&kc->trace_buf[0], 0, __ATOMIC_RELAXED);
	ioctl(kc->fd, KCOV_ENABLE, KCOV_TRACE_CMP);
}

void kcov_disable(struct kcov_child *kc)
{
	if (!kc->active)
		return;

	ioctl(kc->fd, KCOV_DISABLE, 0);
}

/*
 * Hash a kernel PC value into a bitmap index.
 * Simple xor-shift to spread PCs across the bitmap.
 */
static unsigned int pc_to_bit(unsigned long pc)
{
	pc ^= pc >> 17;
	pc ^= pc >> 7;
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

	if (found_new && nr < MAX_NR_SYSCALL) {
		__atomic_fetch_add(&kcov_shm->per_syscall_edges[nr],
			1, __ATOMIC_RELAXED);
		__atomic_store_n(&kcov_shm->last_edge_at[nr],
			call_nr, __ATOMIC_RELAXED);
	}

	return found_new;
}

bool kcov_syscall_is_cold(unsigned int nr)
{
	unsigned long total, last;

	if (kcov_shm == NULL || nr >= MAX_NR_SYSCALL)
		return false;

	total = __atomic_load_n(&kcov_shm->total_calls, __ATOMIC_RELAXED);
	last = __atomic_load_n(&kcov_shm->last_edge_at[nr], __ATOMIC_RELAXED);

	/* Never found any edges — not cold, just unexplored. */
	if (last == 0 && kcov_shm->per_syscall_edges[nr] == 0)
		return false;

	return (total - last) > KCOV_COLD_THRESHOLD;
}
