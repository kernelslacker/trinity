/*
 * int s390_pci_mmio_read(unsigned long mmio_addr,
 *			  void *user_buffer, size_t length);
 * int s390_pci_mmio_write(unsigned long mmio_addr,
 *			   void *user_buffer, size_t length);
 */

#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Allocate buffer which fits the svc requirements:
 * - length must be lower or equal to page size.
 * - transfer must no cross page boundary.
 */
static void sanitise_s390_pci_mmio(struct syscallrecord *rec)
{
	size_t offset = rec->a1 % page_size;

	if (offset + rec->a3 > page_size)
		rec->a3 = page_size - offset;
	if (rec->a3 == 0)
		rec->a3 = 1;
	rec->a2 = (unsigned long)malloc(rec->a3);
	/* Snapshot for the post handler -- a2 may be scribbled by a sibling
	 * syscall before post_s390_pci_mmio() runs.  malloc() failure leaves
	 * a2 == NULL, which the snapshot mirrors. */
	rec->post_state = rec->a2;
}

/* Allocate buffer and generate random data. */
static void sanitise_s390_pci_mmio_write(struct syscallrecord *rec)
{
	sanitise_s390_pci_mmio(rec);
	if (rec->a2)		/* Buffer allocated */
		generate_rand_bytes((void *)rec->a2, rec->a3);
}

static void post_s390_pci_mmio(struct syscallrecord *rec)
{
	void *buf = (void *) rec->post_state;

	if (buf == NULL)
		return;

	if (looks_like_corrupted_ptr(buf)) {
		outputerr("post_s390_pci_mmio: rejected suspicious buf=%p (pid-scribbled?)\n", buf);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a2 = 0;
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_s390_pci_mmio_read = {
	.name = "s390_pci_mmio_read",
	.sanitise = sanitise_s390_pci_mmio,
	.post = post_s390_pci_mmio,
	.num_args = 3,
	.argtype = { [0] = ARG_UNDEFINED, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_RANGE },
	.argname = { [0] = "mmio_addr", [1] = "user_buffer", [2] = "length" },
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 1 << PAGE_SHIFT,
	.rettype = RET_ZERO_SUCCESS
};

struct syscallentry syscall_s390_pci_mmio_write = {
	.name = "s390_pci_mmio_write",
	.sanitise = sanitise_s390_pci_mmio_write,
	.post = post_s390_pci_mmio,
	.num_args = 3,
	.argtype = { [0] = ARG_UNDEFINED, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_RANGE },
	.argname = { [0] = "mmio_addr", [1] = "user_buffer", [2] = "length" },
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 1 << PAGE_SHIFT,
	.rettype = RET_ZERO_SUCCESS
};
