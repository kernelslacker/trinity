/*
 * int s390_pci_mmio_read(unsigned long mmio_addr,
 *			  void *user_buffer, size_t length);
 * int s390_pci_mmio_write(unsigned long mmio_addr,
 *			   void *user_buffer, size_t length);
 */

#include "arch.h"
#include "random.h"
#include "sanitise.h"

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
	rec->a2 = (unsigned long)malloc(rec->a3);
}

/* Allocate buffer and generate random data. */
static void sanitise_s390_pci_mmio_write(struct syscallrecord *rec)
{
	sanitise_s390_pci_mmio(rec);
	if (rec->a2)		/* Buffer allocated */
		generate_rand_bytes((void *)rec->a2, rec->a3);
}

/* Free buffer, freeptr takes care of NULL */
static void post_s390_pci_mmio(struct syscallrecord *rec)
{
	freeptr(&rec->a2);
}

struct syscallentry syscall_s390_pci_mmio_read = {
	.name = "s390_pci_mmio_read",
	.sanitise = sanitise_s390_pci_mmio,
	.post = post_s390_pci_mmio,
	.num_args = 3,
	.arg1name = "mmio_addr",
	.arg1type = ARG_UNDEFINED,
	.arg2name = "user_buffer",
	.arg2type = ARG_NON_NULL_ADDRESS,
	.arg3name = "length",
	.arg3type = ARG_RANGE,
	.low3range = 0,
	.hi3range = 1 << PAGE_SHIFT,
	.rettype = RET_ZERO_SUCCESS
};

struct syscallentry syscall_s390_pci_mmio_write = {
	.name = "s390_pci_mmio_write",
	.sanitise = sanitise_s390_pci_mmio_write,
	.post = post_s390_pci_mmio,
	.num_args = 3,
	.arg1name = "mmio_addr",
	.arg1type = ARG_UNDEFINED,
	.arg2name = "user_buffer",
	.arg2type = ARG_NON_NULL_ADDRESS,
	.arg3name = "length",
	.arg3type = ARG_RANGE,
	.low3range = 0,
	.hi3range = 1 << PAGE_SHIFT,
	.rettype = RET_ZERO_SUCCESS
};
