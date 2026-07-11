/*
 * ioctl fuzzing for Intel SGX kernel driver (isgx)
 * based on intel_sgx: Intel SGX Driver v0.10
 * Feb 25, 2018
 * Add support for SGXv2
 * Feb 26, 2018
 * root@davejingtian.org
 */
#include <linux/types.h>
#include <linux/ioctl.h>
#include "ioctls.h"
#include "utils.h"

#ifdef __has_include
#  if __has_include(<linux/sgx.h>)
#    include <linux/sgx.h>
#    define HAVE_LINUX_SGX_H
#  endif
#endif

#define SGX_MAGIC 0xA4

#define SGX_IOC_ENCLAVE_CREATE \
	_IOW(SGX_MAGIC, 0x00, struct sgx_enclave_create)
#define SGX_IOC_ENCLAVE_ADD_PAGE \
	_IOW(SGX_MAGIC, 0x01, struct sgx_enclave_add_page)
#define SGX_IOC_ENCLAVE_INIT \
	_IOW(SGX_MAGIC, 0x02, struct sgx_enclave_init)

/* SGXv2 */
#define SGX_IOC_ENCLAVE_EMODPR \
	_IOW(SGX_MAGIC, 0x09, struct sgx_modification_param)
#define SGX_IOC_ENCLAVE_MKTCS \
	_IOW(SGX_MAGIC, 0x0a, struct sgx_range)
#define SGX_IOC_ENCLAVE_TRIM \
	_IOW(SGX_MAGIC, 0x0b, struct sgx_range)
#define SGX_IOC_ENCLAVE_NOTIFY_ACCEPT \
	_IOW(SGX_MAGIC, 0x0c, struct sgx_range)
#define SGX_IOC_ENCLAVE_PAGE_REMOVE \
	_IOW(SGX_MAGIC, 0x0d, unsigned long)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpacked"
#ifndef HAVE_LINUX_SGX_H
/**
 * struct sgx_enclave_create - parameter structure for the
 *                             %SGX_IOC_ENCLAVE_CREATE ioctl
 * @src:	address for the SECS page data
 */
struct sgx_enclave_create  {
	__u64	src;
} __attribute__((__packed__));

/**
 * struct sgx_enclave_init - parameter structure for the
 *                           %SGX_IOC_ENCLAVE_INIT ioctl
 * @addr:	address in the ELRANGE
 * @sigstruct:	address for the page data
 * @einittoken:	EINITTOKEN
 */
struct sgx_enclave_init {
	__u64	addr;
	__u64	sigstruct;
	__u64	einittoken;
} __attribute__((__packed__));
#endif /* !HAVE_LINUX_SGX_H */

/**
 * struct sgx_enclave_add_page - parameter structure for the
 *                               %SGX_IOC_ENCLAVE_ADD_PAGE ioctl
 * @addr:	address in the ELRANGE
 * @src:	address for the page data
 * @secinfo:	address for the SECINFO data
 * @mrmask:	bitmask for the 256 byte chunks that are to be measured
 */
struct sgx_enclave_add_page {
	__u64	addr;
	__u64	src;
	__u64	secinfo;
	__u16	mrmask;
} __attribute__((__packed__));


/* SGXv2 */
struct sgx_range {
	unsigned long start_addr;
	unsigned int nr_pages;
};

struct sgx_modification_param {
	struct sgx_range range;
	unsigned long flags;
};
#pragma GCC diagnostic pop

/*
 * Compile-time: every fixed-shape sgx ioctl command whose arg is a
 * kernel struct must have sizeof(struct) matching the _IOC_SIZE
 * encoded in its request bits.  A mismatch means the local struct
 * definitions (or, when HAVE_LINUX_SGX_H, the kernel uapi header)
 * moved without the matching _IO* macro and the kernel would
 * copy_from_user() / copy_to_user() a different number of bytes
 * than we prepared.
 *
 * SGX_IOC_ENCLAVE_MKTCS, SGX_IOC_ENCLAVE_TRIM and
 * SGX_IOC_ENCLAVE_NOTIFY_ACCEPT all take sgx_range and get one
 * assert each -- the three sides can drift independently in a
 * header refactor.
 *
 * SGX_IOC_ENCLAVE_PAGE_REMOVE encodes a bare scalar (unsigned long)
 * and is intentionally absent -- asserting sizeof(struct) against a
 * scalar would be the wrong shape of check.
 */
IOCTL_SIZE_ASSERT(SGX_IOC_ENCLAVE_CREATE, struct sgx_enclave_create);
IOCTL_SIZE_ASSERT(SGX_IOC_ENCLAVE_ADD_PAGE, struct sgx_enclave_add_page);
IOCTL_SIZE_ASSERT(SGX_IOC_ENCLAVE_INIT, struct sgx_enclave_init);
IOCTL_SIZE_ASSERT(SGX_IOC_ENCLAVE_EMODPR, struct sgx_modification_param);
IOCTL_SIZE_ASSERT(SGX_IOC_ENCLAVE_MKTCS, struct sgx_range);
IOCTL_SIZE_ASSERT(SGX_IOC_ENCLAVE_TRIM, struct sgx_range);
IOCTL_SIZE_ASSERT(SGX_IOC_ENCLAVE_NOTIFY_ACCEPT, struct sgx_range);

static const struct ioctl sgx_ioctls[] = {
	IOCTL(SGX_IOC_ENCLAVE_CREATE),
	IOCTL(SGX_IOC_ENCLAVE_ADD_PAGE),
	IOCTL(SGX_IOC_ENCLAVE_INIT),
#ifdef SGXv2
	IOCTL(SGX_IOC_ENCLAVE_EMODPR),
	IOCTL(SGX_IOC_ENCLAVE_MKTCS),
	IOCTL(SGX_IOC_ENCLAVE_TRIM),
	IOCTL(SGX_IOC_ENCLAVE_NOTIFY_ACCEPT),
	IOCTL(SGX_IOC_ENCLAVE_PAGE_REMOVE),
#endif
};

static const char *const sgx_devs[] = {
	"isgx",
};

static const struct ioctl_group sgx_grp = {
	.devtype = DEV_CHAR,
	.devs = sgx_devs,
	.devs_cnt = ARRAY_SIZE(sgx_devs),
	.sanitise = pick_random_ioctl,
	.ioctls = sgx_ioctls,
	.ioctls_cnt = ARRAY_SIZE(sgx_ioctls),
};

REG_IOCTL_GROUP(sgx_grp)
