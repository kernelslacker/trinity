/*
 * ioctl fuzzing for Intel SGX kernel driver (isgx)
 * based on intel_sgx: Intel SGX Driver v0.10 
 * Feb 25, 2018
 * root@davejingtian.org
 */
#include <linux/types.h>
#include <linux/ioctl.h>
#include "ioctls.h"
#include "utils.h"

#define SGX_MAGIC 0xA4

#define SGX_IOC_ENCLAVE_CREATE \
	_IOW(SGX_MAGIC, 0x00, struct sgx_enclave_create)
#define SGX_IOC_ENCLAVE_ADD_PAGE \
	_IOW(SGX_MAGIC, 0x01, struct sgx_enclave_add_page)
#define SGX_IOC_ENCLAVE_INIT \
	_IOW(SGX_MAGIC, 0x02, struct sgx_enclave_init)

/**
 * struct sgx_enclave_create - parameter structure for the
 *                             %SGX_IOC_ENCLAVE_CREATE ioctl
 * @src:	address for the SECS page data
 */
struct sgx_enclave_create  {
	__u64	src;
} __attribute__((__packed__));

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


static const struct ioctl sgx_ioctls[] = {
	IOCTL(SGX_IOC_ENCLAVE_CREATE),
	IOCTL(SGX_IOC_ENCLAVE_ADD_PAGE),
	IOCTL(SGX_IOC_ENCLAVE_INIT),
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
