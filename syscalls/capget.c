/*
 * SYSCALL_DEFINE2(capget, cap_user_header_t, header, cap_user_data_t, dataptr)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <linux/capability.h>
#include "random.h"
#include "sanitise.h"

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

struct syscallentry syscall_capget = {
	.name = "capget",
	.num_args = 2,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_ADDRESS },
	.argname = { [0] = "header", [1] = "dataptr" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.sanitise = sanitise_capget,
};
