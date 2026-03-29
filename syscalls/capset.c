/*
 * SYSCALL_DEFINE2(capset, cap_user_header_t, header, const cap_user_data_t, data)
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

/*
 * Fill header with valid version and pid.
 * Fill data with random capability bitmasks.
 * v3 uses two __user_cap_data_struct entries (64-bit capability sets).
 */
static void sanitise_capset(struct syscallrecord *rec)
{
	struct __user_cap_header_struct *hdr;
	struct __user_cap_data_struct *data;
	unsigned int version;

	hdr = (struct __user_cap_header_struct *) get_writable_address(sizeof(*hdr));
	version = RAND_ARRAY(cap_versions);
	hdr->version = version;
	hdr->pid = get_pid();
	rec->a1 = (unsigned long) hdr;

	/* v1 uses 1 data struct, v2/v3 use 2. */
	if (version == _LINUX_CAPABILITY_VERSION_1) {
		data = (struct __user_cap_data_struct *) get_writable_address(sizeof(*data));
		data->effective = rand32();
		data->permitted = rand32();
		data->inheritable = rand32();
	} else {
		data = (struct __user_cap_data_struct *) get_writable_address(2 * sizeof(*data));
		data[0].effective = rand32();
		data[0].permitted = rand32();
		data[0].inheritable = rand32();
		data[1].effective = rand32();
		data[1].permitted = rand32();
		data[1].inheritable = rand32();
	}
	rec->a2 = (unsigned long) data;
}

struct syscallentry syscall_capset = {
	.name = "capset",
	.num_args = 2,
	.argname = { [0] = "header", [1] = "data" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.sanitise = sanitise_capset,
};
