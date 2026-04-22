/*
 * SYSCALL_DEFINE(lookup_dcookie)(u64 cookie64, char __user * buf, size_t len)
 */
#include "arch.h"
#include "sanitise.h"

static void sanitise_lookup_dcookie(struct syscallrecord *rec)
{
	/*
	 * On a successful cookie lookup the kernel writes up to len bytes
	 * of the resolved path into buf (a2).  ARG_ADDRESS draws from the
	 * random pool, so a fuzzed pointer can land inside an alloc_shared
	 * region.  Mirror the readlink/getcwd shape: use a3 if it's set,
	 * otherwise fall back to a page.
	 */
	avoid_shared_buffer(&rec->a2, rec->a3 ? rec->a3 : page_size);
}

struct syscallentry syscall_lookup_dcookie = {
	.name = "lookup_dcookie",
	.num_args = 3,
	.argtype = { [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "cookie64", [1] = "buf", [2] = "len" },
	.sanitise = sanitise_lookup_dcookie,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
};
