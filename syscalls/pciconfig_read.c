/*
   sys_pciconfig_read (unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len,
                       void *buf)
 */
#include "arch.h"
#include "sanitise.h"

static void sanitise_pciconfig_read(struct syscallrecord *rec)
{
	/*
	 * The kernel writes len bytes of PCI config space into buf (a5).
	 * ARG_ADDRESS draws from the random pool, so a fuzzed pointer can
	 * land inside an alloc_shared region.  a4 (len) is unconstrained
	 * here; clamp the overlap-scan length to a page when len is large
	 * to avoid spurious redirects.
	 */
	avoid_shared_buffer(&rec->a5,
			    (rec->a4 > 0 && rec->a4 <= page_size) ?
				    rec->a4 : page_size);
}

struct syscallentry syscall_pciconfig_read = {
	.name = "pciconfig_read",
	.num_args = 5,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_RANGE, [3] = ARG_LEN, [4] = ARG_ADDRESS },
	.argname = { [0] = "bus", [1] = "dfn", [2] = "off", [3] = "len", [4] = "buf" },
	.arg_params[0].range.low = 0, .arg_params[0].range.hi = 255,
	.arg_params[1].range.low = 0, .arg_params[1].range.hi = 255,
	.arg_params[2].range.low = 0, .arg_params[2].range.hi = 4095,
	.sanitise = sanitise_pciconfig_read,
	.group = GROUP_PROCESS,
};
