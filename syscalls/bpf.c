/*
 * SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)
 */
#include "sanitise.h"

enum bpf_cmd {
	BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM, BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY, BPF_PROG_LOAD,
};

// TODO: sanitize = allocate a page, and use bpf_gen_filter to generate something legit.

struct syscallentry syscall_bpf = {
	.name = "bpf",
	.num_args = 3,

	.arg1name = "cmd",
	.arg1type = ARG_OP,
	.arg1list = {
		.num = 6,
		.values = {
			BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM, BPF_MAP_DELETE_ELEM,
			BPF_MAP_GET_NEXT_KEY, BPF_PROG_LOAD,
		},
	},
	.arg2name = "uattr",
	.arg2type = ARG_ADDRESS,
	.arg3name = "size",
	.arg3type = ARG_LEN,
};
