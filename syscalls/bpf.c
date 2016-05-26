/*
 * SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)
 */
#include <linux/filter.h>
#include "arch.h"
#include "net.h"
#include "sanitise.h"

enum bpf_cmd {
	BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM, BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY, BPF_PROG_LOAD,
};

static void sanitise_bpf(struct syscallrecord *rec)
{
	unsigned long *ptr = NULL, len = 0;

	switch (rec->a1) {
	case BPF_PROG_LOAD:
		bpf_gen_filter(&ptr, &len);
		rec->a2 = (unsigned long) ptr;
		rec->a3 = len;
		break;
	default:
		break;
	}
}

static void post_bpf(struct syscallrecord *rec)
{
	struct sock_fprog *bpf;

	switch (rec->a1) {
	case BPF_MAP_CREATE:
		//TODO: add fd to local object cache
		break;

	case BPF_PROG_LOAD:
		//TODO: add fd to local object cache
		bpf = (struct sock_fprog *) rec->a2;
		free(&bpf->filter);
		freeptr(&rec->a2);
		break;
	default:
		break;
	}
}

static unsigned long bpf_flags[] = {
	BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM, BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY, BPF_PROG_LOAD,
};

struct syscallentry syscall_bpf = {
	.name = "bpf",
	.num_args = 3,

	.arg1name = "cmd",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(bpf_flags),
	.arg2name = "uattr",
	.arg3name = "size",
	.sanitise = sanitise_bpf,
	.post = post_bpf,
};
