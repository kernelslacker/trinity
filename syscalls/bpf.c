/*
 * SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)
 */
#include <linux/bpf.h>
#include <linux/filter.h>
#include "arch.h"
#include "net.h"
#include "random.h"
#include "sanitise.h"

static unsigned long bpf_prog_types[] = {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
};

static const char license[] = "GPLv2";

static void bpf_prog_load(struct syscallrecord *rec)
{
	unsigned long *insns = NULL, len = 0;
	union bpf_attr *attr;

	attr = zmalloc(sizeof(union bpf_attr));

	bpf_gen_filter(&insns, &len);

	attr->prog_type = RAND_ARRAY(bpf_prog_types);
	attr->insn_cnt = len;
	attr->insns = (u64) insns;
	attr->license = (u64) license;
	attr->log_level = 0;
	attr->log_size = rnd() % page_size;
	attr->log_buf = (u64) get_writable_address(page_size);
//	attr->kern_version = TODO: stick uname in here.

	rec->a2 = (unsigned long) attr;
	rec->a3 = sizeof(attr);
}

static void sanitise_bpf(struct syscallrecord *rec)
{
	switch (rec->a1) {
	case BPF_PROG_LOAD:
		bpf_prog_load(rec);
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
