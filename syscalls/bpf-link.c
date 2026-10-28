/*
 * syscalls/bpf-link.c -- BPF_LINK_* command family sanitisers and post
 * handlers: LINK_CREATE, LINK_UPDATE, LINK_DETACH and ITER_CREATE (which
 * consumes a link_fd).
 */

#ifdef USE_BPF

#include <linux/bpf.h>

#include "bpf.h"
#include "bpf-internal.h"
#include "objects.h"
#include "publish_resource.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

/*
 * An attach type link_create() (kernel/bpf/syscall.c) pairs with @prog: its
 * bpf_prog_attach_check_attach_type() holds a cgroup sock, sock addr,
 * sockopt or sk_lookup program, and the tracing and LSM takers a tracing or
 * LSM one, to the attach type it was loaded for, and lets each other type
 * that has a taker through on one to four attach types of its own.  False
 * for a program no link takes.
 */
static bool pick_link_attach_type(const struct bpfprogobj *prog,
				  unsigned int *type)
{
	static const unsigned int sk_skb[] = {
		BPF_SK_SKB_STREAM_PARSER, BPF_SK_SKB_STREAM_VERDICT,
		BPF_SK_SKB_VERDICT,
	};
	static const unsigned int sched_cls[] = {
		BPF_TCX_INGRESS, BPF_TCX_EGRESS,
		BPF_NETKIT_PRIMARY, BPF_NETKIT_PEER,
	};

	switch (prog->prog_type) {
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
	case BPF_PROG_TYPE_SK_LOOKUP:
	case BPF_PROG_TYPE_TRACING:
	case BPF_PROG_TYPE_LSM:
		*type = prog->expected_attach_type;
		return true;
	case BPF_PROG_TYPE_KPROBE:
		switch (prog->expected_attach_type) {
		case BPF_TRACE_KPROBE_MULTI:
		case BPF_TRACE_KPROBE_SESSION:
		case BPF_TRACE_UPROBE_MULTI:
		case BPF_TRACE_UPROBE_SESSION:
			*type = prog->expected_attach_type;
			return true;
		}
		*type = BPF_PERF_EVENT;
		return true;
	case BPF_PROG_TYPE_PERF_EVENT:
	case BPF_PROG_TYPE_TRACEPOINT:
		*type = BPF_PERF_EVENT;
		return true;
	case BPF_PROG_TYPE_CGROUP_SKB:
		/* Held to the attach type it was loaded for only when the
		 * verifier saw it return what one of the two alone takes. */
		*type = RAND_BOOL() ? BPF_CGROUP_INET_INGRESS :
				      BPF_CGROUP_INET_EGRESS;
		return true;
	case BPF_PROG_TYPE_SOCK_OPS:
		*type = BPF_CGROUP_SOCK_OPS;
		return true;
	case BPF_PROG_TYPE_CGROUP_DEVICE:
		*type = BPF_CGROUP_DEVICE;
		return true;
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
		*type = BPF_CGROUP_SYSCTL;
		return true;
	case BPF_PROG_TYPE_SK_MSG:
		*type = BPF_SK_MSG_VERDICT;
		return true;
	case BPF_PROG_TYPE_SK_SKB:
		*type = RAND_ARRAY(sk_skb);
		return true;
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
		*type = BPF_FLOW_DISSECTOR;
		return true;
	case BPF_PROG_TYPE_XDP:
		*type = BPF_XDP;
		return true;
	case BPF_PROG_TYPE_SCHED_CLS:
		*type = RAND_ARRAY(sched_cls);
		return true;
	case BPF_PROG_TYPE_NETFILTER:
		*type = BPF_NETFILTER;
		return true;
	default:
		return false;
	}
}

void sanitise_bpf_link_create(union bpf_attr *attr, struct syscallrecord *rec)
{
	struct bpfprogobj prog;
	unsigned int type;
	bool have_prog;

	/*
	 * bpf_prog_attach_check_attach_type() turns away an attach type the
	 * program does not pair with before any taker runs, so the attach
	 * type is one the program pairs with but one draw in eight, which
	 * takes any.  The catalog fills the tail of the arm it names and
	 * sizes the call; the other head fields come from the bpf pools.
	 */
	have_prog = get_rand_bpf_prog(&prog);
	attr->link_create.prog_fd = have_prog ? prog.fd : -1;
	if (have_prog && !ONE_IN(8) && pick_link_attach_type(&prog, &type))
		attr->link_create.attach_type = type;
	else
		attr->link_create.attach_type =
			bpf_attach_types[rnd_modulo_u32(bpf_attach_types_count)];
	sanitise_bpf_nested(attr, rec);
	attr->link_create.target_fd = get_rand_bpf_fd();
	attr->link_create.flags = rnd_modulo_u32(16);

	/*
	 * link_create() hands the attr to the program's taker, which answers
	 * -EINVAL to a head field it has no use for: bpf_iter_link_attach()
	 * and bpf_tracing_multi_attach() to a target_fd or flags, and the
	 * perf, kprobe_multi, uprobe_multi, netfilter, netns and sockmap
	 * takers to flags.  bpf_tracing_prog_attach() takes target_fd and
	 * target_btf_id together, a program and a btf id in it, or neither
	 * for the target the program was loaded with, which most calls name;
	 * its cookie, which helpers read back uninterpreted and the catalog
	 * leaves at zero as it does every wide raw field, is drawn too.
	 */
	switch (attr->link_create.attach_type) {
	case BPF_TRACE_ITER:
	case BPF_TRACE_FENTRY_MULTI:
	case BPF_TRACE_FEXIT_MULTI:
	case BPF_TRACE_FSESSION_MULTI:
		attr->link_create.target_fd = 0;
		/* fall through */
	case BPF_PERF_EVENT:
	case BPF_TRACE_KPROBE_MULTI:
	case BPF_TRACE_KPROBE_SESSION:
	case BPF_TRACE_UPROBE_MULTI:
	case BPF_TRACE_UPROBE_SESSION:
	case BPF_NETFILTER:
	case BPF_FLOW_DISSECTOR:
	case BPF_SK_LOOKUP:
	case BPF_SK_SKB_STREAM_PARSER:
	case BPF_SK_SKB_STREAM_VERDICT:
	case BPF_SK_SKB_VERDICT:
	case BPF_SK_MSG_VERDICT:
		attr->link_create.flags = 0;
		break;
	case BPF_TRACE_FENTRY:
	case BPF_TRACE_FEXIT:
	case BPF_MODIFY_RETURN:
	case BPF_LSM_MAC:
	case BPF_TRACE_FSESSION:
		if (ONE_IN(8)) {
			attr->link_create.target_fd = get_rand_bpf_prog_fd();
			if (attr->link_create.target_btf_id == 0)
				attr->link_create.target_btf_id = 1;
		} else {
			attr->link_create.target_fd = 0;
			attr->link_create.target_btf_id = 0;
		}
		attr->link_create.tracing.cookie = rnd_u64();
		break;
	}
}

void sanitise_bpf_link_update(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->link_update.link_fd = get_rand_bpf_link_fd();
	attr->link_update.new_prog_fd = get_rand_bpf_prog_fd();
	attr->link_update.flags = rnd_modulo_u32(4);
	rec->a3 = sizeof(attr->link_update);
}

void sanitise_bpf_link_detach(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->link_detach.link_fd = get_rand_bpf_link_fd();
	rec->a3 = 4;
}

void sanitise_bpf_iter_create(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->iter_create.link_fd = get_rand_bpf_link_fd();
	attr->iter_create.flags = 0;
	rec->a3 = sizeof(attr->iter_create);
}

void post_bpf_link_create(int fd, bool attr_readable, union bpf_attr *attr)
{
	/*
	 * Live link fd — feed the per-child link pool so subsequent
	 * BPF_LINK_UPDATE / BPF_LINK_DETACH / BPF_ITER_CREATE calls
	 * pick it up via get_rand_bpf_link_fd() and reach the link
	 * dispatch paths instead of bouncing on EINVAL from a
	 * type-confused map fd.
	 */
	if (fd >= 0 && attr_readable)
		publish_resource(OBJ_FD_BPF_LINK, fd,
				 &(struct resource_meta){.subtype = attr->link_create.attach_type});
}

void post_bpf_link_get_fd_by_id(int fd)
{
	/*
	 * Same fd kind as LINK_CREATE returns, sourced via id-lookup.
	 * Attach type unknown at lookup time — leave it 0; it's
	 * metadata only.
	 */
	if (fd >= 0)
		publish_resource(OBJ_FD_BPF_LINK, fd, NULL);
}

#endif	/* USE_BPF */
