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

void sanitise_bpf_link_create(union bpf_attr *attr, struct syscallrecord *rec)
{
	/*
	 * The attach type, the tail of the link_create arm it names and the
	 * size of the call are the catalog's.  The head fields the catalog
	 * fills as well, with a generic fd and raw flags, are drawn again from
	 * the bpf pools.
	 */
	sanitise_bpf_default(attr, rec);
	attr->link_create.prog_fd = get_rand_bpf_prog_fd();
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
