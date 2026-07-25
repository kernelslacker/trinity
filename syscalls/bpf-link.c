/*
 * syscalls/bpf-link.c -- BPF_LINK_* command family sanitisers and
 * post handlers carved out of syscalls/bpf.c.
 *
 * Covers LINK_CREATE, LINK_UPDATE, LINK_DETACH, ITER_CREATE (which
 * consumes a link_fd) and their two post handlers.  The aggregator
 * syscalls/bpf.c dispatches into these via the externs in
 * bpf-internal.h.
 */

#ifdef USE_BPF

#include <linux/bpf.h>

#include "bpf.h"
#include "bpf-internal.h"
#include "objects.h"
#include "publish_resource.h"
#include "rnd.h"
#include "sanitise.h"

void sanitise_bpf_link_create(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->link_create.prog_fd = get_rand_bpf_prog_fd();
	attr->link_create.target_fd = get_rand_bpf_fd();
	attr->link_create.attach_type = bpf_attach_types[rnd_modulo_u32(bpf_attach_types_count)];
	attr->link_create.flags = rnd_modulo_u32(16);
	rec->a3 = sizeof(attr->link_create);
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
