/*
 * syscalls/bpf-btf.c -- BPF_BTF_* command family sanitisers and post
 * handler carved out of syscalls/bpf.c.
 *
 * Covers BTF_LOAD (with its BPF_F_TOKEN_FD arm), the cross-family
 * OBJ_GET_INFO_BY_FD dispatcher (which rotates through all four fd
 * pools -- prog, map, link, btf), and post_bpf_btf_fd shared by
 * BTF_LOAD and BTF_GET_FD_BY_ID.  The aggregator syscalls/bpf.c
 * dispatches into these via the externs in bpf-internal.h.
 *
 * OBJ_GET_INFO_BY_FD lives here because BTF is the pool most likely
 * to source a fresh fd for the dispatcher: the other three arms
 * (map / prog / link) already have their own carved TUs, so keeping
 * this alongside the btf pool leaves the aggregator with just the
 * cross-family generic ID ops.
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
#include "shm.h"
#include "trinity.h"
#include "utils.h"

void sanitise_bpf_btf_load(union bpf_attr *attr, struct syscallrecord *rec)
{
	/* Without an explicit case BTF_LOAD falls through to default
	 * with an all-zero attr -- the kernel rejects the empty BTF
	 * blob with -EINVAL at btf_parse(), but the cap check on
	 * btf_token_fd runs before parsing.  Inject the token at the
	 * usual rate so the bpf_token_capable() arm of btf_new_fd()
	 * actually executes. */
	rec->a3 = sizeof(union bpf_attr);
	if (ONE_IN(8)) {
		attr->btf_token_fd = bpf_random_token_fd();
		attr->btf_flags |= BPF_F_TOKEN_FD;
	}
}

void sanitise_bpf_obj_get_info_by_fd(union bpf_attr *attr, struct syscallrecord *rec)
{
	/*
	 * The kernel dispatches to a different obj_get_info_by_fd
	 * implementation per fd type (map / prog / btf / link), each
	 * with its own info struct layout and copy-out path.  Pick
	 * one of the four pools at random, then fall through to any
	 * other non-empty pool so we still produce an fd when the
	 * preferred pool is empty.  All four fd kinds get coverage
	 * once the link / btf pools start filling from the syscall
	 * fuzz path.
	 */
	int fd = -1;
	unsigned int start = rnd_modulo_u32(4);
	unsigned int i;

	for (i = 0; i < 4 && fd == -1; i++) {
		switch ((start + i) % 4) {
		case 0: fd = get_rand_bpf_prog_fd(); break;
		case 1: fd = get_rand_bpf_fd(); break;
		case 2: fd = get_rand_bpf_link_fd(); break;
		case 3: fd = get_rand_bpf_btf_fd(); break;
		}
	}
	attr->info.bpf_fd = fd;
	attr->info.info_len = rnd_modulo_u32(page_size);
	attr->info.info = (u64) get_writable_address(page_size);
	{
		unsigned long info_addr = attr->info.info;
		avoid_shared_buffer_inout(&info_addr, page_size);
		attr->info.info = info_addr;
	}
	rec->a3 = sizeof(attr->info);
}

void post_bpf_btf_fd(int fd)
{
	/*
	 * BTF fd, either freshly parsed from a (typically malformed)
	 * BTF blob or sourced via id-lookup against the kernel's btf
	 * id table.  Feed the per-child BTF pool so the BTF-specific
	 * dispatch in BPF_OBJ_GET_INFO_BY_FD has fds to operate on.
	 */
	if (fd >= 0)
		publish_resource(OBJ_FD_BPF_BTF, fd, NULL);
}

#endif	/* USE_BPF */
