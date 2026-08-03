/*
 * syscalls/bpf-map.c -- BPF_MAP_* command family sanitisers and post
 * handlers carved out of syscalls/bpf.c.
 *
 * Includes the OBJ_GET arm because its attr layout is the map-fd
 * shape (attr->map_fd + 32-byte a3 window), not a distinct object
 * pool.  The aggregator syscalls/bpf.c dispatches into these via the
 * externs in bpf-internal.h.
 */

#ifdef USE_BPF

#include <linux/bpf.h>
#include <stddef.h>

#include "bpf.h"
#include "bpf-internal.h"
#include "objects.h"
#include "publish_resource.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

/*
 * Full set of BPF_MAP_CREATE flags so set_rand_bitmask can generate
 * composite values that reach every flag bit, not just bits 0-2.
 * BPF_F_TOKEN_FD (bit 16) is excluded here because the token-fd arm
 * in sanitise_bpf_map_create handles it with dedicated logic below.
 */
static const unsigned long bpf_map_create_flags[] = {
	BPF_F_NO_PREALLOC,
	BPF_F_NO_COMMON_LRU,
	BPF_F_NUMA_NODE,
	BPF_F_RDONLY,
	BPF_F_WRONLY,
	BPF_F_STACK_BUILD_ID,
	BPF_F_ZERO_SEED,
	BPF_F_RDONLY_PROG,
	BPF_F_WRONLY_PROG,
	BPF_F_CLONE,
	BPF_F_MMAPABLE,
	BPF_F_PRESERVE_ELEMS,
	BPF_F_INNER_MAP,
	BPF_F_LINK,
	BPF_F_PATH_FD,
	BPF_F_VTYPE_BTF_OBJ_FD,
	BPF_F_SEGV_ON_FAULT,
	BPF_F_NO_USER_CONV,
};

/*
 * BPF_MAP_UPDATE_ELEM flags.  BPF_ANY (0), BPF_NOEXIST (1), and
 * BPF_EXIST (2) encode the existence policy; BPF_F_LOCK (4) is an
 * orthogonal spin-lock flag that may be combined with any policy.
 * Using set_rand_bitmask over the non-zero members generates all
 * valid combinations including NOEXIST|LOCK and EXIST|LOCK that a
 * plain RAND_RANGE(0, 4) can never produce.
 */
static const unsigned long bpf_map_update_flags[] = {
	BPF_NOEXIST,
	BPF_EXIST,
	BPF_F_LOCK,
};

void sanitise_bpf_map_create(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_type = bpf_map_types[rnd_modulo_u32(bpf_map_types_count)];
	attr->key_size = rnd_modulo_u32(1024);
	attr->value_size = rnd_modulo_u32((1024 * 64));
	attr->max_entries = rnd_modulo_u32(1024);
	attr->map_flags = set_rand_bitmask(ARRAY_SIZE(bpf_map_create_flags),
					   bpf_map_create_flags);
	bpf_fill_obj_name(attr->map_name);
	/* Cover map_name so the fill above reaches the kernel; previous
	 * rec->a3 = 20 stopped at map_flags.  The token-fd arm below
	 * overrides this with a still-larger window that already
	 * encompasses map_name. */
	rec->a3 = offsetof(union bpf_attr, map_name) +
		  sizeof(attr->map_name);
	if (ONE_IN(8)) {
		/* BPF_F_TOKEN_FD in map_flags is the gate the kernel
		 * uses to decide whether to resolve map_token_fd at
		 * all; without it the token fd is ignored and
		 * bpf_token_capable() never runs.  Bump rec->a3 to
		 * cover map_token_fd so the kernel reads the slot
		 * we just wrote. */
		attr->map_token_fd = bpf_random_token_fd();
		attr->map_flags |= BPF_F_TOKEN_FD;
		rec->a3 = offsetof(union bpf_attr, map_token_fd) +
			  sizeof(attr->map_token_fd);
	}
}

void sanitise_bpf_map_lookup(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_fd = get_rand_bpf_fd();
	attr->key = RAND_RANGE(0, 10);
	attr->value = rnd_u32();
	rec->a3 = 32;
}

void sanitise_bpf_map_update(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_fd = get_rand_bpf_fd();
	attr->key = RAND_RANGE(0, 10);
	attr->value = rnd_u32();
	attr->next_key = rnd_u32();
	attr->flags = set_rand_bitmask(ARRAY_SIZE(bpf_map_update_flags),
				       bpf_map_update_flags);
	rec->a3 = 32;
}

void sanitise_bpf_map_delete(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_fd = get_rand_bpf_fd();
	attr->key = RAND_RANGE(0, 10);
	rec->a3 = 32;
}

void sanitise_bpf_map_get_next_key(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_fd = get_rand_bpf_fd();
	attr->key = RAND_RANGE(0, 10);
	attr->value = rnd_u32();
	rec->a3 = 32;
}

void sanitise_bpf_map_freeze(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_fd = get_rand_bpf_fd();
	rec->a3 = 4;
}

void sanitise_bpf_obj_get(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_fd = get_rand_bpf_fd();
	rec->a3 = 32;
}

void post_bpf_map_create(int fd, bool attr_readable, union bpf_attr *attr)
{
	if (fd >= 0 && attr_readable)
		publish_resource(OBJ_FD_BPF_MAP, fd,
				 &(struct resource_meta){.subtype = attr->map_type});
}

void post_bpf_map_get_fd_by_id(int fd)
{
	/*
	 * Looked-up map fd is the same kind of object as one fresh
	 * from BPF_MAP_CREATE — just sourced via id-lookup against
	 * the kernel's id table.  Publish into the per-child pool so
	 * subsequent map-fd consumers (LOOKUP_ELEM, UPDATE_ELEM,
	 * FREEZE, etc.) can pick it up.  Map type is unknown at this
	 * point; leaving it as BPF_MAP_TYPE_UNSPEC just makes the
	 * dump output read "unknown" — no behavioural impact since
	 * map_type is metadata only.
	 */
	if (fd >= 0)
		publish_resource(OBJ_FD_BPF_MAP, fd, NULL);
}

#endif	/* USE_BPF */
