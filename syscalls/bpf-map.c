/*
 * syscalls/bpf-map.c -- BPF_MAP_* command family sanitisers and post handlers.
 * Includes the OBJ_GET arm because its attr layout is the map-fd shape
 * (attr->map_fd + 32-byte a3 window), not a distinct object pool.
 */

#ifdef USE_BPF

#include <linux/bpf.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include "arch.h"
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
 * BPF_F_CPU (8) and BPF_F_ALL_CPUS (16) are for the per-cpu map types and
 * no other (bpf_map_check_op_flags()), and exclude each other: BPF_F_CPU
 * moves the value of the one cpu whose number is in the upper 32 bits of
 * flags, BPF_F_ALL_CPUS sends one value to every cpu.
 * set_rand_bitmask over the non-zero members draws combinations a plain
 * RAND_RANGE(0, 4) never could; draw_update_flags() holds most of them to
 * what the kernel takes.
 */
static const unsigned long bpf_map_update_flags[] = {
	BPF_NOEXIST,
	BPF_EXIST,
	BPF_F_LOCK,
	BPF_F_CPU,
	BPF_F_ALL_CPUS,
};

/* A map's value_size is under 64 KiB, so this holds one value of a map the
 * pool knows nothing of. */
#define ELEM_BUF_GENEROUS	(64 * 1024)

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

static unsigned long map_cpus(void)
{
	static unsigned long cpus;
	long n;

	if (cpus == 0) {
		n = sysconf(_SC_NPROCESSORS_CONF);
		cpus = n > 0 ? n : 1;
	}
	return cpus;
}

/* The map types that keep one value for each possible cpu. */
static bool map_is_percpu(unsigned int type)
{
	return type == BPF_MAP_TYPE_PERCPU_ARRAY ||
	       type == BPF_MAP_TYPE_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE;
}

/*
 * What the kernel moves for a value (bpf_map_value_size()): a per-cpu map
 * moves a row of every possible cpu's value, each rounded up to 8 bytes,
 * unless BPF_F_CPU or BPF_F_ALL_CPUS names one value.  The row of a map
 * with a big value_size is more than the pool holds, so the calls that
 * can name one value do.
 */
static unsigned long map_value_len(const struct bpfobj *map, u64 flags)
{
	if ((flags & (BPF_F_CPU | BPF_F_ALL_CPUS)) ||
	    !map_is_percpu(map->map_type))
		return map->value_size;
	return ((map->value_size + 7UL) & ~7UL) * map_cpus();
}

/*
 * Draw a map from the pool, naming it in attr->map_fd.  Of a map the pool
 * met only by id the pool knows no type, and so no size: its buffers are
 * made generously.  Returns whether the map is a known one.
 */
static bool pick_map(union bpf_attr *attr, struct bpfobj *map)
{
	if (!get_rand_bpf_map(map)) {
		memset(map, 0, sizeof(*map));
		map->map_fd = -1;
	}
	attr->map_fd = map->map_fd;
	return map->map_type != BPF_MAP_TYPE_UNSPEC;
}

/*
 * A buffer for the kernel to read or write through a pointer of the attr,
 * @len bytes and at least a page, so the address scrub finds a whole page of
 * the pool where the pointer is and leaves it.  Its first page is junk: a
 * key or a value the kernel reads, or one it overwrites.  One pointer in
 * thirty-two is no buffer, but an address nothing is mapped at, which is
 * -EFAULT, or -EINVAL for the key of a map that has none.
 */
static u64 elem_buffer(unsigned long len)
{
	unsigned char *buf;

	if (ONE_IN(32))
		return 1 + rnd_modulo_u32(10);

	buf = get_writable_address(len < page_size ? page_size : len);
	if (buf == NULL)
		return 0;
	generate_rand_bytes(buf, page_size);
	return (unsigned long) buf;
}

/*
 * A key.  Seven in eight are a small index, the first byte under 16 and the
 * rest zero, which an array takes as an index, an LPM trie as a prefix
 * length, and calls that follow each other as a key already in a hash.  A
 * map with no key takes none: any pointer for it is -EINVAL
 * (__bpf_copy_key()), so it gets one in thirty-two.  @optional keys may be
 * left out.
 */
static u64 draw_key(const struct bpfobj *map, bool known, bool optional)
{
	unsigned long len = known ? map->key_size : page_size;
	unsigned char *key;

	if (optional && ONE_IN(4))
		return 0;
	if (len == 0)
		return ONE_IN(32) ? 1 + rnd_modulo_u32(10) : 0;

	key = (unsigned char *) elem_buffer(len);
	if (range_in_writable_pool((unsigned long) key, page_size) &&
	    !ONE_IN(8)) {
		memset(key, 0, known ? len : 8);
		key[0] = rnd_modulo_u32(16);
	}
	return (unsigned long) key;
}

static u64 draw_value(const struct bpfobj *map, bool known, u64 flags)
{
	return elem_buffer(known ? map_value_len(map, flags) : ELEM_BUF_GENEROUS);
}

/*
 * BPF_MAP_UPDATE_ELEM flags, from the table.  One draw in sixteen is sent as
 * drawn, to reach what the kernel refuses: both existence flags, a lock on a
 * map whose BTF has no spin lock, a cpu flag on a map that is not per-cpu,
 * both cpu flags.  The rest are held to what bpf_map_check_op_flags() and
 * the update code of the maps take.  BPF_F_CPU carries the number of its cpu
 * in the upper 32 bits of flags, a possible one but for one draw in
 * thirty-two, and a row of cpus too big for the pool is sent as one value.
 */
static u64 draw_update_flags(const struct bpfobj *map, bool known)
{
	u64 flags = set_rand_bitmask(ARRAY_SIZE(bpf_map_update_flags),
				     bpf_map_update_flags);
	bool as_drawn = ONE_IN(16);

	if (!as_drawn) {
		flags &= ~(u64) BPF_F_LOCK;
		if ((flags & BPF_NOEXIST) && (flags & BPF_EXIST))
			flags &= ~(u64) BPF_EXIST;
		if ((flags & BPF_F_CPU) && (flags & BPF_F_ALL_CPUS))
			flags &= ~(u64) BPF_F_ALL_CPUS;
		if (!known || !map_is_percpu(map->map_type))
			flags &= ~(u64) (BPF_F_CPU | BPF_F_ALL_CPUS);
	}

	if (flags & BPF_F_CPU)
		flags |= (ONE_IN(32) ? 0x100000 + rnd_modulo_u32(0x1000) :
			  rnd_modulo_u32(map_cpus())) * (1ULL << 32);
	else if (as_drawn && ONE_IN(4))
		/* A cpu number with no BPF_F_CPU to say it is one. */
		flags |= (u64) rnd_modulo_u32(map_cpus()) << 32;

	if (known && map_value_len(map, flags) > BPF_ELEM_BUF_MAX)
		flags |= BPF_F_ALL_CPUS;
	return flags;
}

/*
 * The flags of a lookup.  BPF_MAP_LOOKUP_ELEM takes BPF_F_CPU, on a per-cpu
 * map; BPF_MAP_LOOKUP_AND_DELETE_ELEM takes none but BPF_F_LOCK, which
 * needs the spin lock a map without BTF does not have.  So both are sent
 * with no flags but for one call in sixteen, which carries one of the
 * update flags, nearly all of them refused here.
 */
static u64 draw_lookup_flags(const struct bpfobj *map, bool known,
			     bool and_delete)
{
	if (ONE_IN(16))
		return RAND_ARRAY(bpf_map_update_flags);
	if (and_delete || !known || !map_is_percpu(map->map_type))
		return 0;

	if (RAND_BOOL() || map_value_len(map, 0) > BPF_ELEM_BUF_MAX)
		return BPF_F_CPU | (ONE_IN(32) ?
				    0x100000 + rnd_modulo_u32(0x1000) :
				    rnd_modulo_u32(map_cpus())) * (1ULL << 32);
	return 0;
}

void sanitise_bpf_map_lookup(union bpf_attr *attr, struct syscallrecord *rec,
			     bool and_delete)
{
	struct bpfobj map;
	bool known = pick_map(attr, &map);

	attr->flags = draw_lookup_flags(&map, known, and_delete);
	attr->key = draw_key(&map, known, false);
	attr->value = draw_value(&map, known, and_delete ? 0 : attr->flags);
	rec->a3 = 32;
}

void sanitise_bpf_map_update(union bpf_attr *attr, struct syscallrecord *rec)
{
	struct bpfobj map;
	bool known = pick_map(attr, &map);

	attr->flags = draw_update_flags(&map, known);
	attr->key = draw_key(&map, known, false);
	attr->value = draw_value(&map, known, attr->flags);
	rec->a3 = 32;
}

void sanitise_bpf_map_delete(union bpf_attr *attr, struct syscallrecord *rec)
{
	struct bpfobj map;
	bool known = pick_map(attr, &map);

	attr->key = draw_key(&map, known, false);
	rec->a3 = 32;
}

/* The key is optional here: none asks for the first one.  The next key is
 * written back, key_size bytes of it. */
void sanitise_bpf_map_get_next_key(union bpf_attr *attr, struct syscallrecord *rec)
{
	struct bpfobj map;
	bool known = pick_map(attr, &map);

	attr->key = draw_key(&map, known, true);
	attr->next_key = elem_buffer(known ? map.key_size : page_size);
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
	struct object *obj;

	if (fd < 0 || !attr_readable)
		return;

	/* The sizes are not in the publish metadata; the element commands
	 * size their buffers by them. */
	obj = publish_resource(OBJ_FD_BPF_MAP, fd,
			       &(struct resource_meta){.subtype = attr->map_type});
	if (obj != NULL) {
		obj->bpfobj.key_size = attr->key_size;
		obj->bpfobj.value_size = attr->value_size;
	}
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
