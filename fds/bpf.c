/* bpf FDs */

#ifdef USE_BPF

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <linux/perf_event.h>

#include "bpf.h"
#include "syscall-gate.h"
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/socket.h"
static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return trinity_raw_syscall(__NR_bpf, cmd, attr, size);
}

static int bpf_create_map(enum bpf_map_type map_type, unsigned int key_size,
			unsigned int value_size, unsigned int max_entries, int map_flags)
{
	union bpf_attr attr = {
		.map_type    = map_type,
		.key_size    = key_size,
		.value_size  = value_size,
		.max_entries = max_entries,
		.map_flags   = map_flags,
	};

	return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}


struct bpf_fd_types {
	u32 map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 flags;
	char name[32];
};

static struct bpf_fd_types bpf_fds[] = {
	{ BPF_MAP_TYPE_HASH, sizeof(long long), sizeof(long long), 1024, 0, "hash" },
	{ BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(long long), 256, 0, "array" },
	{ BPF_MAP_TYPE_PROG_ARRAY, sizeof(int), sizeof(int), 4, 0, "prog_array" },
	{ BPF_MAP_TYPE_PERF_EVENT_ARRAY, sizeof(int), sizeof(u32), 32, 0, "perf event array" },
	{ BPF_MAP_TYPE_PERCPU_HASH, sizeof(u32), sizeof(u64) * PERF_MAX_STACK_DEPTH, 10000, 0, "percpu hash" },
	{ BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(u32), sizeof(u64), 100, 0, "percpu array" },
	{ BPF_MAP_TYPE_STACK_TRACE, sizeof(u32), sizeof(u64), 100, 0, "stack trace" },
	{ BPF_MAP_TYPE_CGROUP_ARRAY, sizeof(u32), sizeof(u32), 1, 0, "cgroup array" },
	{ BPF_MAP_TYPE_LRU_HASH, sizeof(u32), sizeof(long), 10000, 0, "LRU hash" },
	{ BPF_MAP_TYPE_LRU_HASH, sizeof(u32), sizeof(long), 10000, BPF_F_NO_COMMON_LRU, "LRU hash (no common LRU)" },
	{ BPF_MAP_TYPE_LRU_PERCPU_HASH, sizeof(u32), sizeof(long), 1000, 0, "LRU percpu hash" },
	{ BPF_MAP_TYPE_LPM_TRIE, 8, sizeof(long), 10000, 0, "LPM TRIE" },
	{ BPF_MAP_TYPE_RINGBUF, 0, 0, 4096, 0, "ringbuf" },
	{ BPF_MAP_TYPE_BLOOM_FILTER, 0, sizeof(u32), 100, 0, "bloom filter" },
	{ BPF_MAP_TYPE_USER_RINGBUF, 0, 0, 4096, 0, "user ringbuf" },
	{ BPF_MAP_TYPE_ARENA, 0, 0, 4096, 0, "arena" },
};

/*
 * Cross-process safe: reads obj->bpfobj scalar fields and looks up the
 * map type name from the static bpf_fds[] table.  The scalars survive
 * fork/COW and no process-local pointers are dereferenced, so it is
 * correct to call this from a different process than the allocator.
 */
static void bpf_map_dump(struct object *obj, enum obj_scope scope)
{
	u32 type = obj->bpfobj.map_type;
	const char *name = "unknown";
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(bpf_fds); i++) {
		if (bpf_fds[i].map_type == type) {
			name = bpf_fds[i].name;
			break;
		}
	}

	output(2, "bpf map fd:%d type:%s scope:%d\n",
		obj->bpfobj.map_fd, name, scope);
}

static int open_bpf_fd(void)
{
	struct object *obj;
	unsigned int idx;
	int fd;

	idx = rnd_modulo_u32(ARRAY_SIZE(bpf_fds));
	fd = bpf_create_map(bpf_fds[idx].map_type, bpf_fds[idx].key_size,
			    bpf_fds[idx].value_size, bpf_fds[idx].max_entries,
			    bpf_fds[idx].flags);
	if (fd < 0)
		return false;

	obj = alloc_object();
	if (obj == NULL) {
		close(fd);
		return false;
	}
	obj->bpfobj.map_fd = fd;
	obj->bpfobj.map_type = bpf_fds[idx].map_type;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_BPF_MAP);
	__atomic_add_fetch(&shm->stats.ebpf_gen.maps_provided, 1, __ATOMIC_RELAXED);
	return true;
}

static int init_bpf_fds(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_BPF_MAP);
	head->destroy = &close_fd_destructor;
	head->dump = &bpf_map_dump;
	/*
	 * bpfobj is {u32 map_type; int map_fd;} with no pointer members,
	 * so the OBJ_GLOBAL pool's scalars stay valid across fork/COW and
	 * cross-process reads (dump, lockless slot pick) are safe.
	 */

	for (i = 0; i < ARRAY_SIZE(bpf_fds); i++)
		open_bpf_fd();

	return true;
}

int get_rand_bpf_fd(void)
{
	struct objhead *local;

	/*
	 * Coin-flip preference for the per-child local pool first.  Map
	 * fds get added to OBJ_LOCAL by post_bpf (BPF_MAP_CREATE) and by
	 * the bpf_lifecycle childop, but until now nothing read from
	 * there — every consumer landed on OBJ_GLOBAL with the static
	 * provider templates.  Probabilistic preference keeps both pools
	 * feeding the syscall sanitiser so freshly-created fds with
	 * partially-mutated map state can race the static templates and
	 * the lifecycle teardown.  Falls through to global on miss so
	 * children with empty local pools still see the templates.
	 *
	 * get_objhead(OBJ_LOCAL, ...) returns NULL outside child context;
	 * guard the lookup so non-child callers (init, regeneration in
	 * the parent) safely fall through to the global pool.
	 *
	 * OBJ_LOCAL is per-child and not subject to the lockless-reader
	 * UAF window that the version-validated object-slot read guards
	 * against (cf. get_rand_socketinfo in fds/sockets.c), so the
	 * local pick stays unguarded; only the OBJ_GLOBAL fallback below
	 * gets the slot-version validation wireup.
	 */
	local = get_objhead(OBJ_LOCAL, OBJ_FD_BPF_MAP);
	if (local != NULL && local->num_entries > 0 && RAND_BOOL()) {
		struct object *obj = get_random_object(OBJ_FD_BPF_MAP,
						       OBJ_LOCAL);
		if (objpool_check(obj, OBJ_FD_BPF_MAP))
			return obj->bpfobj.map_fd;
	}

	if (objects_empty(OBJ_FD_BPF_MAP) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->bpfobj.map_fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window: between the lockless slot pick and the
	 * consumer's read of the bpf map fd handed to BPF_MAP_LOOKUP_ELEM
	 * etc., the parent can destroy the obj; release_obj() zeroes the
	 * chunk and routes it through deferred-free, so the stale slot
	 * pointer can read a zeroed or recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_BPF_MAP, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_BPF_MAP))
			continue;

		fd = obj->bpfobj.map_fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider bpf_map_fd_provider = {
	.name = "bpf-map",
	.objtype = OBJ_FD_BPF_MAP,
	.enabled = true,
	.init = &init_bpf_fds,
	.get = &get_rand_bpf_fd,
};

REG_FD_PROV(bpf_map_fd_provider);

/*
 * BPF program fd provider.
 *
 * Loads a small set of verifier-clean template programs at startup
 * (one per supported program type) and publishes the resulting fds
 * into the global object pool.  Other syscalls — setsockopt with
 * SO_ATTACH_BPF, perf_event_open + PERF_EVENT_IOC_SET_BPF, the
 * bpf(PROG_ATTACH/LINK_CREATE) commands, etc. — pull these fds via
 * get_rand_bpf_prog_fd() and end up exercising the cross-subsystem
 * paths that hold most live BPF CVEs.
 *
 * Capability gates reject most program types when trinity runs
 * unprivileged; the init loop tries each template and keeps whichever
 * successfully loaded.  ENOSYS on any attempt latches the whole
 * provider off (kernel built without BPF).  EPERM/EACCES on a single
 * type just skips that template.
 */
struct bpf_prog_template {
	u32 prog_type;
	const char *name;
};

static struct bpf_prog_template bpf_prog_templates[] = {
	{ BPF_PROG_TYPE_SOCKET_FILTER,	"socket_filter" },
	{ BPF_PROG_TYPE_KPROBE,		"kprobe" },
	{ BPF_PROG_TYPE_TRACEPOINT,	"tracepoint" },
	{ BPF_PROG_TYPE_CGROUP_SKB,	"cgroup_skb" },
	{ BPF_PROG_TYPE_CGROUP_SOCK,	"cgroup_sock" },
	{ BPF_PROG_TYPE_XDP,		"xdp" },
	{ BPF_PROG_TYPE_PERF_EVENT,	"perf_event" },
	{ BPF_PROG_TYPE_RAW_TRACEPOINT,	"raw_tracepoint" },
	{ BPF_PROG_TYPE_SCHED_CLS,	"sched_cls" },
	{ BPF_PROG_TYPE_SCHED_ACT,	"sched_act" },
};

#define MAX_BPF_PROG_FDS	10

static const char bpf_prog_license[] = "GPL";

static int bpf_load_template_prog(unsigned int prog_type)
{
	/*
	 * The minimal verifier-clean program: r0 = 0; exit.
	 * Two instructions, no helper calls, no map references — passes
	 * every prog type that doesn't require a BTF attach target.
	 */
	struct bpf_insn insns[] = {
		EBPF_MOV64_IMM(BPF_REG_0, 0),
		EBPF_EXIT(),
	};
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = prog_type;
	attr.insn_cnt = ARRAY_SIZE(insns);
	attr.insns = (u64)(uintptr_t)insns;
	attr.license = (u64)(uintptr_t)bpf_prog_license;

	return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static const char *bpf_prog_template_name(u32 prog_type)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(bpf_prog_templates); i++)
		if (bpf_prog_templates[i].prog_type == prog_type)
			return bpf_prog_templates[i].name;
	return "unknown";
}

/*
 * Cross-process safe: reads obj->bpfprogobj scalar fields and looks up
 * the prog type name from the static bpf_prog_templates[] table.  The
 * scalars survive fork/COW and no process-local pointers are
 * dereferenced, so it is correct to call this from a different process
 * than the allocator.
 */
static void bpf_prog_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "bpf prog fd:%d type:%s scope:%d\n",
		obj->bpfprogobj.fd,
		bpf_prog_template_name(obj->bpfprogobj.prog_type),
		scope);
}

static int init_bpf_prog_fds(void)
{
	struct objhead *head;
	unsigned int i;
	unsigned int loaded = 0;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_BPF_PROG);
	head->destroy = &close_fd_destructor;
	head->dump = &bpf_prog_dump;
	/*
	 * bpfprogobj is {int fd; u32 prog_type;} with no pointer members,
	 * so the OBJ_GLOBAL pool's scalars stay valid across fork/COW and
	 * cross-process reads are safe.
	 */

	for (i = 0; i < ARRAY_SIZE(bpf_prog_templates); i++) {
		struct object *obj;
		int fd;

		fd = bpf_load_template_prog(bpf_prog_templates[i].prog_type);
		if (fd < 0) {
			/*
			 * ENOSYS = no BPF in this kernel; fail the whole
			 * provider so we don't keep retrying for nothing.
			 * EPERM/EACCES = capability gate on this prog type
			 * specifically; skip it and move on.
			 */
			if (errno == ENOSYS)
				return false;
			continue;
		}

		obj = alloc_object();
		if (obj == NULL) {
			close(fd);
			continue;
		}
		obj->bpfprogobj.fd = fd;
		obj->bpfprogobj.prog_type = bpf_prog_templates[i].prog_type;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_BPF_PROG);
		__atomic_add_fetch(&shm->stats.ebpf_gen.progs_provided, 1,
				   __ATOMIC_RELAXED);
		loaded++;

		if (loaded >= MAX_BPF_PROG_FDS)
			break;
	}

	return true;
}

int get_rand_bpf_prog_fd(void)
{
	struct objhead *local;

	/* See get_rand_bpf_fd() for why we coin-flip OBJ_LOCAL first.
	 * OBJ_LOCAL is per-child and unaffected by the lockless-reader
	 * UAF window that the version-validated object-slot read guards
	 * against (cf. get_rand_socketinfo in fds/sockets.c), so only the
	 * OBJ_GLOBAL fallback below gets the slot-version validation
	 * wireup. */
	local = get_objhead(OBJ_LOCAL, OBJ_FD_BPF_PROG);
	if (local != NULL && local->num_entries > 0 && RAND_BOOL()) {
		struct object *obj = get_random_object(OBJ_FD_BPF_PROG,
						       OBJ_LOCAL);
		if (objpool_check(obj, OBJ_FD_BPF_PROG))
			return obj->bpfprogobj.fd;
	}

	if (objects_empty(OBJ_FD_BPF_PROG) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->bpfprogobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window: between the lockless slot pick and the
	 * consumer's read of the bpf prog fd handed to BPF_PROG_RUN /
	 * BPF_PROG_TEST_RUN / BPF_LINK_CREATE, the parent can destroy the
	 * obj; release_obj() zeroes the chunk and routes it through
	 * deferred-free, so the stale slot pointer can read a zeroed or
	 * recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_BPF_PROG, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_BPF_PROG))
			continue;

		fd = obj->bpfprogobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider bpf_prog_fd_provider = {
	.name = "bpf-prog",
	.objtype = OBJ_FD_BPF_PROG,
	.enabled = true,
	.init = &init_bpf_prog_fds,
	.get = &get_rand_bpf_prog_fd,
};

REG_FD_PROV(bpf_prog_fd_provider);

/*
 * BPF link fd provider.
 *
 * Links are bpf-prog-attachment handles returned by BPF_LINK_CREATE
 * (and by BPF_LINK_GET_FD_BY_ID looking up an existing link by id).
 * They underpin BPF_LINK_UPDATE / BPF_LINK_DETACH / BPF_ITER_CREATE
 * and the LINK info-by-fd dispatch path inside BPF_OBJ_GET_INFO_BY_FD.
 *
 * No init seeding: a successful BPF_LINK_CREATE needs a (prog_fd,
 * target_fd, attach_type) triple where the kernel hook actually
 * accepts that combination, and most attach types either need
 * privileges trinity doesn't have or attach targets we don't model.
 * The pool fills lazily as the syscall fuzz path lands successful
 * LINK_CREATE / LINK_GET_FD_BY_ID calls — same lazy-fill pattern as
 * the per-child pool entries the existing map / prog providers
 * rely on.  .open is left NULL for the same reason.
 */
/*
 * Cross-process safe: reads obj->bpflinkobj scalar fields and the scope
 * scalar.  These survive fork/COW and no process-local pointers are
 * dereferenced.
 */
static void bpf_link_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "bpf link fd:%d attach_type:%u scope:%d\n",
		obj->bpflinkobj.fd,
		obj->bpflinkobj.attach_type,
		scope);
}

static int init_bpf_link_fds(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_BPF_LINK);
	head->destroy = &close_fd_destructor;
	head->dump = &bpf_link_dump;
	/*
	 * bpflinkobj is {int fd; u32 attach_type;} with no pointer members,
	 * so the OBJ_GLOBAL pool's scalars stay valid across fork/COW and
	 * cross-process reads are safe.
	 */

	return true;
}

int get_rand_bpf_link_fd(void)
{
	struct objhead *local;

	/* See get_rand_bpf_fd() for why we coin-flip OBJ_LOCAL first.
	 * OBJ_LOCAL is per-child and unaffected by the lockless-reader
	 * UAF window that the version-validated object-slot read guards
	 * against (cf. get_rand_socketinfo in fds/sockets.c), so only the
	 * OBJ_GLOBAL fallback below gets the slot-version validation
	 * wireup. */
	local = get_objhead(OBJ_LOCAL, OBJ_FD_BPF_LINK);
	if (local != NULL && local->num_entries > 0 && RAND_BOOL()) {
		struct object *obj = get_random_object(OBJ_FD_BPF_LINK,
						       OBJ_LOCAL);
		if (objpool_check(obj, OBJ_FD_BPF_LINK))
			return obj->bpflinkobj.fd;
	}

	if (objects_empty(OBJ_FD_BPF_LINK) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->bpflinkobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window: between the lockless slot pick and the
	 * consumer's read of the bpf link fd handed to BPF_LINK_UPDATE /
	 * BPF_LINK_DETACH / BPF_LINK_GET_FD_BY_ID, the parent can destroy
	 * the obj; release_obj() zeroes the chunk and routes it through
	 * deferred-free, so the stale slot pointer can read a zeroed or
	 * recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_BPF_LINK, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_BPF_LINK))
			continue;

		fd = obj->bpflinkobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider bpf_link_fd_provider = {
	.name = "bpf-link",
	.objtype = OBJ_FD_BPF_LINK,
	.enabled = true,
	.init = &init_bpf_link_fds,
	.get = &get_rand_bpf_link_fd,
};

REG_FD_PROV(bpf_link_fd_provider);

/*
 * BPF BTF fd provider.
 *
 * BTF fds come from BPF_BTF_LOAD (parse a BTF blob) and from
 * BPF_BTF_GET_FD_BY_ID (look up an existing kernel/module BTF).
 * They feed BPF_OBJ_GET_INFO_BY_FD's BTF dispatch path so the
 * kernel's btf_get_info_by_fd() runs against real BTF objects
 * instead of EBADFD-bouncing on a type-confused fd.
 *
 * No init seeding: BPF_BTF_LOAD wants a well-formed BTF binary
 * (header + type table + string table), and trinity has no BTF
 * generator.  BPF_BTF_GET_FD_BY_ID could in theory probe the
 * kernel's vmlinux BTF (id 1 on most kernels), but that's a
 * speculative cross-platform assumption and the syscall fuzz path
 * gets there anyway via random id probing.
 */
static void bpf_btf_destructor(struct object *obj)
{
	close(obj->bpfbtfobj.fd);
}

/*
 * Cross-process safe: reads obj->bpfbtfobj.fd and the scope scalar.
 * These survive fork/COW and no process-local pointers are
 * dereferenced.
 */
static void bpf_btf_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "bpf btf fd:%d scope:%d\n", obj->bpfbtfobj.fd, scope);
}

static int init_bpf_btf_fds(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_BPF_BTF);
	head->destroy = &bpf_btf_destructor;
	head->dump = &bpf_btf_dump;
	/*
	 * bpfbtfobj is {int fd;} with no pointer members, so the
	 * OBJ_GLOBAL pool's scalars stay valid across fork/COW and
	 * cross-process reads are safe.
	 */

	return true;
}

int get_rand_bpf_btf_fd(void)
{
	struct objhead *local;

	/* See get_rand_bpf_fd() for why we coin-flip OBJ_LOCAL first.
	 * OBJ_LOCAL is per-child and unaffected by the lockless-reader
	 * UAF window that the version-validated object-slot read guards
	 * against (cf. get_rand_socketinfo in fds/sockets.c), so only the
	 * OBJ_GLOBAL fallback below gets the slot-version validation
	 * wireup. */
	local = get_objhead(OBJ_LOCAL, OBJ_FD_BPF_BTF);
	if (local != NULL && local->num_entries > 0 && RAND_BOOL()) {
		struct object *obj = get_random_object(OBJ_FD_BPF_BTF,
						       OBJ_LOCAL);
		if (objpool_check(obj, OBJ_FD_BPF_BTF))
			return obj->bpfbtfobj.fd;
	}

	if (objects_empty(OBJ_FD_BPF_BTF) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->bpfbtfobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window: between the lockless slot pick and the
	 * consumer's read of the BTF fd routed into
	 * BPF_OBJ_GET_INFO_BY_FD, the parent can destroy the obj;
	 * release_obj() zeroes the chunk and routes it through
	 * deferred-free, so the stale slot pointer can read a zeroed or
	 * recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_BPF_BTF, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_BPF_BTF))
			continue;

		fd = obj->bpfbtfobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider bpf_btf_fd_provider = {
	.name = "bpf-btf",
	.objtype = OBJ_FD_BPF_BTF,
	.enabled = true,
	.init = &init_bpf_btf_fds,
	.get = &get_rand_bpf_btf_fd,
};

REG_FD_PROV(bpf_btf_fd_provider);

/*
 * BPF token fd provider.
 *
 * Token fds come from BPF_TOKEN_CREATE against a bpffs mount that has
 * the per-cmd delegate_{cmds,maps,progs,attachs} options set.  Passing
 * a token fd in attr->{prog,map,btf,fd_by_id}_token_fd alongside
 * BPF_F_TOKEN_FD in the corresponding flags field flips the kernel-side
 * cap-gate from capable() to bpf_token_capable(), which consults the
 * token's allowed_caps mask instead of the caller's credentials --
 * an entirely separate accept/reject decision tree.
 *
 * No init seeding: BPF_TOKEN_CREATE wants a bpffs_fd opened against a
 * mount provisioned with the right delegate options, and trinity does
 * not stand one up.  The pool fills lazily as the syscall fuzz path
 * lands a successful BPF_TOKEN_CREATE -- same lazy-fill pattern as the
 * link / btf providers.
 */
static void bpf_token_destructor(struct object *obj)
{
	close(obj->bpftokenobj.fd);
}

/*
 * Cross-process safe: reads obj->bpftokenobj.fd and the scope scalar.
 * These survive fork/COW and no process-local pointers are
 * dereferenced.
 */
static void bpf_token_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "bpf token fd:%d scope:%d\n", obj->bpftokenobj.fd, scope);
}

static int init_bpf_token_fds(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_BPF_TOKEN);
	head->destroy = &bpf_token_destructor;
	head->dump = &bpf_token_dump;
	/*
	 * bpftokenobj is {int fd;} with no pointer members, so the
	 * OBJ_GLOBAL pool's scalars stay valid across fork/COW and
	 * cross-process reads are safe.
	 */

	return true;
}

int get_rand_bpf_token_fd(void)
{
	struct objhead *local;

	/* See get_rand_bpf_fd() for why we coin-flip OBJ_LOCAL first.
	 * OBJ_LOCAL is per-child and unaffected by the lockless-reader
	 * UAF window that the version-validated object-slot read guards
	 * against (cf. get_rand_socketinfo in fds/sockets.c), so only the
	 * OBJ_GLOBAL fallback below gets the slot-version validation
	 * wireup. */
	local = get_objhead(OBJ_LOCAL, OBJ_FD_BPF_TOKEN);
	if (local != NULL && local->num_entries > 0 && RAND_BOOL()) {
		struct object *obj = get_random_object(OBJ_FD_BPF_TOKEN,
						       OBJ_LOCAL);
		if (objpool_check(obj, OBJ_FD_BPF_TOKEN))
			return obj->bpftokenobj.fd;
	}

	if (objects_empty(OBJ_FD_BPF_TOKEN) == true)
		return -1;

	/*
	 * Versioned slot pick + objpool_check() before the
	 * obj->bpftokenobj.fd deref.  A version-validated object-slot read
	 * guards the lockless reader against a recycled object
	 * (cf. get_rand_socketinfo in fds/sockets.c).  Same OBJ_GLOBAL
	 * lockless-reader UAF window: between the lockless slot pick and the
	 * consumer's read of the token fd routed into
	 * attr->{prog,map,btf}_token_fd, the parent can destroy the obj;
	 * release_obj() zeroes the chunk and routes it through
	 * deferred-free, so the stale slot pointer can read a zeroed or
	 * recycled chunk.
	 */
	for (int i = 0; i < 1000; i++) {
		struct object *obj;
		int fd;

		obj = get_random_object(OBJ_FD_BPF_TOKEN, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_BPF_TOKEN))
			continue;

		fd = obj->bpftokenobj.fd;
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

static const struct fd_provider bpf_token_fd_provider = {
	.name = "bpf-token",
	.objtype = OBJ_FD_BPF_TOKEN,
	.enabled = true,
	.init = &init_bpf_token_fds,
	.get = &get_rand_bpf_token_fd,
};

REG_FD_PROV(bpf_token_fd_provider);
#endif
