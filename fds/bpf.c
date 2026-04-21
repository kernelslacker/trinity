/* bpf FDs */

#ifdef USE_BPF

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <linux/unistd.h>
#include <linux/perf_event.h>

#include "bpf.h"
#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"

static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
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


static void bpf_map_destructor(struct object *obj)
{
	close(obj->bpfobj.map_fd);
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

	idx = rand() % ARRAY_SIZE(bpf_fds);
	fd = bpf_create_map(bpf_fds[idx].map_type, bpf_fds[idx].key_size,
			    bpf_fds[idx].value_size, bpf_fds[idx].max_entries,
			    bpf_fds[idx].flags);
	if (fd < 0)
		return false;

	obj = alloc_object();
	obj->bpfobj.map_fd = fd;
	obj->bpfobj.map_type = bpf_fds[idx].map_type;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_BPF_MAP);
	__atomic_add_fetch(&shm->stats.bpf_maps_provided, 1, __ATOMIC_RELAXED);
	return true;
}

static int init_bpf_fds(void)
{
	struct objhead *head;
	unsigned int i;
	struct rlimit r = {1 << 20, 1 << 20};

	setrlimit(RLIMIT_MEMLOCK, &r);

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_BPF_MAP);
	head->destroy = &bpf_map_destructor;
	head->dump = &bpf_map_dump;

	for (i = 0; i < ARRAY_SIZE(bpf_fds); i++)
		open_bpf_fd();

	return true;
}

int get_rand_bpf_fd(void)
{
	struct object *obj = NULL;
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
	 */
	local = get_objhead(OBJ_LOCAL, OBJ_FD_BPF_MAP);
	if (local != NULL && local->num_entries > 0 && RAND_BOOL())
		obj = get_random_object(OBJ_FD_BPF_MAP, OBJ_LOCAL);
	if (obj == NULL) {
		if (objects_empty(OBJ_FD_BPF_MAP) == true)
			return -1;
		obj = get_random_object(OBJ_FD_BPF_MAP, OBJ_GLOBAL);
	}
	if (obj == NULL)
		return -1;
	return obj->bpfobj.map_fd;
}

static const struct fd_provider bpf_map_fd_provider = {
	.name = "bpf-map",
	.objtype = OBJ_FD_BPF_MAP,
	.enabled = true,
	.init = &init_bpf_fds,
	.get = &get_rand_bpf_fd,
	.open = &open_bpf_fd,
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

static void bpf_prog_destructor(struct object *obj)
{
	close(obj->bpfprogobj.fd);
}

static void bpf_prog_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "bpf prog fd:%d type:%s scope:%d\n",
		obj->bpfprogobj.fd,
		bpf_prog_template_name(obj->bpfprogobj.prog_type),
		scope);
}

/*
 * Single-shot template load + publish.  Used both to pre-fill the
 * pool from init and for per-syscall regeneration via try_regenerate_fd
 * after a stale-fd teardown.
 */
static int open_bpf_prog_fd(void)
{
	struct object *obj;
	unsigned int idx;
	int fd;

	idx = rand() % ARRAY_SIZE(bpf_prog_templates);
	fd = bpf_load_template_prog(bpf_prog_templates[idx].prog_type);
	if (fd < 0)
		return false;

	obj = alloc_object();
	obj->bpfprogobj.fd = fd;
	obj->bpfprogobj.prog_type = bpf_prog_templates[idx].prog_type;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_BPF_PROG);
	__atomic_add_fetch(&shm->stats.bpf_progs_provided, 1, __ATOMIC_RELAXED);
	return true;
}

static int init_bpf_prog_fds(void)
{
	struct objhead *head;
	struct rlimit r = {1 << 20, 1 << 20};
	unsigned int i;
	unsigned int loaded = 0;

	/*
	 * The map provider already raised RLIMIT_MEMLOCK if it ran first;
	 * the providers are visited in REG_FD_PROV registration order which
	 * isn't guaranteed, so re-set it here.  setrlimit is idempotent.
	 */
	setrlimit(RLIMIT_MEMLOCK, &r);

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_BPF_PROG);
	head->destroy = &bpf_prog_destructor;
	head->dump = &bpf_prog_dump;

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
		obj->bpfprogobj.fd = fd;
		obj->bpfprogobj.prog_type = bpf_prog_templates[i].prog_type;
		add_object(obj, OBJ_GLOBAL, OBJ_FD_BPF_PROG);
		__atomic_add_fetch(&shm->stats.bpf_progs_provided, 1,
				   __ATOMIC_RELAXED);
		loaded++;

		if (loaded >= MAX_BPF_PROG_FDS)
			break;
	}

	return true;
}

int get_rand_bpf_prog_fd(void)
{
	struct object *obj = NULL;
	struct objhead *local;

	/* See get_rand_bpf_fd() for why we coin-flip OBJ_LOCAL first. */
	local = get_objhead(OBJ_LOCAL, OBJ_FD_BPF_PROG);
	if (local != NULL && local->num_entries > 0 && RAND_BOOL())
		obj = get_random_object(OBJ_FD_BPF_PROG, OBJ_LOCAL);
	if (obj == NULL) {
		if (objects_empty(OBJ_FD_BPF_PROG) == true)
			return -1;
		obj = get_random_object(OBJ_FD_BPF_PROG, OBJ_GLOBAL);
	}
	if (obj == NULL)
		return -1;
	return obj->bpfprogobj.fd;
}

static const struct fd_provider bpf_prog_fd_provider = {
	.name = "bpf-prog",
	.objtype = OBJ_FD_BPF_PROG,
	.enabled = true,
	.init = &init_bpf_prog_fds,
	.get = &get_rand_bpf_prog_fd,
	.open = &open_bpf_prog_fd,
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
static void bpf_link_destructor(struct object *obj)
{
	close(obj->bpflinkobj.fd);
}

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
	head->destroy = &bpf_link_destructor;
	head->dump = &bpf_link_dump;

	return true;
}

int get_rand_bpf_link_fd(void)
{
	struct object *obj = NULL;
	struct objhead *local;

	/* See get_rand_bpf_fd() for why we coin-flip OBJ_LOCAL first. */
	local = get_objhead(OBJ_LOCAL, OBJ_FD_BPF_LINK);
	if (local != NULL && local->num_entries > 0 && RAND_BOOL())
		obj = get_random_object(OBJ_FD_BPF_LINK, OBJ_LOCAL);
	if (obj == NULL) {
		if (objects_empty(OBJ_FD_BPF_LINK) == true)
			return -1;
		obj = get_random_object(OBJ_FD_BPF_LINK, OBJ_GLOBAL);
	}
	if (obj == NULL)
		return -1;
	return obj->bpflinkobj.fd;
}

static const struct fd_provider bpf_link_fd_provider = {
	.name = "bpf-link",
	.objtype = OBJ_FD_BPF_LINK,
	.enabled = true,
	.init = &init_bpf_link_fds,
	.get = &get_rand_bpf_link_fd,
	.open = NULL,
};

REG_FD_PROV(bpf_link_fd_provider);
#endif
