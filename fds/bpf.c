/* bpf FDs */

#ifdef USE_BPF

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
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

/*
 * Each row has to pass its map type's allocation check, or the create
 * fails with -EINVAL and nothing is pooled: an arena takes no key or value,
 * a page count in max_entries and BPF_F_MMAPABLE (arena_map_alloc()), an
 * LPM trie BPF_F_NO_PREALLOC (trie_alloc()), and a sockmap a 4-byte key
 * (sock_map_alloc()).  A sockmap's or sockhash's value is a socket's fd,
 * of 4 or 8 bytes, and only 8 hold the cookie a lookup copies out
 * (sock_map_lookup_sys(), -ENOSPC otherwise).
 */
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
	{ BPF_MAP_TYPE_LPM_TRIE, 8, sizeof(long), 10000, BPF_F_NO_PREALLOC, "LPM TRIE" },
	{ BPF_MAP_TYPE_RINGBUF, 0, 0, 4096, 0, "ringbuf" },
	{ BPF_MAP_TYPE_BLOOM_FILTER, 0, sizeof(u32), 100, 0, "bloom filter" },
	{ BPF_MAP_TYPE_USER_RINGBUF, 0, 0, 4096, 0, "user ringbuf" },
	{ BPF_MAP_TYPE_ARENA, 0, 0, 4096, BPF_F_MMAPABLE, "arena" },
	{ BPF_MAP_TYPE_SOCKMAP, sizeof(u32), sizeof(u64), 16, 0, "sockmap" },
	{ BPF_MAP_TYPE_SOCKHASH, sizeof(u32), sizeof(u64), 16, 0, "sockhash" },
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
	obj->bpfobj.key_size = bpf_fds[idx].key_size;
	obj->bpfobj.value_size = bpf_fds[idx].value_size;
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
	 * bpfobj is four u32-sized scalars with no pointer members, so the
	 * OBJ_GLOBAL pool's scalars stay valid across fork/COW and
	 * cross-process reads (dump, lockless slot pick) are safe.
	 */

	for (i = 0; i < ARRAY_SIZE(bpf_fds); i++)
		open_bpf_fd();

	return true;
}

/*
 * A pooled bpf object of @type that holds an fd.  The child's own pool is
 * taken on a coin flip, so the fds its syscall posts made (a fresh map
 * with partially mutated state, a link from BPF_LINK_CREATE) race the
 * templates init seeded, and always while the global pool is empty: init
 * seeds no link, btf or token, and a child's add to the global pool is a
 * no-op, so those live in local pools alone.  A miss there falls through
 * to the global pool.  get_objhead(OBJ_LOCAL, ...) returns NULL outside
 * child context, which leaves init and the parent on the global pool.
 *
 * The OBJ_GLOBAL pick retries a slot objpool_check() turns away or whose
 * fd is gone: between its lockless slot pick and the consumer's read of
 * the fd, the parent can destroy the object, and release_obj() zeroes the
 * chunk and routes it through deferred-free, so a stale slot can read a
 * zeroed or recycled chunk (cf. get_rand_socketinfo in fds/sockets.c).
 * OBJ_LOCAL is per-child and outside that window.
 */
static struct object *pick_bpf_object(enum objecttype type)
{
	struct objhead *local = get_objhead(OBJ_LOCAL, type);
	bool global_empty = objects_empty(type);
	struct object *obj;

	if (local != NULL && local->num_entries > 0 &&
	    (global_empty || RAND_BOOL())) {
		obj = get_random_object(type, OBJ_LOCAL);
		if (objpool_check(obj, type) && fd_from_object(obj, type) >= 0)
			return obj;
	}

	if (global_empty)
		return NULL;

	for (int i = 0; i < 1000; i++) {
		obj = get_random_object(type, OBJ_GLOBAL);
		if (objpool_check(obj, type) && fd_from_object(obj, type) >= 0)
			return obj;
	}

	return NULL;
}

/*
 * The fd of a pooled @type object, from either pool, whose kind (a map's
 * map type, a program's program type) is one of the @n_kinds in @kinds,
 * or -1 when neither pool holds one.
 */
static int pick_bpf_fd_of_kind(enum objecttype type, const unsigned int *kinds,
			       unsigned int n_kinds)
{
	static const enum obj_scope scopes[] = { OBJ_LOCAL, OBJ_GLOBAL };
	unsigned int matches = 0;
	unsigned int i, idx;
	int fd = -1;

	for (i = 0; i < ARRAY_SIZE(scopes); i++) {
		struct objhead *head = get_objhead(scopes[i], type);
		struct object *obj;

		for_each_obj(head, obj, idx) {
			unsigned int kind, k;

			if (!objpool_check(obj, type) ||
			    fd_from_object(obj, type) < 0)
				continue;
			kind = type == OBJ_FD_BPF_MAP ? obj->bpfobj.map_type :
							obj->bpfprogobj.prog_type;
			for (k = 0; k < n_kinds; k++)
				if (kinds[k] == kind)
					break;
			if (k == n_kinds)
				continue;
			/* The nth match takes the pick one time in n, so
			 * each is as likely as another. */
			if (rnd_modulo_u32(++matches) == 0)
				fd = fd_from_object(obj, type);
		}
	}
	return fd;
}

bool get_rand_bpf_map(struct bpfobj *map)
{
	struct object *obj = pick_bpf_object(OBJ_FD_BPF_MAP);

	if (obj == NULL)
		return false;
	*map = obj->bpfobj;
	return true;
}

int get_rand_bpf_fd(void)
{
	struct bpfobj map;

	return get_rand_bpf_map(&map) ? map.map_fd : -1;
}

int get_rand_bpf_map_fd_of_types(const unsigned int *map_types,
				 unsigned int n_types)
{
	return pick_bpf_fd_of_kind(OBJ_FD_BPF_MAP, map_types, n_types);
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
 * (one per supported program type, plus one per multi attach type)
 * and publishes the resulting fds into the global object pool.
 * Other syscalls — setsockopt with SO_ATTACH_BPF, perf_event_open +
 * PERF_EVENT_IOC_SET_BPF, the bpf(PROG_ATTACH/LINK_CREATE) commands,
 * etc. — pull these fds via get_rand_bpf_prog_fd() and end up
 * exercising the cross-subsystem paths that hold most live BPF CVEs.
 *
 * The multi entries matter because link_create() pairs a program
 * with the attach type it was loaded for: a kprobe program loaded
 * with no expected attach type can only take a perf-event link, so
 * the kprobe_multi / uprobe_multi arms never saw a pooled prog.
 * Loading one template per multi attach type gives each arm a prog
 * whose expected attach type names it.
 *
 * Every template is r0 = 0; exit but three: a second LWT_XMIT program
 * that pushes a tunnel header first, without which no skb leaves an
 * LWT route encapsulated, and the sockmap programs, which pass.
 *
 * Capability gates reject most program types when trinity runs
 * unprivileged; the init loop tries each template and keeps whichever
 * successfully loaded.  ENOSYS on any attempt latches the whole
 * provider off (kernel built without BPF).  EPERM/EACCES on a single
 * type just skips that template.  The tracing-multi entries also
 * need vmlinux BTF at load time and fail with -EINVAL without it,
 * which skips them the same way.
 */
struct bpf_prog_template {
	u32 prog_type;
	u32 expected_attach_type;
	const char *name;
	/* Writes the program to insns and returns its length; NULL for
	 * r0 = 0; exit. */
	unsigned int (*build)(struct bpf_insn *insns);
};

/*
 * Push a GRE-in-IPv4 header with bpf_lwt_push_encap(BPF_LWT_ENCAP_IP) and
 * go on (BPF_OK).  bpf_lwt_push_ip_encap() fills in the checksum left 0,
 * and marks a TCP GSO skb SKB_GSO_GRE (handle_gso_encap()), so the
 * segmentation that skb meets carries a tunnel header.  The header goes
 * onto the stack a word at a time, each word read from the bytes in host
 * order.
 */
static unsigned int build_lwt_push_encap(struct bpf_insn *insns)
{
	static const unsigned char hdr[24] = {
		0x45, 0, 0, 0,			/* IPv4, ihl 5 */
		0, 0, 0, 0,
		64, IPPROTO_GRE, 0, 0,		/* ttl, protocol, check */
		127, 0, 0, 1,
		127, 0, 0, 1,
		0, 0, 0x08, 0x00,		/* GRE: no flags, ETH_P_IP */
	};
	unsigned int i, n = 0;

	for (i = 0; i < sizeof(hdr); i += sizeof(__s32)) {
		__s32 word;

		memcpy(&word, hdr + i, sizeof(word));
		insns[n++] = EBPF_ST_MEM(BPF_W, BPF_REG_10,
					 (int) i - (int) sizeof(hdr), word);
	}
	insns[n++] = EBPF_MOV64_IMM(BPF_REG_2, BPF_LWT_ENCAP_IP);
	insns[n++] = EBPF_MOV64_REG(BPF_REG_3, BPF_REG_10);
	insns[n++] = EBPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -(int) sizeof(hdr));
	insns[n++] = EBPF_MOV64_IMM(BPF_REG_4, sizeof(hdr));
	insns[n++] = EBPF_CALL(BPF_FUNC_lwt_push_encap);
	insns[n++] = EBPF_MOV64_IMM(BPF_REG_0, BPF_OK);
	insns[n++] = EBPF_EXIT();
	return n;
}

/*
 * r0 = SK_PASS; exit, for the sockmap programs.  0 is SK_DROP to a
 * verdict, which would drop everything a socket in the map receives or
 * sends, and "no whole message yet" to a stream parser, which would hold
 * back all the socket receives (sk_psock_strp_parse()).  SK_PASS keeps
 * the data moving through the psock, and a parser cuts the stream into
 * one-byte messages.
 */
static unsigned int build_sk_pass(struct bpf_insn *insns)
{
	insns[0] = EBPF_MOV64_IMM(BPF_REG_0, SK_PASS);
	insns[1] = EBPF_EXIT();
	return 2;
}

static struct bpf_prog_template bpf_prog_templates[] = {
	{ BPF_PROG_TYPE_SOCKET_FILTER,	0,				"socket_filter" },
	{ BPF_PROG_TYPE_KPROBE,		0,				"kprobe" },
	{ BPF_PROG_TYPE_TRACEPOINT,	0,				"tracepoint" },
	{ BPF_PROG_TYPE_CGROUP_SKB,	0,				"cgroup_skb" },
	{ BPF_PROG_TYPE_CGROUP_SOCK,	0,				"cgroup_sock" },
	{ BPF_PROG_TYPE_XDP,		0,				"xdp" },
	{ BPF_PROG_TYPE_PERF_EVENT,	0,				"perf_event" },
	{ BPF_PROG_TYPE_RAW_TRACEPOINT,	0,				"raw_tracepoint" },
	{ BPF_PROG_TYPE_SCHED_CLS,	0,				"sched_cls" },
	{ BPF_PROG_TYPE_SCHED_ACT,	0,				"sched_act" },
	{ BPF_PROG_TYPE_LWT_IN,		0,				"lwt_in" },
	{ BPF_PROG_TYPE_LWT_OUT,	0,				"lwt_out" },
	{ BPF_PROG_TYPE_LWT_XMIT,	0,				"lwt_xmit" },
	{ BPF_PROG_TYPE_LWT_XMIT,	0,				"lwt_xmit_encap",
	  build_lwt_push_encap },
	{ BPF_PROG_TYPE_SK_SKB,		0,				"sk_skb",
	  build_sk_pass },
	{ BPF_PROG_TYPE_SK_MSG,		0,				"sk_msg",
	  build_sk_pass },
	{ BPF_PROG_TYPE_KPROBE,		BPF_TRACE_KPROBE_MULTI,		"kprobe_multi" },
	{ BPF_PROG_TYPE_KPROBE,		BPF_TRACE_KPROBE_SESSION,	"kprobe_session" },
	{ BPF_PROG_TYPE_KPROBE,		BPF_TRACE_UPROBE_MULTI,		"uprobe_multi" },
	{ BPF_PROG_TYPE_KPROBE,		BPF_TRACE_UPROBE_SESSION,	"uprobe_session" },
	{ BPF_PROG_TYPE_TRACING,	BPF_TRACE_FENTRY_MULTI,		"tracing_fentry_multi" },
	{ BPF_PROG_TYPE_TRACING,	BPF_TRACE_FEXIT_MULTI,		"tracing_fexit_multi" },
	{ BPF_PROG_TYPE_TRACING,	BPF_TRACE_FSESSION_MULTI,	"tracing_fsession_multi" },
};

static const char bpf_prog_license[] = "GPL";

static int bpf_load_template_prog(const struct bpf_prog_template *t)
{
	struct bpf_insn insns[16];
	unsigned int n = 0;
	union bpf_attr attr;

	if (t->build != NULL) {
		n = t->build(insns);
	} else {
		/*
		 * The minimal verifier-clean program: r0 = 0; exit.
		 * Two instructions, no helper calls, no map references —
		 * passes every prog type that doesn't require a BTF attach
		 * target, including the multi attach types, which need
		 * vmlinux BTF only for the tracing-multi trio.
		 */
		insns[n++] = EBPF_MOV64_IMM(BPF_REG_0, 0);
		insns[n++] = EBPF_EXIT();
	}

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = t->prog_type;
	attr.expected_attach_type = t->expected_attach_type;
	attr.insn_cnt = n;
	attr.insns = (u64)(uintptr_t)insns;
	attr.license = (u64)(uintptr_t)bpf_prog_license;

	return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static const char *bpf_prog_template_name(u32 prog_type,
					  u32 expected_attach_type)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(bpf_prog_templates); i++)
		if (bpf_prog_templates[i].prog_type == prog_type &&
		    bpf_prog_templates[i].expected_attach_type == expected_attach_type)
			return bpf_prog_templates[i].name;
	for (i = 0; i < ARRAY_SIZE(bpf_prog_templates); i++)
		if (bpf_prog_templates[i].prog_type == prog_type)
			return bpf_prog_templates[i].name;
	return "unknown";
}

static void bpf_prog_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "bpf prog fd:%d type:%s scope:%d\n",
		obj->bpfprogobj.fd,
		bpf_prog_template_name(obj->bpfprogobj.prog_type,
				       obj->bpfprogobj.expected_attach_type),
		scope);
}

static int init_bpf_prog_fds(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_BPF_PROG);
	head->destroy = &close_fd_destructor;
	head->dump = &bpf_prog_dump;
	/*
	 * bpfprogobj is {int fd; u32 prog_type; u32 expected_attach_type;}
	 * with no pointer members, so the OBJ_GLOBAL pool's scalars stay
	 * valid across fork/COW and cross-process reads are safe.
	 */

	for (i = 0; i < ARRAY_SIZE(bpf_prog_templates); i++) {
		struct object *obj;
		int fd;

		fd = bpf_load_template_prog(&bpf_prog_templates[i]);
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
		obj->bpfprogobj.expected_attach_type =
			bpf_prog_loaded_attach_type(bpf_prog_templates[i].prog_type,
						    bpf_prog_templates[i].expected_attach_type);
		add_object(obj, OBJ_GLOBAL, OBJ_FD_BPF_PROG);
		__atomic_add_fetch(&shm->stats.ebpf_gen.progs_provided, 1,
				   __ATOMIC_RELAXED);
	}

	return true;
}

bool get_rand_bpf_prog(struct bpfprogobj *prog)
{
	struct object *obj = pick_bpf_object(OBJ_FD_BPF_PROG);

	if (obj == NULL)
		return false;
	*prog = obj->bpfprogobj;
	return true;
}

int get_rand_bpf_prog_fd(void)
{
	struct bpfprogobj prog;

	return get_rand_bpf_prog(&prog) ? prog.fd : -1;
}

int get_rand_bpf_prog_fd_of_type(unsigned int prog_type)
{
	return pick_bpf_fd_of_kind(OBJ_FD_BPF_PROG, &prog_type, 1);
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
	struct object *obj = pick_bpf_object(OBJ_FD_BPF_LINK);

	return obj != NULL ? obj->bpflinkobj.fd : -1;
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
static int init_bpf_btf_fds(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_BPF_BTF);
	head->destroy = &close_fd_destructor;
	head->dump = &generic_fd_dump;
	/*
	 * bpfbtfobj is {int fd;} with no pointer members, so the
	 * OBJ_GLOBAL pool's scalars stay valid across fork/COW and
	 * cross-process reads are safe.
	 */

	return true;
}

int get_rand_bpf_btf_fd(void)
{
	struct object *obj = pick_bpf_object(OBJ_FD_BPF_BTF);

	return obj != NULL ? obj->bpfbtfobj.fd : -1;
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
static int init_bpf_token_fds(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_BPF_TOKEN);
	head->destroy = &close_fd_destructor;
	head->dump = &generic_fd_dump;
	/*
	 * bpftokenobj is {int fd;} with no pointer members, so the
	 * OBJ_GLOBAL pool's scalars stay valid across fork/COW and
	 * cross-process reads are safe.
	 */

	return true;
}

int get_rand_bpf_token_fd(void)
{
	struct object *obj = pick_bpf_object(OBJ_FD_BPF_TOKEN);

	return obj != NULL ? obj->bpftokenobj.fd : -1;
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
