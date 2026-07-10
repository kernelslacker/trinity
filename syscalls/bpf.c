/*
 * SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)
 */
#ifdef USE_BPF
#include <sys/utsname.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/version.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "arch.h"
#include "bpf.h"
#include "name-pool.h"
#include "net.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "publish_resource.h"
#include "shm.h"
#include "struct_catalog.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
#include "kernel/seccomp.h"
static __u32 get_kern_version(void)
{
	struct utsname buf;
	unsigned int major, minor, patch;

	if (uname(&buf) != 0)
		return 0;
	if (sscanf(buf.release, "%u.%u.%u", &major, &minor, &patch) != 3)
		return 0;
	return KERNEL_VERSION(major, minor, patch);
}

static const char *const bpf_raw_tp_names[] = {
	"sys_enter", "sys_exit", "sched_switch", "sched_wakeup", "task_newtask",
};

/*
 * bpf_prog_types[] also lives in struct_catalog.c alongside the
 * MAP_CREATE / PROG_LOAD variants for the same shared-vocabulary
 * reason as bpf_map_types[].  Declared extern in include/bpf.h.
 */

static const char license[] = "GPLv2";

/*
 * Fill a BPF_OBJ_NAME_LEN obj-name buffer (prog_name / map_name).
 * Caller guarantees the buffer was zmalloc'd, so trailing bytes are
 * already NUL and a draw shorter than the buffer leaves a valid
 * terminator behind.  Blend a pool-drawn (possibly mutated) name from
 * a prior bpf() call with fresh alphanumerics so a later bpf() op can
 * pick up a name an earlier op planted -- reuse-exactly drives the
 * kernel's per-name lookup paths (BPF_OBJ_GET_INFO_BY_FD's name copy,
 * the prog_name dedup in trace dumps), and the mutated arms exercise
 * bpf_obj_name_cpy()'s isalnum/'_'/'.' validator on near-valid input.
 */
static void bpf_fill_obj_name(char *name)
{
	static const char alphabet[] =
		"abcdefghijklmnopqrstuvwxyz0123456789_";
	unsigned int n, i;

	if (ONE_IN(4)) {
		size_t got = name_pool_draw_mutated(NAME_KIND_BPF_OBJ_NAME,
						    name,
						    BPF_OBJ_NAME_LEN - 1);

		if (got > 0)
			return;
		/* empty pool -- fall through to fresh generation */
	}

	n = 1 + rnd_modulo_u32(BPF_OBJ_NAME_LEN - 1);
	for (i = 0; i < n; i++)
		name[i] = alphabet[rnd_modulo_u32(sizeof(alphabet) - 1)];
	name_pool_record(NAME_KIND_BPF_OBJ_NAME, name, n);
}

static bool bpf_prog_load(union bpf_attr *attr)
{
	bool classic_filter = false;

	attr->prog_type = bpf_prog_types[rnd_modulo_u32(bpf_prog_types_count)];

	if (attr->prog_type == BPF_PROG_TYPE_SOCKET_FILTER && ONE_IN(2)) {
		/* Classic BPF via sock_fprog for socket filters */
		unsigned long *insns = NULL, len = 0;
		bpf_gen_filter(&insns, &len);
		attr->insn_cnt = len;
		attr->insns = (u64) insns;
		classic_filter = true;
	} else {
		/* Use eBPF for non-socket-filter programs, and for the socket
		 * filter half that does not choose classic BPF. */
		int insn_count = 0;
		struct bpf_insn *insns = ebpf_gen_program(&insn_count, attr->prog_type);
		attr->insn_cnt = insn_count;
		attr->insns = (u64) insns;
	}

	attr->license = (u64) license;
	attr->log_level = 0;
	attr->log_size = rnd_modulo_u32(page_size);
	attr->log_buf = (u64) get_writable_address(page_size);
	{
		unsigned long log_buf_addr = attr->log_buf;
		avoid_shared_buffer_inout(&log_buf_addr, page_size);
		attr->log_buf = log_buf_addr;
	}
	attr->kern_version = get_kern_version();
	bpf_fill_obj_name(attr->prog_name);
	return classic_filter;
}

/* Commands added after trinity's original definitions */
#ifndef BPF_OBJ_PIN
#define BPF_OBJ_PIN 6
#define BPF_OBJ_GET 7
#endif
#ifndef BPF_PROG_ATTACH
#define BPF_PROG_ATTACH			8
#define BPF_PROG_DETACH			9
#endif
#ifndef BPF_PROG_TEST_RUN
#define BPF_PROG_TEST_RUN		10
#endif
#ifndef BPF_PROG_GET_NEXT_ID
#define BPF_PROG_GET_NEXT_ID		11
#define BPF_MAP_GET_NEXT_ID		12
#define BPF_PROG_GET_FD_BY_ID		13
#define BPF_MAP_GET_FD_BY_ID		14
#define BPF_OBJ_GET_INFO_BY_FD		15
#define BPF_PROG_QUERY			16
#endif
#ifndef BPF_RAW_TRACEPOINT_OPEN
#define BPF_RAW_TRACEPOINT_OPEN		17
#endif
#ifndef BPF_BTF_LOAD
#define BPF_BTF_LOAD			18
#define BPF_BTF_GET_FD_BY_ID		19
#define BPF_TASK_FD_QUERY		20
#endif
#ifndef BPF_MAP_LOOKUP_AND_DELETE_ELEM
#define BPF_MAP_LOOKUP_AND_DELETE_ELEM	21
#endif
#ifndef BPF_MAP_FREEZE
#define BPF_MAP_FREEZE			22
#endif
#ifndef BPF_BTF_GET_NEXT_ID
#define BPF_BTF_GET_NEXT_ID		23
#endif
#ifndef BPF_MAP_LOOKUP_BATCH
#define BPF_MAP_LOOKUP_BATCH		24
#define BPF_MAP_LOOKUP_AND_DELETE_BATCH	25
#define BPF_MAP_UPDATE_BATCH		26
#define BPF_MAP_DELETE_BATCH		27
#endif
#ifndef BPF_LINK_CREATE
#define BPF_LINK_CREATE			28
#define BPF_LINK_UPDATE			29
#define BPF_LINK_GET_FD_BY_ID		30
#define BPF_LINK_GET_NEXT_ID		31
#endif
#ifndef BPF_ENABLE_STATS
#define BPF_ENABLE_STATS		32
#endif
#ifndef BPF_ITER_CREATE
#define BPF_ITER_CREATE			33
#endif
#ifndef BPF_LINK_DETACH
#define BPF_LINK_DETACH			34
#endif
#ifndef BPF_PROG_BIND_MAP
#define BPF_PROG_BIND_MAP		35
#endif
#ifndef BPF_TOKEN_CREATE
#define BPF_TOKEN_CREATE		36
#endif
#ifndef BPF_PROG_STREAM_READ_BY_FD
#define BPF_PROG_STREAM_READ_BY_FD	37
#endif
#ifndef BPF_PROG_ASSOC_STRUCT_OPS
#define BPF_PROG_ASSOC_STRUCT_OPS	38
#endif

/* BPF_F_TOKEN_FD and the map-type fallbacks moved to include/bpf.h
 * so the schema-aware fill catalog and this file share them. */

/*
 * bpf_map_types[] now lives in struct_catalog.c so the schema-aware
 * fill's FT_ENUM annotation on union bpf_attr.map_type and the
 * sanitise here share a single vocabulary.  Declared extern in
 * include/bpf.h; consumed below via rnd_modulo_u32 instead of
 * RAND_ARRAY because the array's compile-time size is no longer
 * visible at the call site.
 */

/* Attach types not present in older bpf.h headers */
#ifndef BPF_TRACE_KPROBE_SESSION
#define BPF_TRACE_KPROBE_SESSION	56
#endif
#ifndef BPF_TRACE_UPROBE_SESSION
#define BPF_TRACE_UPROBE_SESSION	57
#endif
#ifndef BPF_TRACE_FSESSION
#define BPF_TRACE_FSESSION		58
#endif

/*
 * bpf_attach_types[] now lives in struct_catalog.c alongside the
 * PROG_ATTACH variant annotation; declared extern in include/bpf.h.
 */

/*
 * Snapshot of the dispatch cmd and the pre-relocation attr pointer the
 * post handler reads, captured at sanitise time and consumed by the
 * post handler.  Two layers of protection here:
 *
 *  - Lives in rec->post_state, a slot the syscall ABI does not expose,
 *    so the post path is immune to a sibling syscall scribbling rec->a1
 *    (the cmd) or rec->a2 (the attr pointer) between the syscall
 *    returning and the post handler running.  The old post handler
 *    dispatched off rec->a1 directly: a sibling scribble of the cmd
 *    between syscall return and post entry would steer object-pool
 *    seeding and the BPF_PROG_LOAD instruction-buffer free into the
 *    wrong arms, misclassifying a fresh map fd as a prog fd (or vice
 *    versa) and silently leaking the program insns.
 *
 *  - attr_original is the pre-avoid_shared_buffer pointer.  ASB
 *    relocated rec->a2 into a writable-pool region without copying the
 *    sanitised fields, so the kernel consumed whatever uninitialised
 *    bytes the pool page held -- post-handler reads off the relocated
 *    rec->a2 would see pool garbage, not the values sanitise wrote.
 *    Reads of map_type / prog_type / link_create.attach_type drive
 *    object-pool tagging that classifies what trinity asked for, and
 *    the attr->insns free at BPF_PROG_LOAD must reach the
 *    sanitise-time allocation, not the pool buffer -- all four read
 *    sites want sanitise intent, so attr_original is the only pointer
 *    we store.  attr_original is also what deferred_free_enqueue()
 *    must receive: the relocated pool address lives in the writable
 *    allocator, not the libc heap, and would be rejected by the
 *    heap-bounds gate.
 *
 * The leading `magic` cookie distinguishes a real bpf_post_state from
 * arbitrary attacker-influenced memory: rec->post_state is opaque to
 * the syscall ABI, but the whole syscallrecord can still be wholesale
 * scribbled, and a heap-shaped post_state pointer rewritten to a
 * foreign allocation would otherwise survive looks_like_corrupted_ptr
 * and let post_bpf parse the foreign bytes as if they were a snap.
 * The cookie check catches that — the magic byte-pattern is unique
 * across the codebase and unlikely to appear at the start of an
 * unrelated allocation by chance.
 */
#define BPF_POST_STATE_MAGIC	0x4250465F4D41475FUL	/* "BPF_MAG_" */
struct bpf_post_state {
	unsigned long magic;
	unsigned int cmd;
	bool classic_bpf_insns;
	union bpf_attr *attr_original;
};

/*
 * Source a token fd value for attr->{prog,map,btf,fd_by_id}_token_fd.
 * The pool is lazy-fill: until a BPF_TOKEN_CREATE roll succeeds the
 * pool is empty and get_rand_bpf_token_fd() returns -1.  Convert that
 * (and a ONE_IN(4) sample of live pool draws) into either -1 or a
 * random integer, so the kernel's token resolution path -- which
 * EBADFs out on a bad fd -- is exercised even when no real token
 * exists.  Live token draws otherwise dominate once the pool warms
 * and the EBADF arm of bpf_token_capable() would never run.
 */
static int bpf_random_token_fd(void)
{
	int fd = get_rand_bpf_token_fd();

	if (fd < 0 || ONE_IN(4))
		fd = ONE_IN(2) ? -1 : (int) rnd_u32();
	return fd;
}

static void sanitise_bpf_map_create(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_type = bpf_map_types[rnd_modulo_u32(bpf_map_types_count)];
	attr->key_size = rnd_modulo_u32(1024);
	attr->value_size = rnd_modulo_u32((1024 * 64));
	attr->max_entries = rnd_modulo_u32(1024);
	attr->map_flags = RAND_RANGE(0, 4);
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

static void sanitise_bpf_map_lookup(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_fd = get_rand_bpf_fd();
	attr->key = RAND_RANGE(0, 10);
	attr->value = rnd_u32();
	rec->a3 = 32;
}

static void sanitise_bpf_map_update(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_fd = get_rand_bpf_fd();
	attr->key = RAND_RANGE(0, 10);
	attr->value = rnd_u32();
	attr->next_key = rnd_u32();
	attr->flags = RAND_RANGE(0, 4);
	rec->a3 = 32;
}

static void sanitise_bpf_map_delete(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_fd = get_rand_bpf_fd();
	attr->key = RAND_RANGE(0, 10);
	rec->a3 = 32;
}

static void sanitise_bpf_map_get_next_key(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_fd = get_rand_bpf_fd();
	attr->key = RAND_RANGE(0, 10);
	attr->value = rnd_u32();
	rec->a3 = 32;
}

static void sanitise_bpf_map_freeze(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_fd = get_rand_bpf_fd();
	rec->a3 = 4;
}

static void sanitise_bpf_obj_get(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->map_fd = get_rand_bpf_fd();
	rec->a3 = 32;
}

static bool sanitise_bpf_prog_load(union bpf_attr *attr, struct syscallrecord *rec)
{
	bool classic_bpf_insns = bpf_prog_load(attr);

	/* Cover prog_name so bpf_fill_obj_name's bytes reach the kernel
	 * verifier's bpf_obj_name_cpy(); without the bump rec->a3 = 48
	 * stops one byte short of the name field. */
	rec->a3 = offsetof(union bpf_attr, prog_name) +
		  sizeof(attr->prog_name);
	if (ONE_IN(8)) {
		/* See the BPF_MAP_CREATE arm for why both the flag
		 * bit and the fd matter, and why rec->a3 must grow
		 * to cover prog_token_fd. */
		attr->prog_token_fd = bpf_random_token_fd();
		attr->prog_flags |= BPF_F_TOKEN_FD;
		rec->a3 = offsetof(union bpf_attr, prog_token_fd) +
			  sizeof(attr->prog_token_fd);
	}
	return classic_bpf_insns;
}

static void sanitise_bpf_prog_attach(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->target_fd = get_rand_bpf_fd();
	attr->attach_bpf_fd = get_rand_bpf_prog_fd();
	attr->attach_type = bpf_attach_types[rnd_modulo_u32(bpf_attach_types_count)];
	rec->a3 = 16;
}

static void sanitise_bpf_prog_test_run(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->test.prog_fd = get_rand_bpf_prog_fd();
	attr->test.data_size_in = rnd_modulo_u32(page_size);
	attr->test.data_in = (u64) get_address();
	attr->test.data_size_out = rnd_modulo_u32(page_size);
	attr->test.data_out = (u64) get_writable_address(page_size);
	{
		unsigned long data_out_addr = attr->test.data_out;
		avoid_shared_buffer_inout(&data_out_addr, page_size);
		attr->test.data_out = data_out_addr;
	}
	attr->test.repeat = rnd_modulo_u32(256);
	rec->a3 = sizeof(attr->test);
}

static void sanitise_bpf_get_next_id(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->start_id = rnd_u32();
	rec->a3 = 8;
}

static void sanitise_bpf_get_fd_by_id(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->start_id = rnd_u32();
	rec->a3 = 8;
#ifdef HAVE_BPF_ATTR_FD_BY_ID_TOKEN_FD
	if (ONE_IN(8)) {
		/* fd_by_id_token_fd lives in the same anonymous
		 * struct as start_id; the kernel resolves it when
		 * non-zero without any flag bit gate, then routes
		 * the per-cmd cap check through bpf_token_capable().
		 * Bump rec->a3 so the kernel reads the slot. */
		attr->fd_by_id_token_fd = bpf_random_token_fd();
		rec->a3 = offsetof(union bpf_attr,
				   fd_by_id_token_fd) +
			  sizeof(attr->fd_by_id_token_fd);
	}
#endif
}

static void sanitise_bpf_btf_load(union bpf_attr *attr, struct syscallrecord *rec)
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

static void sanitise_bpf_obj_get_info_by_fd(union bpf_attr *attr, struct syscallrecord *rec)
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

static void sanitise_bpf_link_create(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->link_create.prog_fd = get_rand_bpf_prog_fd();
	attr->link_create.target_fd = get_rand_bpf_fd();
	attr->link_create.attach_type = bpf_attach_types[rnd_modulo_u32(bpf_attach_types_count)];
	attr->link_create.flags = rnd_modulo_u32(16);
	rec->a3 = sizeof(attr->link_create);
}

static void sanitise_bpf_link_update(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->link_update.link_fd = get_rand_bpf_link_fd();
	attr->link_update.new_prog_fd = get_rand_bpf_prog_fd();
	attr->link_update.flags = rnd_modulo_u32(4);
	rec->a3 = sizeof(attr->link_update);
}

static void sanitise_bpf_link_detach(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->link_detach.link_fd = get_rand_bpf_link_fd();
	rec->a3 = 4;
}

static void sanitise_bpf_enable_stats(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->enable_stats.type = rnd_modulo_u32(4);
	rec->a3 = 4;
}

static void sanitise_bpf_iter_create(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->iter_create.link_fd = get_rand_bpf_link_fd();
	attr->iter_create.flags = 0;
	rec->a3 = sizeof(attr->iter_create);
}

static void sanitise_bpf_prog_bind_map(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->prog_bind_map.prog_fd = get_rand_bpf_prog_fd();
	attr->prog_bind_map.map_fd = get_rand_bpf_fd();
	attr->prog_bind_map.flags = 0;
	rec->a3 = sizeof(attr->prog_bind_map);
}

static void sanitise_bpf_raw_tracepoint(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->raw_tracepoint.prog_fd = get_rand_bpf_prog_fd();
	attr->raw_tracepoint.name = (u64) RAND_ARRAY(bpf_raw_tp_names);
	rec->a3 = sizeof(attr->raw_tracepoint);
}

static void sanitise_bpf_default(union bpf_attr *attr, struct syscallrecord *rec)
{
	/*
	 * Schema-aware floor for the ~15 cmds without a hand-rolled
	 * arm above (BPF_PROG_QUERY, BPF_TASK_FD_QUERY, the MAP_*
	 * batch ops, etc.).  struct_field_fill_schema_aware reads
	 * the cmd discriminator off rec->a1 via bpf_attr's variant
	 * table; annotated variants get FT_ENUM / FT_FLAGS / FT_FD
	 * / FT_PTR_BYTES coherent fill instead of zero, and
	 * unannotated cmds fall through to the zmalloc-zero shape
	 * the old default produced.  rec->a3 prefers the variant's
	 * effective_size when set so the kernel sees a per-cmd size
	 * rather than the full union; unset effective_size keeps
	 * the historical sizeof(union bpf_attr) default.
	 */
	const struct struct_desc *desc = struct_catalog_lookup("bpf_attr");
	const struct union_variant *variant = NULL;
	const struct union_variant *nested = NULL;

	if (desc != NULL) {
		variant = struct_desc_resolve_variant(desc, rec, NULL);
		struct_field_fill_schema_aware((unsigned char *) attr,
					       sizeof(union bpf_attr),
					       desc, rec);
		/*
		 * Nested tagged-union: when the outer variant gates
		 * a sub-union (e.g. link_create's attach_type), the
		 * sub-variant's effective_size is the more specific
		 * bound -- a TRACING arm's 28 bytes vs. the full 88
		 * link_create struct.  Pick the nested size when it
		 * resolves and is non-zero; otherwise the outer
		 * variant's size still wins.
		 */
		if (variant != NULL && variant->nested_variants != NULL)
			nested = struct_desc_resolve_nested_variant(
				variant,
				(const unsigned char *) attr,
				sizeof(union bpf_attr));
	}
	if (nested != NULL && nested->effective_size != 0)
		rec->a3 = nested->effective_size;
	else if (variant != NULL && variant->effective_size != 0)
		rec->a3 = variant->effective_size;
	else
		rec->a3 = sizeof(union bpf_attr);
}

static void sanitise_bpf(struct syscallrecord *rec)
{
	struct bpf_post_state *snap;
	union bpf_attr *attr;
	unsigned int cmd = rec->a1;
	bool classic_bpf_insns = false;

	rec->post_state = 0;

	/* attr is the BPF sanitise-time allocation that the post handler
	 * routes through deferred_free_enqueue() (see line ~840).  A rare
	 * post-state-corruption branch may return without freeing, leaving
	 * a stale tracker slot to be evicted by LRU -- a benign leak
	 * relative to the wrong-free failure mode the audit cares about. */
	attr = zmalloc_tracked(sizeof(union bpf_attr));
	rec->a2 = (unsigned long) attr;

	switch (cmd) {
	case BPF_MAP_CREATE:
		sanitise_bpf_map_create(attr, rec);
		break;
	case BPF_MAP_LOOKUP_ELEM:
	case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
		sanitise_bpf_map_lookup(attr, rec);
		break;
	case BPF_MAP_UPDATE_ELEM:
		sanitise_bpf_map_update(attr, rec);
		break;
	case BPF_MAP_DELETE_ELEM:
		sanitise_bpf_map_delete(attr, rec);
		break;
	case BPF_MAP_GET_NEXT_KEY:
		sanitise_bpf_map_get_next_key(attr, rec);
		break;
	case BPF_MAP_FREEZE:
		sanitise_bpf_map_freeze(attr, rec);
		break;
	case BPF_OBJ_GET:
		sanitise_bpf_obj_get(attr, rec);
		break;
	case BPF_PROG_LOAD:
		classic_bpf_insns = sanitise_bpf_prog_load(attr, rec);
		break;
	case BPF_PROG_ATTACH:
	case BPF_PROG_DETACH:
		sanitise_bpf_prog_attach(attr, rec);
		break;
	case BPF_PROG_TEST_RUN:
		sanitise_bpf_prog_test_run(attr, rec);
		break;
	case BPF_PROG_GET_NEXT_ID:
	case BPF_MAP_GET_NEXT_ID:
	case BPF_BTF_GET_NEXT_ID:
	case BPF_LINK_GET_NEXT_ID:
		sanitise_bpf_get_next_id(attr, rec);
		break;
	case BPF_PROG_GET_FD_BY_ID:
	case BPF_MAP_GET_FD_BY_ID:
	case BPF_BTF_GET_FD_BY_ID:
	case BPF_LINK_GET_FD_BY_ID:
		sanitise_bpf_get_fd_by_id(attr, rec);
		break;
	case BPF_BTF_LOAD:
		sanitise_bpf_btf_load(attr, rec);
		break;
	case BPF_OBJ_GET_INFO_BY_FD:
		sanitise_bpf_obj_get_info_by_fd(attr, rec);
		break;
	case BPF_LINK_CREATE:
		sanitise_bpf_link_create(attr, rec);
		break;
	case BPF_LINK_UPDATE:
		sanitise_bpf_link_update(attr, rec);
		break;
	case BPF_LINK_DETACH:
		sanitise_bpf_link_detach(attr, rec);
		break;
	case BPF_ENABLE_STATS:
		sanitise_bpf_enable_stats(attr, rec);
		break;
	case BPF_ITER_CREATE:
		sanitise_bpf_iter_create(attr, rec);
		break;
	case BPF_PROG_BIND_MAP:
		sanitise_bpf_prog_bind_map(attr, rec);
		break;
	case BPF_RAW_TRACEPOINT_OPEN:
		sanitise_bpf_raw_tracepoint(attr, rec);
		break;
	default:
		sanitise_bpf_default(attr, rec);
		break;
	}

	avoid_shared_buffer_inout(&rec->a2, rec->a3);

	/*
	 * Snapshot the cmd alongside the pre-relocation attr pointer.
	 * magic-cookie / private post_state: see post_state_register().
	 * Specific bpf failure mode: the old post handler dispatched off
	 * rec->a1 directly, so a flip from a pool-seeding cmd to
	 * BPF_PROG_LOAD would skip the insn-buffer free and a flip in the
	 * other direction would dereference attr fields that
	 * bpf_prog_load() never wrote.
	 *
	 * The local attr still references the zmalloc above -- ASB only
	 * rewrote rec->a2 and did not touch attr -- so storing it here
	 * captures the sanitise-intent struct the post handler must read,
	 * not the writable-pool address the kernel actually consumed.  See
	 * the struct bpf_post_state comment for why every post-handler read
	 * site wants sanitise intent rather than kernel-observed bytes.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = BPF_POST_STATE_MAGIC;
	snap->cmd = cmd;
	snap->classic_bpf_insns = classic_bpf_insns;
	snap->attr_original = attr;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);
}

/*
 * Drive the sk_lookup attach lifecycle on a freshly loaded
 * BPF_PROG_TYPE_SK_LOOKUP program.  sk_lookup attaches via
 * BPF_LINK_CREATE against a network namespace fd (not a cgroup or
 * netdev), so open /proc/self/ns/net as the target.  Best-effort:
 * a verifier-rejected prog never reaches here, and the LINK_CREATE
 * itself routinely EPERMs without CAP_NET_ADMIN/CAP_BPF on the
 * netns -- both are normal outcomes for a privilege-fuzzed run.
 * The live link fd, when one is returned, gets published into the
 * shared OBJ_FD_BPF_LINK pool so its release follows the same
 * schedule as every other bpf link, with no special-case leak.
 */
static void bpf_attach_sk_lookup(int prog_fd)
{
	union bpf_attr lc;
	int netns_fd, link_fd;

	netns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (netns_fd < 0)
		return;

	memset(&lc, 0, sizeof(lc));
	lc.link_create.prog_fd = prog_fd;
	lc.link_create.target_fd = netns_fd;
	lc.link_create.attach_type = BPF_SK_LOOKUP;
	lc.link_create.flags = 0;

	link_fd = syscall(__NR_bpf, BPF_LINK_CREATE, &lc, sizeof(lc));
	close(netns_fd);

	if (link_fd >= 0)
		publish_resource(OBJ_FD_BPF_LINK, link_fd,
				 &(struct resource_meta){.subtype = BPF_SK_LOOKUP});
}

/*
 * Ownership-table + magic-cookie reject pair.  Sequenced inside the
 * helper in the only correct order (ownership first, then magic --
 * the cookie alone does not prove the snap is the live one for this
 * record; see post-state-deref-order check).  Returns false on either
 * gate firing; on false the caller must return without freeing snap.
 * The looks_like_corrupted_ptr() shape gates that bracket this call
 * stay in post_bpf so the post-state-deref static checker can see
 * them next to the snap->* dereferences.
 */
static bool bpf_post_state_owned_and_valid_magic(struct syscallrecord *rec,
						 struct bpf_post_state *snap)
{
	/*
	 * Ownership-table check: shape passed but the magic cookie below
	 * only proves "looks like struct bpf_post_state", not "is the
	 * snapshot we produced for this attempt".  A sibling scribble that
	 * redirects rec->post_state at a stale same-type snap still resident
	 * on the deferred-free queue carries the matching cookie by
	 * construction, so a cookie-only gate would trust it and proceed to
	 * dispatch off snap->cmd / dereference snap->attr_original -- driving
	 * the BPF_PROG_LOAD arm into free() on an attacker-influenced
	 * attr->insns and the deferred_free_enqueue() tail into the same
	 * fate on attr.  sanitise_bpf() registers each snap in the post_state
	 * ownership table immediately after the rec->post_state assignment;
	 * a value that fails the lookup is not the live snap for this record
	 * and must not be dereferenced.  Mirrors prctl.c / execve.c / pipe.c.
	 * Bail without freeing -- the pointer is suspect.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_bpf: rejected post_state=%p not in ownership "
			  "table (post_state-redirected?)\n", snap);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return false;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * bpf_post_state.  A cookie mismatch means snap does not point at
	 * our struct -- abandon the post handler entirely rather than
	 * read attr_original / cmd out of wild memory.  Do NOT free: the
	 * pointer is suspect and may not be heap-owned, so handing it to
	 * deferred_free_enqueue() would corrupt the allocator's bookkeeping.
	 */
	if (snap->magic != BPF_POST_STATE_MAGIC) {
		outputerr("post_bpf: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return false;
	}

	return true;
}

static void bpf_post_validate_retval(struct syscallrecord *rec,
				     unsigned int cmd, unsigned long ret)
{
	/*
	 * Per-cmd STRONG-VAL on retval for the *_GET_NEXT_ID dispatch.
	 * BPF_{PROG,MAP,BTF,LINK}_GET_NEXT_ID all funnel through
	 * bpf_obj_get_next_id() in kernel/bpf/syscall.c, which returns 0
	 * on success (writing the resolved id into attr->next_id via
	 * put_user) or -EINVAL / -EPERM / -ENOENT / -EFAULT on failure --
	 * the syscall return is RZS, not the id itself; the id lives in
	 * attr->next_id.  Any retval other than 0 or -1UL on these cmds
	 * is structural corruption: a torn write of the return slot, a
	 * sign-extension at the syscall ABI boundary, or -errno bits
	 * leaking through the success path without becoming -1UL.  None
	 * of the four register through add_object, so the FD-pool blanket
	 * gate at add_object's entry never sees their retval; this per-
	 * cmd guard closes that gap.  Validate against the snapshotted
	 * cmd, not rec->a1, so a sibling scribble of rec->a1 cannot
	 * misroute the dispatch.  -1UL fall-through is intentional --
	 * every documented failure path lands there.
	 */
	if (ret != (unsigned long)-1L) {
		switch (cmd) {
		case BPF_PROG_GET_NEXT_ID:
		case BPF_MAP_GET_NEXT_ID:
		case BPF_BTF_GET_NEXT_ID:
		case BPF_LINK_GET_NEXT_ID:
			if (ret != 0) {
				outputerr("post_bpf: cmd=%u rejected GET_NEXT_ID retval=0x%lx (expected 0 or -1UL)\n",
					  cmd, ret);
				post_handler_corrupt_ptr_bump(rec, NULL);
			}
			break;
		/*
		 * *_GET_FD_BY_ID return a real fd on success — bound to the
		 * VAL13 family fd window [0, 1<<20).  -errno other than -1UL
		 * or a wildly out-of-range value is structural corruption.
		 */
		case BPF_PROG_GET_FD_BY_ID:
		case BPF_MAP_GET_FD_BY_ID:
		case BPF_BTF_GET_FD_BY_ID:
		case BPF_LINK_GET_FD_BY_ID:
			if ((long)ret < 0 || ret >= (1UL << 20)) {
				outputerr("post_bpf: cmd=%u rejected GET_FD_BY_ID retval=0x%lx (expected [0,1<<20) or -1UL)\n",
					  cmd, ret);
				post_handler_corrupt_ptr_bump(rec, NULL);
			}
			break;
		default:
			break;
		}
	}
}

static void post_bpf_map_create(int fd, bool attr_readable, union bpf_attr *attr)
{
	if (fd >= 0 && attr_readable)
		publish_resource(OBJ_FD_BPF_MAP, fd,
				 &(struct resource_meta){.subtype = attr->map_type});
}

static void post_bpf_prog_load(int fd, bool attr_readable, union bpf_attr *attr,
			       bool classic_bpf_insns)
{
	if (fd >= 0 && attr_readable)
		publish_resource(OBJ_FD_BPF_PROG, fd,
				 &(struct resource_meta){.subtype = attr->prog_type});

	/*
	 * sk_lookup is one of the few prog types whose runtime path is
	 * gated entirely on having an attached link in the target netns
	 * -- a freshly loaded prog with no link is a verifier exercise
	 * and nothing else.  Drive the attach inline so the attach path
	 * sees traffic; the resulting link fd, if any, joins the normal
	 * link pool and releases on the standard schedule.
	 */
	if (fd >= 0 && attr_readable &&
	    attr->prog_type == BPF_PROG_TYPE_SK_LOOKUP)
		bpf_attach_sk_lookup(fd);

	/* Two instruction-buffer allocators feed BPF_PROG_LOAD: the
	 * classic-BPF branch returns a tracked sock_fprog wrapper that
	 * owns a separate inner filter buffer (both allocations need
	 * deferred_free_enqueue to consume their tracker slots), and the
	 * eBPF branch returns a tracked insn buffer that releases the
	 * same way.  classic_bpf_insns is captured in the snap at
	 * sanitise time so a sibling scribble of attr fields cannot
	 * misroute the dispatch.
	 *
	 * Both branches gate on alloc_track_lookup() before releasing:
	 * attr->insns is read out of the shm-resident syscallrecord at
	 * post time and is not captured in the snap, so a sibling fuzzed
	 * value-result syscall can scribble it between dispatch and here.
	 * A shape-only gate would pass any heap-shaped scribble through
	 * to plain free(); if the scribbled value aliases a pointer
	 * already admitted to the deferred-free in-flight set by another
	 * site, that plain free() bypasses inflight_hash_remove() and
	 * the original site's later TTL-expiry double-frees the chunk
	 * (free_ring_entry sees the value still in inflight_hash, passes
	 * its in-flight-miss gate, and calls free() a second time).
	 * Routing the proven-ours eBPF buffer through
	 * deferred_free_enqueue() keeps the bookkeeping in lock-step:
	 * enqueue consumes alloc_track and admits to inflight_hash, and
	 * the TTL-expiry free clears inflight_hash.
	 *
	 * Outer attr_readable gates the attr->insns load itself: an
	 * unmapped attr would fault before alloc_track_lookup ever ran
	 * on the inner pointer.  When the wrapper gate fails the inner
	 * buffers stay on the deferred-free tracker until LRU eviction,
	 * a benign leak relative to the SIGSEGV the gate prevents. */
	if (attr_readable) {
		if (classic_bpf_insns) {
			bpf_free_filter((struct sock_fprog *)(unsigned long)attr->insns);
		} else {
			void *ptr = (void *)(unsigned long)attr->insns;
			if (ptr != NULL && alloc_track_lookup(ptr))
				deferred_free_enqueue(ptr);
		}
	}
}

static void post_bpf_map_get_fd_by_id(int fd)
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

static void post_bpf_prog_get_fd_by_id(int fd)
{
	/* Same logic as BPF_MAP_GET_FD_BY_ID for prog fds. */
	if (fd >= 0)
		publish_resource(OBJ_FD_BPF_PROG, fd, NULL);
}

static void post_bpf_link_create(int fd, bool attr_readable, union bpf_attr *attr)
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

static void post_bpf_link_get_fd_by_id(int fd)
{
	/*
	 * Same fd kind as LINK_CREATE returns, sourced via id-lookup.
	 * Attach type unknown at lookup time — leave it 0; it's
	 * metadata only.
	 */
	if (fd >= 0)
		publish_resource(OBJ_FD_BPF_LINK, fd, NULL);
}

static void post_bpf_btf_fd(int fd)
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

static void post_bpf_token_create(int fd)
{
	/*
	 * Live bpf token fd.  Publishing into the per-child token
	 * pool lets subsequent BPF_MAP_CREATE / BPF_PROG_LOAD /
	 * BPF_BTF_LOAD / BPF_*_GET_FD_BY_ID dispatches pull it via
	 * get_rand_bpf_token_fd() and stash it in their respective
	 * attr->*_token_fd slot alongside BPF_F_TOKEN_FD in the
	 * matching flags field.  The kernel then resolves the token
	 * and routes the per-op cap check through
	 * bpf_token_capable(), exercising a separate accept/reject
	 * decision tree from the default capable()-only path.
	 * Without this hook the token fd opened here is immediately
	 * closed by the tail switch below and the gate stays
	 * unreachable.
	 */
	if (fd >= 0)
		publish_resource(OBJ_FD_BPF_TOKEN, fd, NULL);
}

static void post_bpf_prog_attach(unsigned long ret, bool attr_readable,
				 union bpf_attr *attr)
{
	/*
	 * A successful legacy attach pins the program against the
	 * target object (cgroup, sockmap, netns, ...) without going
	 * through bpf_link.  close() on the prog fd does not undo the
	 * attach: the target keeps a refcount on the program until an
	 * explicit BPF_PROG_DETACH with the matching {target_fd,
	 * attach_bpf_fd, attach_type} triple, or until the target
	 * itself is destroyed.  Most attach_types in the dispatch
	 * array expect target_fd to be a cgroup / netns / netdev fd
	 * and so reject the random map fd we hand them, but the
	 * sockmap and reuseport-array attach paths accept a map fd
	 * and can succeed against a freshly created sockmap.  When
	 * that happens, replay the inverse cmd from the snapshot so
	 * the program ref drops at syscall return rather than at
	 * child exit.
	 */
	if (ret == 0 && attr_readable) {
		union bpf_attr detach;

		memset(&detach, 0, sizeof(detach));
		detach.target_fd = attr->target_fd;
		detach.attach_bpf_fd = attr->attach_bpf_fd;
		detach.attach_type = attr->attach_type;
		(void) syscall(__NR_bpf, BPF_PROG_DETACH,
			       &detach, sizeof(detach));
	}
}

/* Close fds returned by commands not tracked above.  The
 * remaining commands that can return an fd are OBJ_GET,
 * RAW_TRACEPOINT_OPEN, ENABLE_STATS, and ITER_CREATE — none of
 * them produce a kind of fd that fits one of our pools, so they
 * get closed immediately to avoid leaking.  We can't blindly
 * close on all commands because non-fd commands return 0 for
 * success, and closing fd 0 would destroy stdin. */
static void post_bpf_close_orphan_fd(int fd, unsigned int cmd)
{
	switch (cmd) {
	case BPF_MAP_CREATE:
	case BPF_PROG_LOAD:
	case BPF_MAP_GET_FD_BY_ID:
	case BPF_PROG_GET_FD_BY_ID:
	case BPF_LINK_CREATE:
	case BPF_LINK_GET_FD_BY_ID:
	case BPF_BTF_LOAD:
	case BPF_BTF_GET_FD_BY_ID:
	case BPF_TOKEN_CREATE:
		/* Already tracked above. */
		break;
	case BPF_OBJ_GET:
	case BPF_RAW_TRACEPOINT_OPEN:
	case BPF_ENABLE_STATS:
	case BPF_ITER_CREATE:
		close(fd);
		break;
	default:
		break;
	}
}

static void post_bpf(struct syscallrecord *rec)
{
	struct bpf_post_state *snap = (struct bpf_post_state *) rec->post_state;
	union bpf_attr *attr;
	unsigned int cmd;
	int fd = rec->retval;
	unsigned long ret = rec->retval;
	bool attr_readable;

	rec->a2 = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler and is not exposed to
	 * the syscall ABI, so the argN-scribbling sibling paths leave it
	 * alone.  The whole syscallrecord can still be wholesale-stomped
	 * (e.g. by a child reusing the slot), so keep the corruption guard
	 * as a backstop.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_bpf: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!bpf_post_state_owned_and_valid_magic(rec, snap))
		return;

	/*
	 * Defense in depth: if something corrupted the snapshot itself,
	 * the inner attr_original pointer may no longer reference our heap
	 * allocation.  attr_original is always set by sanitise (no opcode
	 * skips the zmalloc), so NULL here is itself corruption -- the
	 * < 0x10000 band of looks_like_corrupted_ptr() catches it without
	 * a separate NULL guard.
	 */
	if (looks_like_corrupted_ptr(rec, snap->attr_original)) {
		outputerr("post_bpf: rejected suspicious snap attr_original=%p (post_state-scribbled?)\n",
			  snap->attr_original);
		post_state_release(rec, snap);
		return;
	}

	cmd = snap->cmd;
	attr = snap->attr_original;

	/*
	 * Wrapper-side readability gate before reading attr inner fields:
	 * looks_like_corrupted_ptr above is shape-only (heap-band +
	 * alignment), so a heap-shaped but unmapped snap->attr_original
	 * would survive and an inner read (attr->map_type / attr->prog_type
	 * / attr->insns / attr->link_create.attach_type / attr->target_fd
	 * / attr->attach_bpf_fd / attr->attach_type) would fault the post
	 * handler before the dispatch ever runs.  Require attr to be a
	 * tracked allocation (one we produced via zmalloc_tracked at
	 * sanitise) or readable for a union bpf_attr-sized window.  When
	 * neither holds, the per-cmd cases below that read attr skip their
	 * inner work; cases that only consume rec->retval still run, as
	 * does the tail fd-closer and the unconditional deferred-free of
	 * attr.  Mirrors post_seccomp SECCOMP_SET_MODE_FILTER, post_prctl
	 * PR_SET_SECCOMP, and post_setsockopt SO_ATTACH_FILTER.
	 */
	attr_readable = alloc_track_lookup(attr) ||
			range_readable_user(attr, sizeof(union bpf_attr));

	bpf_post_validate_retval(rec, cmd, ret);

	switch (cmd) {
	case BPF_MAP_CREATE:
		post_bpf_map_create(fd, attr_readable, attr);
		break;
	case BPF_PROG_LOAD:
		post_bpf_prog_load(fd, attr_readable, attr, snap->classic_bpf_insns);
		break;
	case BPF_MAP_GET_FD_BY_ID:
		post_bpf_map_get_fd_by_id(fd);
		break;
	case BPF_PROG_GET_FD_BY_ID:
		post_bpf_prog_get_fd_by_id(fd);
		break;
	case BPF_LINK_CREATE:
		post_bpf_link_create(fd, attr_readable, attr);
		break;
	case BPF_LINK_GET_FD_BY_ID:
		post_bpf_link_get_fd_by_id(fd);
		break;
	case BPF_BTF_LOAD:
	case BPF_BTF_GET_FD_BY_ID:
		post_bpf_btf_fd(fd);
		break;
	case BPF_TOKEN_CREATE:
		post_bpf_token_create(fd);
		break;
	case BPF_PROG_ATTACH:
		post_bpf_prog_attach(ret, attr_readable, attr);
		break;
	default:
		break;
	}

	if (fd >= 0)
		post_bpf_close_orphan_fd(fd, cmd);

	deferred_free_enqueue(attr);
	post_state_release(rec, snap);
}

static unsigned long bpf_cmds[] = {
	BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM, BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD, BPF_OBJ_PIN, BPF_OBJ_GET,
	BPF_PROG_ATTACH, BPF_PROG_DETACH, BPF_PROG_TEST_RUN,
	BPF_PROG_GET_NEXT_ID, BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID, BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD, BPF_PROG_QUERY,
	BPF_RAW_TRACEPOINT_OPEN,
	BPF_BTF_LOAD, BPF_BTF_GET_FD_BY_ID, BPF_TASK_FD_QUERY,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM, BPF_MAP_FREEZE,
	BPF_BTF_GET_NEXT_ID,
	BPF_MAP_LOOKUP_BATCH, BPF_MAP_LOOKUP_AND_DELETE_BATCH,
	BPF_MAP_UPDATE_BATCH, BPF_MAP_DELETE_BATCH,
	BPF_LINK_CREATE, BPF_LINK_UPDATE,
	BPF_LINK_GET_FD_BY_ID, BPF_LINK_GET_NEXT_ID,
	BPF_ENABLE_STATS, BPF_ITER_CREATE,
	BPF_LINK_DETACH, BPF_PROG_BIND_MAP,
	BPF_TOKEN_CREATE,
	BPF_PROG_STREAM_READ_BY_FD, BPF_PROG_ASSOC_STRUCT_OPS,
};

struct syscallentry syscall_bpf = {
	.name = "bpf",
	.group = GROUP_BPF,
	.num_args = 3,

	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS, [2] = ARG_STRUCT_SIZE },
	.argname = { [0] = "cmd", [1] = "uattr", [2] = "size" },
	.arg_params[0].list = ARGLIST(bpf_cmds),
	.flags = KCOV_REMOTE_HEAVY,
	.sanitise = sanitise_bpf,
	.post = post_bpf,
};
#endif
