/*
 * SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)
 */
#ifdef USE_BPF
#include <sys/utsname.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/version.h>
#include <sys/syscall.h>
#include <string.h>
#include <unistd.h>
#include "arch.h"
#include "bpf.h"
#include "net.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

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

static unsigned long bpf_prog_types[] = {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	BPF_PROG_TYPE_LWT_SEG6LOCAL,
	BPF_PROG_TYPE_LIRC_MODE2,
	BPF_PROG_TYPE_SK_REUSEPORT,
	BPF_PROG_TYPE_FLOW_DISSECTOR,
	BPF_PROG_TYPE_CGROUP_SYSCTL,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
	BPF_PROG_TYPE_CGROUP_SOCKOPT,
	BPF_PROG_TYPE_TRACING,
	BPF_PROG_TYPE_STRUCT_OPS,
	BPF_PROG_TYPE_EXT,
	BPF_PROG_TYPE_LSM,
	BPF_PROG_TYPE_SK_LOOKUP,
	BPF_PROG_TYPE_SYSCALL,
	BPF_PROG_TYPE_NETFILTER,
};

static const char license[] = "GPLv2";

static void bpf_prog_load(union bpf_attr *attr)
{
	attr->prog_type = RAND_ARRAY(bpf_prog_types);

	if (attr->prog_type == BPF_PROG_TYPE_SOCKET_FILTER && ONE_IN(2)) {
		/* Classic BPF via sock_fprog for socket filters */
		unsigned long *insns = NULL, len = 0;
		bpf_gen_filter(&insns, &len);
		attr->insn_cnt = len;
		attr->insns = (u64) insns;
	} else {
		/* eBPF for everything else (and sometimes socket filters) */
		int insn_count = 0;
		struct bpf_insn *insns = ebpf_gen_program(&insn_count, attr->prog_type);
		attr->insn_cnt = insn_count;
		attr->insns = (u64) insns;
	}

	attr->license = (u64) license;
	attr->log_level = 0;
	attr->log_size = rand() % page_size;
	attr->log_buf = (u64) get_writable_address(page_size);
	attr->kern_version = get_kern_version();
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

/* Map types added after trinity's original definitions */
#ifndef BPF_MAP_TYPE_ARRAY_OF_MAPS
#define BPF_MAP_TYPE_ARRAY_OF_MAPS	12
#define BPF_MAP_TYPE_HASH_OF_MAPS	13
#endif
#ifndef BPF_MAP_TYPE_DEVMAP
#define BPF_MAP_TYPE_DEVMAP		14
#define BPF_MAP_TYPE_SOCKMAP		15
#define BPF_MAP_TYPE_CPUMAP		16
#endif
#ifndef BPF_MAP_TYPE_XSKMAP
#define BPF_MAP_TYPE_XSKMAP		17
#define BPF_MAP_TYPE_SOCKHASH		18
#endif
#ifndef BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
#define BPF_MAP_TYPE_REUSEPORT_SOCKARRAY 20
#endif
#ifndef BPF_MAP_TYPE_QUEUE
#define BPF_MAP_TYPE_QUEUE		22
#define BPF_MAP_TYPE_STACK		23
#endif
#ifndef BPF_MAP_TYPE_SK_STORAGE
#define BPF_MAP_TYPE_SK_STORAGE		24
#endif
#ifndef BPF_MAP_TYPE_DEVMAP_HASH
#define BPF_MAP_TYPE_DEVMAP_HASH	25
#endif
#ifndef BPF_MAP_TYPE_STRUCT_OPS
#define BPF_MAP_TYPE_STRUCT_OPS		26
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF		27
#endif
#ifndef BPF_MAP_TYPE_INODE_STORAGE
#define BPF_MAP_TYPE_INODE_STORAGE	28
#endif
#ifndef BPF_MAP_TYPE_TASK_STORAGE
#define BPF_MAP_TYPE_TASK_STORAGE	29
#endif
#ifndef BPF_MAP_TYPE_BLOOM_FILTER
#define BPF_MAP_TYPE_BLOOM_FILTER	30
#endif
#ifndef BPF_MAP_TYPE_USER_RINGBUF
#define BPF_MAP_TYPE_USER_RINGBUF	31
#endif
#ifndef BPF_MAP_TYPE_CGRP_STORAGE
#define BPF_MAP_TYPE_CGRP_STORAGE	32
#endif
#ifndef BPF_MAP_TYPE_ARENA
#define BPF_MAP_TYPE_ARENA		33
#endif
#ifndef BPF_MAP_TYPE_INSN_ARRAY
#define BPF_MAP_TYPE_INSN_ARRAY		34
#endif

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

static unsigned long bpf_attach_types[] = {
	BPF_CGROUP_INET_INGRESS, BPF_CGROUP_INET_EGRESS,
	BPF_CGROUP_INET_SOCK_CREATE, BPF_CGROUP_SOCK_OPS,
	BPF_SK_SKB_STREAM_PARSER, BPF_SK_SKB_STREAM_VERDICT,
	BPF_CGROUP_DEVICE, BPF_SK_MSG_VERDICT,
	BPF_CGROUP_INET4_BIND, BPF_CGROUP_INET6_BIND,
	BPF_CGROUP_INET4_CONNECT, BPF_CGROUP_INET6_CONNECT,
	BPF_CGROUP_INET4_POST_BIND, BPF_CGROUP_INET6_POST_BIND,
	BPF_CGROUP_UDP4_SENDMSG, BPF_CGROUP_UDP6_SENDMSG,
	BPF_LIRC_MODE2, BPF_FLOW_DISSECTOR,
	BPF_CGROUP_SYSCTL,
	BPF_CGROUP_UDP4_RECVMSG, BPF_CGROUP_UDP6_RECVMSG,
	BPF_CGROUP_GETSOCKOPT, BPF_CGROUP_SETSOCKOPT,
	BPF_TRACE_RAW_TP, BPF_TRACE_FENTRY, BPF_TRACE_FEXIT,
	BPF_MODIFY_RETURN, BPF_LSM_MAC, BPF_TRACE_ITER,
	BPF_CGROUP_INET4_GETPEERNAME, BPF_CGROUP_INET6_GETPEERNAME,
	BPF_CGROUP_INET4_GETSOCKNAME, BPF_CGROUP_INET6_GETSOCKNAME,
	BPF_XDP_DEVMAP, BPF_CGROUP_INET_SOCK_RELEASE,
	BPF_XDP_CPUMAP, BPF_SK_LOOKUP, BPF_XDP,
	BPF_SK_SKB_VERDICT,
	BPF_SK_REUSEPORT_SELECT, BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,
	BPF_PERF_EVENT, BPF_TRACE_KPROBE_MULTI,
	BPF_LSM_CGROUP, BPF_STRUCT_OPS, BPF_NETFILTER,
	BPF_TCX_INGRESS, BPF_TCX_EGRESS,
	BPF_TRACE_UPROBE_MULTI,
	BPF_CGROUP_UNIX_CONNECT, BPF_CGROUP_UNIX_SENDMSG,
	BPF_CGROUP_UNIX_RECVMSG, BPF_CGROUP_UNIX_GETPEERNAME,
	BPF_CGROUP_UNIX_GETSOCKNAME,
	BPF_NETKIT_PRIMARY, BPF_NETKIT_PEER,
	BPF_TRACE_KPROBE_SESSION, BPF_TRACE_UPROBE_SESSION,
	BPF_TRACE_FSESSION,
};

/*
 * Snapshot of the dispatch cmd and the heap-allocated union bpf_attr
 * the post handler reads, captured at sanitise time and consumed by the
 * post handler.  Lives in rec->post_state, a slot the syscall ABI does
 * not expose, so the post path is immune to a sibling syscall scribbling
 * rec->a1 (the cmd) or rec->a2 (the attr pointer) between the syscall
 * returning and the post handler running.  The old post handler
 * dispatched off rec->a1 directly: a sibling scribble of the cmd
 * between syscall return and post entry would steer object-pool seeding
 * and the BPF_PROG_LOAD instruction-buffer free into the wrong arms,
 * misclassifying a fresh map fd as a prog fd (or vice versa) and
 * silently leaking the program insns.
 */
struct bpf_post_state {
	unsigned int cmd;
	union bpf_attr *attr;
};

static void sanitise_bpf(struct syscallrecord *rec)
{
	struct bpf_post_state *snap;
	union bpf_attr *attr;
	unsigned int cmd = rec->a1;
	unsigned long bpf_map_types[] = {
		BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_ARRAY,
		BPF_MAP_TYPE_PROG_ARRAY, BPF_MAP_TYPE_PERF_EVENT_ARRAY,
		BPF_MAP_TYPE_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_ARRAY,
		BPF_MAP_TYPE_STACK_TRACE, BPF_MAP_TYPE_CGROUP_ARRAY,
		BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH,
		BPF_MAP_TYPE_LPM_TRIE,
		BPF_MAP_TYPE_ARRAY_OF_MAPS, BPF_MAP_TYPE_HASH_OF_MAPS,
		BPF_MAP_TYPE_DEVMAP, BPF_MAP_TYPE_SOCKMAP,
		BPF_MAP_TYPE_CPUMAP, BPF_MAP_TYPE_XSKMAP,
		BPF_MAP_TYPE_SOCKHASH,
		BPF_MAP_TYPE_CGROUP_STORAGE,
		BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
		BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
		BPF_MAP_TYPE_QUEUE, BPF_MAP_TYPE_STACK,
		BPF_MAP_TYPE_SK_STORAGE, BPF_MAP_TYPE_DEVMAP_HASH,
		BPF_MAP_TYPE_STRUCT_OPS, BPF_MAP_TYPE_RINGBUF,
		BPF_MAP_TYPE_INODE_STORAGE, BPF_MAP_TYPE_TASK_STORAGE,
		BPF_MAP_TYPE_BLOOM_FILTER, BPF_MAP_TYPE_USER_RINGBUF,
		BPF_MAP_TYPE_CGRP_STORAGE, BPF_MAP_TYPE_ARENA,
		BPF_MAP_TYPE_INSN_ARRAY,
	};

	rec->post_state = 0;

	attr = zmalloc(sizeof(union bpf_attr));
	rec->a2 = (unsigned long) attr;

	switch (cmd) {
	case BPF_MAP_CREATE:
		attr->map_type = RAND_ARRAY(bpf_map_types);
		attr->key_size = rand() % 1024;
		attr->value_size = rand() % (1024 * 64);
		attr->max_entries = rand() % 1024;
		attr->flags = RAND_RANGE(0, 4);
		rec->a3 = 20;
		break;

	case BPF_MAP_LOOKUP_ELEM:
	case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
		attr->map_fd = get_rand_bpf_fd();
		attr->key = RAND_RANGE(0, 10);
		attr->value = rand();
		rec->a3 = 32;
		break;

	case BPF_MAP_UPDATE_ELEM:
		attr->map_fd = get_rand_bpf_fd();
		attr->key = RAND_RANGE(0, 10);
		attr->value = rand();
		attr->next_key = rand();
		attr->flags = RAND_RANGE(0, 4);
		rec->a3 = 32;
		break;

	case BPF_MAP_DELETE_ELEM:
		attr->map_fd = get_rand_bpf_fd();
		attr->key = RAND_RANGE(0, 10);
		rec->a3 = 32;
		break;

	case BPF_MAP_GET_NEXT_KEY:
		attr->map_fd = get_rand_bpf_fd();
		attr->key = RAND_RANGE(0, 10);
		attr->value = rand();
		rec->a3 = 32;
		break;

	case BPF_MAP_FREEZE:
		attr->map_fd = get_rand_bpf_fd();
		rec->a3 = 4;
		break;

	case BPF_OBJ_GET:
		attr->map_fd = get_rand_bpf_fd();
		rec->a3 = 32;
		break;

	case BPF_PROG_LOAD:
		bpf_prog_load(attr);
		rec->a3 = 48;
		break;

	case BPF_PROG_ATTACH:
	case BPF_PROG_DETACH:
		attr->target_fd = get_rand_bpf_fd();
		attr->attach_bpf_fd = get_rand_bpf_prog_fd();
		attr->attach_type = RAND_ARRAY(bpf_attach_types);
		rec->a3 = 16;
		break;

	case BPF_PROG_TEST_RUN:
		attr->test.prog_fd = get_rand_bpf_prog_fd();
		attr->test.data_size_in = rand() % page_size;
		attr->test.data_in = (u64) get_address();
		attr->test.data_size_out = rand() % page_size;
		attr->test.data_out = (u64) get_writable_address(page_size);
		attr->test.repeat = rand() % 256;
		rec->a3 = sizeof(attr->test);
		break;

	case BPF_PROG_GET_NEXT_ID:
	case BPF_MAP_GET_NEXT_ID:
	case BPF_BTF_GET_NEXT_ID:
	case BPF_LINK_GET_NEXT_ID:
		attr->start_id = rand();
		rec->a3 = 8;
		break;

	case BPF_PROG_GET_FD_BY_ID:
	case BPF_MAP_GET_FD_BY_ID:
	case BPF_BTF_GET_FD_BY_ID:
	case BPF_LINK_GET_FD_BY_ID:
		attr->start_id = rand();
		rec->a3 = 8;
		break;

	case BPF_OBJ_GET_INFO_BY_FD: {
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
		unsigned int start = rand() % 4;
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
		attr->info.info_len = rand() % page_size;
		attr->info.info = (u64) get_writable_address(page_size);
		rec->a3 = sizeof(attr->info);
		break;
	}

	case BPF_LINK_CREATE:
		attr->link_create.prog_fd = get_rand_bpf_prog_fd();
		attr->link_create.target_fd = get_rand_bpf_fd();
		attr->link_create.attach_type = RAND_ARRAY(bpf_attach_types);
		attr->link_create.flags = rand() % 16;
		rec->a3 = sizeof(attr->link_create);
		break;

	case BPF_LINK_UPDATE:
		attr->link_update.link_fd = get_rand_bpf_link_fd();
		attr->link_update.new_prog_fd = get_rand_bpf_prog_fd();
		attr->link_update.flags = rand() % 4;
		rec->a3 = sizeof(attr->link_update);
		break;

	case BPF_LINK_DETACH:
		attr->link_detach.link_fd = get_rand_bpf_link_fd();
		rec->a3 = 4;
		break;

	case BPF_ENABLE_STATS:
		attr->enable_stats.type = rand() % 4;
		rec->a3 = 4;
		break;

	case BPF_ITER_CREATE:
		attr->iter_create.link_fd = get_rand_bpf_link_fd();
		attr->iter_create.flags = 0;
		rec->a3 = sizeof(attr->iter_create);
		break;

	case BPF_PROG_BIND_MAP:
		attr->prog_bind_map.prog_fd = get_rand_bpf_prog_fd();
		attr->prog_bind_map.map_fd = get_rand_bpf_fd();
		attr->prog_bind_map.flags = 0;
		rec->a3 = sizeof(attr->prog_bind_map);
		break;

	case BPF_RAW_TRACEPOINT_OPEN:
		attr->raw_tracepoint.prog_fd = get_rand_bpf_prog_fd();
		attr->raw_tracepoint.name = (u64) RAND_ARRAY(bpf_raw_tp_names);
		rec->a3 = sizeof(attr->raw_tracepoint);
		break;

	default:
		rec->a3 = sizeof(union bpf_attr);
		break;
	}

	/*
	 * Snapshot the cmd alongside the heap pointer.  rec->a1 (cmd) and
	 * rec->a2 (attr) are both ABI-exposed and a sibling syscall can
	 * scribble either between syscall return and post entry; the old
	 * post handler dispatched off rec->a1 directly, so a flip from a
	 * pool-seeding cmd to BPF_PROG_LOAD would skip the insn-buffer free
	 * and a flip in the other direction would dereference attr fields
	 * that bpf_prog_load() never wrote.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->cmd = cmd;
	snap->attr = attr;
	rec->post_state = (unsigned long) snap;
}

static void post_bpf(struct syscallrecord *rec)
{
	struct bpf_post_state *snap = (struct bpf_post_state *) rec->post_state;
	union bpf_attr *attr;
	unsigned int cmd;
	int fd = rec->retval;
	unsigned long ret = rec->retval;

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

	/*
	 * Defense in depth: if something corrupted the snapshot itself,
	 * the inner attr pointer may no longer reference our heap
	 * allocation.  attr is always allocated by sanitise (no opcode
	 * skips the zmalloc), so NULL here is itself corruption -- the
	 * < 0x10000 band of looks_like_corrupted_ptr() catches it without
	 * a separate NULL guard.
	 */
	if (looks_like_corrupted_ptr(rec, snap->attr)) {
		outputerr("post_bpf: rejected suspicious snap attr=%p (post_state-scribbled?)\n",
			  snap->attr);
		deferred_freeptr(&rec->post_state);
		return;
	}

	cmd = snap->cmd;
	attr = snap->attr;

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

	switch (cmd) {
	case BPF_MAP_CREATE:
		if (fd >= 0) {
			struct object *obj = alloc_object();
			obj->bpfobj.map_fd = fd;
			obj->bpfobj.map_type = attr->map_type;
			add_object(obj, OBJ_LOCAL, OBJ_FD_BPF_MAP);
		}
		break;

	case BPF_PROG_LOAD:
		if (fd >= 0) {
			struct object *obj = alloc_object();
			obj->bpfprogobj.fd = fd;
			obj->bpfprogobj.prog_type = attr->prog_type;
			add_object(obj, OBJ_LOCAL, OBJ_FD_BPF_PROG);
		}

		/* Free the instruction buffer (allocated by both generators) */
		{
			void *ptr = (void *)(unsigned long)attr->insns;
			if (inner_ptr_ok_to_free(rec, ptr, "post_bpf/attr->insns"))
				free(ptr);
		}
		break;

	case BPF_MAP_GET_FD_BY_ID:
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
		if (fd >= 0) {
			struct object *obj = alloc_object();
			obj->bpfobj.map_fd = fd;
			obj->bpfobj.map_type = BPF_MAP_TYPE_UNSPEC;
			add_object(obj, OBJ_LOCAL, OBJ_FD_BPF_MAP);
		}
		break;

	case BPF_PROG_GET_FD_BY_ID:
		/* Same logic as BPF_MAP_GET_FD_BY_ID for prog fds. */
		if (fd >= 0) {
			struct object *obj = alloc_object();
			obj->bpfprogobj.fd = fd;
			obj->bpfprogobj.prog_type = BPF_PROG_TYPE_UNSPEC;
			add_object(obj, OBJ_LOCAL, OBJ_FD_BPF_PROG);
		}
		break;

	case BPF_LINK_CREATE:
		/*
		 * Live link fd — feed the per-child link pool so subsequent
		 * BPF_LINK_UPDATE / BPF_LINK_DETACH / BPF_ITER_CREATE calls
		 * pick it up via get_rand_bpf_link_fd() and reach the link
		 * dispatch paths instead of bouncing on EINVAL from a
		 * type-confused map fd.
		 */
		if (fd >= 0) {
			struct object *obj = alloc_object();
			obj->bpflinkobj.fd = fd;
			obj->bpflinkobj.attach_type = attr->link_create.attach_type;
			add_object(obj, OBJ_LOCAL, OBJ_FD_BPF_LINK);
		}
		break;

	case BPF_LINK_GET_FD_BY_ID:
		/*
		 * Same fd kind as LINK_CREATE returns, sourced via id-lookup.
		 * Attach type unknown at lookup time — leave it 0; it's
		 * metadata only.
		 */
		if (fd >= 0) {
			struct object *obj = alloc_object();
			obj->bpflinkobj.fd = fd;
			obj->bpflinkobj.attach_type = 0;
			add_object(obj, OBJ_LOCAL, OBJ_FD_BPF_LINK);
		}
		break;

	case BPF_BTF_LOAD:
	case BPF_BTF_GET_FD_BY_ID:
		/*
		 * BTF fd, either freshly parsed from a (typically malformed)
		 * BTF blob or sourced via id-lookup against the kernel's btf
		 * id table.  Feed the per-child BTF pool so the BTF-specific
		 * dispatch in BPF_OBJ_GET_INFO_BY_FD has fds to operate on.
		 */
		if (fd >= 0) {
			struct object *obj = alloc_object();
			obj->bpfbtfobj.fd = fd;
			add_object(obj, OBJ_LOCAL, OBJ_FD_BPF_BTF);
		}
		break;

	case BPF_PROG_ATTACH:
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
		if (rec->retval == 0) {
			union bpf_attr detach;

			memset(&detach, 0, sizeof(detach));
			detach.target_fd = attr->target_fd;
			detach.attach_bpf_fd = attr->attach_bpf_fd;
			detach.attach_type = attr->attach_type;
			(void) syscall(__NR_bpf, BPF_PROG_DETACH,
				       &detach, sizeof(detach));
		}
		break;

	default:
		break;
	}

	/* Close fds returned by commands not tracked above.  The
	 * remaining commands that can return an fd are OBJ_GET,
	 * RAW_TRACEPOINT_OPEN, ENABLE_STATS, ITER_CREATE, and
	 * TOKEN_CREATE — none of them produce a kind of fd that fits
	 * one of our pools, so they get closed immediately to avoid
	 * leaking.  We can't blindly close on all commands because
	 * non-fd commands return 0 for success, and closing fd 0 would
	 * destroy stdin. */
	if (fd >= 0) {
		switch (cmd) {
		case BPF_MAP_CREATE:
		case BPF_PROG_LOAD:
		case BPF_MAP_GET_FD_BY_ID:
		case BPF_PROG_GET_FD_BY_ID:
		case BPF_LINK_CREATE:
		case BPF_LINK_GET_FD_BY_ID:
		case BPF_BTF_LOAD:
		case BPF_BTF_GET_FD_BY_ID:
			/* Already tracked above. */
			break;
		case BPF_OBJ_GET:
		case BPF_RAW_TRACEPOINT_OPEN:
		case BPF_ENABLE_STATS:
		case BPF_ITER_CREATE:
		case BPF_TOKEN_CREATE:
			close(fd);
			break;
		default:
			break;
		}
	}

	deferred_free_enqueue(attr, NULL);
	deferred_freeptr(&rec->post_state);
}

static unsigned long bpf_cmds[] = {
	BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM, BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD, BPF_OBJ_GET,
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

	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "cmd", [1] = "uattr", [2] = "size" },
	.arg_params[0].list = ARGLIST(bpf_cmds),
	.sanitise = sanitise_bpf,
	.post = post_bpf,
};
#endif
