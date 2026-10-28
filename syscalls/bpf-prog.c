/*
 * syscalls/bpf-prog.c -- BPF_PROG_* command family sanitisers and post
 * handlers: PROG_LOAD (the classic-vs-eBPF insn buffer split and the sk_lookup
 * post-attach lifecycle), PROG_ATTACH / PROG_DETACH, PROG_TEST_RUN,
 * RAW_TRACEPOINT_OPEN and PROG_STREAM_OPEN.  The raw tracepoint and stream
 * arms ride here because they consume a prog_fd, and neither has an object
 * pool of its own: the tracepoint arm draws a name from a fixed list, and
 * the stream fd it opens is pooled as a plain file.
 */

#ifdef USE_BPF

#include <sys/utsname.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/version.h>

#include "bpf.h"
#include "bpf-internal.h"
#include "deferred-free.h"
#include "fd.h"
#include "net.h"
#include "objects.h"
#include "publish_resource.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
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

/*
 * bpf_prog_types[] is defined in struct_catalog/bpf.c so the FT_ENUM
 * annotation on union bpf_attr.prog_type (struct_catalog/bpf-prog.c) and
 * the prog_type draw in bpf_prog_load() share one vocabulary.  Declared
 * extern in include/bpf.h.
 */

static const char license[] = "GPLv2";

/*
 * The prog_flags bpf_prog_load() takes, from the mask it checks them
 * against, less BPF_F_TOKEN_FD, which has an arm of its own.  The verifier
 * takes these on a program of any type: how strict its alignment checks
 * are, the test modes, and BPF_F_ARENA_SCALAR, which matters only to a
 * program with an arena but is refused with -EOPNOTSUPP wherever the JIT
 * lacks bpf_jit_supports_arena_scalar(): x86-64 and arm64.
 */
static const unsigned long bpf_prog_load_flags[] = {
	BPF_F_STRICT_ALIGNMENT,
	BPF_F_ANY_ALIGNMENT,
	BPF_F_TEST_RND_HI32,
	BPF_F_TEST_STATE_FREQ,
	BPF_F_TEST_REG_INVARIANTS,
#if defined(__x86_64__) || defined(__aarch64__)
	BPF_F_ARENA_SCALAR,
#endif
};

/*
 * Three loads in four set no flags, so the common path keeps loading.  The
 * rest take a subset of the list above, and the flags the kernel takes only
 * of some programs go to those:
 *
 * BPF_F_SLEEPABLE passes can_be_sleepable() only for a type that needs no
 * attach target: kprobe, which then attaches only to a uprobe event,
 * tracepoint and raw tracepoint.  Any other type is refused with -EINVAL.
 *
 * BPF_F_XDP_HAS_FRAGS is XDP's: the attach path in net/core/dev.c reads it.
 *
 * BPF_F_XDP_DEV_BOUND_ONLY reaches bpf_prog_dev_bound_init() only with a
 * prog_ifindex, and that takes no flag but this one and
 * BPF_F_XDP_HAS_FRAGS, the latter only beside it, so the draw replaces the
 * subset.  It names a small ifindex: the netdev has to exist and have
 * ndo_bpf for the load to get further.
 */
static void bpf_prog_load_set_flags(union bpf_attr *attr)
{
	if (!ONE_IN(4))
		return;

	if (attr->prog_type == BPF_PROG_TYPE_XDP && ONE_IN(4)) {
		attr->prog_flags = BPF_F_XDP_DEV_BOUND_ONLY;
		if (RAND_BOOL())
			attr->prog_flags |= BPF_F_XDP_HAS_FRAGS;
		attr->prog_ifindex = 1 + rnd_modulo_u32(8);
		return;
	}

	attr->prog_flags = set_rand_bitmask(ARRAY_SIZE(bpf_prog_load_flags),
					    bpf_prog_load_flags);

	switch (attr->prog_type) {
	case BPF_PROG_TYPE_KPROBE:
	case BPF_PROG_TYPE_TRACEPOINT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
		if (ONE_IN(4))
			attr->prog_flags |= BPF_F_SLEEPABLE;
		break;
	case BPF_PROG_TYPE_XDP:
		if (RAND_BOOL())
			attr->prog_flags |= BPF_F_XDP_HAS_FRAGS;
		break;
	default:
		break;
	}
}

static bool bpf_prog_load(union bpf_attr *attr)
{
	bool classic_filter = false;

	attr->prog_type = bpf_prog_types[rnd_modulo_u32(bpf_prog_types_count)];
	bpf_prog_load_set_flags(attr);

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
	/* Rotate log_level over the full BPF_LOG_MASK range (0-15) so that
	 * BPF_LOG_FIXED (8), BPF_LOG_STATS (4), and all their combinations
	 * receive coverage.  One value in 17 is deliberately out-of-mask (0x10)
	 * to exercise the log_level & ~BPF_LOG_MASK reject arm in
	 * bpf_verifier_log_attr_valid().  BPF_LOG_MASK = 0xF. */
	unsigned int log_level_raw = rnd_modulo_u32(17);
	attr->log_level = log_level_raw < 16 ? log_level_raw : 0x10U;
	if (attr->log_level == 0) {
		attr->log_size = 0;
		attr->log_buf = 0;
	} else {
		attr->log_size = rnd_modulo_u32(page_size - 1) + 1;
		attr->log_buf = (u64) get_writable_address(page_size);
		{
			unsigned long log_buf_addr = attr->log_buf;
			avoid_shared_buffer_inout(&log_buf_addr, page_size);
			attr->log_buf = log_buf_addr;
		}
	}
	attr->kern_version = get_kern_version();
	bpf_fill_obj_name(attr->prog_name);
	return classic_filter;
}

bool sanitise_bpf_prog_load(union bpf_attr *attr, struct syscallrecord *rec)
{
	bool classic_bpf_insns = bpf_prog_load(attr);

	/* Cover prog_name so bpf_fill_obj_name's bytes reach the kernel
	 * verifier's bpf_obj_name_cpy(), and prog_ifindex, which follows it
	 * and which BPF_F_XDP_DEV_BOUND_ONLY needs the kernel to read. */
	rec->a3 = offsetof(union bpf_attr, prog_ifindex) +
		  sizeof(attr->prog_ifindex);
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

void sanitise_bpf_prog_attach(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->target_fd = get_rand_bpf_fd();
	attr->attach_bpf_fd = get_rand_bpf_prog_fd();
	attr->attach_type = bpf_attach_types[rnd_modulo_u32(bpf_attach_types_count)];
	rec->a3 = 16;
}

void sanitise_bpf_prog_test_run(union bpf_attr *attr, struct syscallrecord *rec)
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

void sanitise_bpf_raw_tracepoint(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->raw_tracepoint.prog_fd = get_rand_bpf_prog_fd();
	attr->raw_tracepoint.name = (u64) RAND_ARRAY(bpf_raw_tp_names);
	rec->a3 = sizeof(attr->raw_tracepoint);
}

#ifdef USE_BPF_PROG_STREAM_OPEN
/*
 * bpf_prog_stream_new_fd() serves only the stdout and stderr ids and
 * prog_stream_open() refuses any flag but BPF_F_STREAM_NONBLOCK, so most
 * draws are valid and a stray id or flag (-ENOENT, -EINVAL) is the rare one.
 * A blocking stream fd sleeps in wait_event_interruptible() on an empty
 * stream until the call's alarm ends it, so only a quarter of the opens
 * leave NONBLOCK clear.
 */
void sanitise_bpf_prog_stream_open(union bpf_attr *attr, struct syscallrecord *rec)
{
	attr->prog_stream_open.prog_fd = get_rand_bpf_prog_fd();
	if (ONE_IN(16))
		attr->prog_stream_open.stream_id = rnd_u32();
	else
		attr->prog_stream_open.stream_id = RAND_BOOL() ?
			BPF_STREAM_STDOUT : BPF_STREAM_STDERR;
	if (ONE_IN(16))
		attr->prog_stream_open.flags = rnd_u32();
	else
		attr->prog_stream_open.flags = ONE_IN(4) ?
			0 : BPF_F_STREAM_NONBLOCK;
	rec->a3 = sizeof(attr->prog_stream_open);
}
#endif

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
 * bpf_prog_load_fixup_attach_type() (kernel/bpf/syscall.c) stands in the
 * attach type a cgroup sock or reuseport program means by 0, which is what
 * link_create() then holds an attach type to.
 */
unsigned int bpf_prog_loaded_attach_type(unsigned int prog_type,
					 unsigned int requested)
{
	if (requested != 0)
		return requested;
	switch (prog_type) {
	case BPF_PROG_TYPE_CGROUP_SOCK:
		return BPF_CGROUP_INET_SOCK_CREATE;
	case BPF_PROG_TYPE_SK_REUSEPORT:
		return BPF_SK_REUSEPORT_SELECT;
	default:
		return 0;
	}
}

void post_bpf_prog_load(int fd, bool attr_readable, union bpf_attr *attr,
			bool classic_bpf_insns, int errnum)
{
	if (fd < 0) {
		if (errnum == EINVAL)
			__atomic_add_fetch(&shm->stats.ebpf_gen.bpf_prog_load_einval, 1, __ATOMIC_RELAXED);
		else
			__atomic_add_fetch(&shm->stats.ebpf_gen.bpf_prog_load_rejected, 1, __ATOMIC_RELAXED);
	}

	if (fd >= 0 && attr_readable) {
		struct object *obj;

		obj = publish_resource(OBJ_FD_BPF_PROG, fd,
				       &(struct resource_meta){.subtype = attr->prog_type});
		if (obj != NULL)
			obj->bpfprogobj.expected_attach_type =
				bpf_prog_loaded_attach_type(attr->prog_type,
							    attr->expected_attach_type);
	}

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
	 * tracked by another site, that plain free() races the original
	 * site's TTL-expiry drain and can double-free the chunk.
	 * Routing the proven-ours eBPF buffer through
	 * deferred_free_enqueue() keeps the bookkeeping in lock-step:
	 * enqueue consumes alloc_track and the TTL-expiry free releases it.
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

void post_bpf_prog_get_fd_by_id(int fd)
{
	/* Same logic as BPF_MAP_GET_FD_BY_ID for prog fds. */
	if (fd >= 0)
		publish_resource(OBJ_FD_BPF_PROG, fd, NULL);
}

/*
 * The bpf-stream fd BPF_PROG_STREAM_OPEN returned belongs to no provider:
 * pool it, so read() and poll() reach bpf_stream_fops and the pool's cap
 * closes it in time.  Left alone, every open that succeeds leaks one.  A
 * stdio or protected number is no fd this call made (the kernel hands out
 * only free ones), so it is neither pooled nor closed; what the pool
 * refuses past that is the stream's alone, and is closed.
 */
void post_bpf_prog_stream_open(int fd)
{
	if (fd <= 2 || fd_is_protected(fd))
		return;

	if (!pool_returned_fd(fd))
		close(fd);
}

void post_bpf_prog_attach(unsigned long ret, bool attr_readable,
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

#endif	/* USE_BPF */
