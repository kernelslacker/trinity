/*
 * syscalls/bpf-prog.c -- BPF_PROG_* command family sanitisers and
 * post handlers carved out of syscalls/bpf.c.
 *
 * Covers PROG_LOAD (with its bpf_prog_load / get_kern_version /
 * bpf_raw_tp_names / license helpers, the classic-vs-eBPF insn buffer
 * split, and the sk_lookup post-attach lifecycle), PROG_ATTACH /
 * PROG_DETACH, PROG_TEST_RUN, and RAW_TRACEPOINT_OPEN.  The RAW
 * tracepoint arm rides here because it consumes a prog_fd (via
 * get_rand_bpf_prog_fd) and the fixed name-pool for raw tracepoint
 * names has no independent object type of its own.
 *
 * The aggregator syscalls/bpf.c dispatches into these via the externs
 * in bpf-internal.h.
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
 * bpf_prog_types[] also lives in struct_catalog.c alongside the
 * MAP_CREATE / PROG_LOAD variants for the same shared-vocabulary
 * reason as bpf_map_types[].  Declared extern in include/bpf.h.
 */

static const char license[] = "GPLv2";

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
	/* Rotate log_level over the full BPF_LOG_MASK range (0-15) so that
	 * BPF_LOG_FIXED (8), BPF_LOG_STATS (4), and all their combinations
	 * receive coverage.  One value in 17 is deliberately out-of-mask (0x10)
	 * to exercise the log_level & ~BPF_LOG_MASK reject arm in
	 * bpf_verifier_log_attr_valid().  BPF_LOG_MASK = 0xF. */
	unsigned int log_level_raw = rnd_modulo_u32(17); /* dead-arm-detect: not a multi-arm dispatch */
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

void post_bpf_prog_load(int fd, bool attr_readable, union bpf_attr *attr,
			bool classic_bpf_insns)
{
	if (fd < 0)
		__atomic_add_fetch(&shm->stats.ebpf_gen.bpf_prog_load_rejected, 1, __ATOMIC_RELAXED);

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
