/*
 * Helper descriptor tables and helper picker for the eBPF program
 * generator.  Split out of net/bpf/ebpf.c so the tier1/tier2 emitters
 * can share the descriptor selection without pulling in the whole
 * generator TU.  Descriptor tables and their construction macros stay
 * private to this TU; only the getter, the insn-cost helper and the
 * satisfiability picker are exported through ebpf-internal.h.
 */
#include <stdint.h>
#include <linux/bpf.h>

#include "bpf.h"
#include "random.h"
#include "rnd.h"
#include "utils.h"

#include "ebpf-internal.h"

#ifdef USE_BPF

#define HD0(f) \
	{ .func = (f), .nargs = 0, .arg_kind = { 0, 0, 0, 0, 0 } }
#define HD2(f, a0, a1) \
	{ .func = (f), .nargs = 2, \
	  .arg_kind = { (a0), (a1), 0, 0, 0 } }
#define HD3(f, a0, a1, a2) \
	{ .func = (f), .nargs = 3, \
	  .arg_kind = { (a0), (a1), (a2), 0, 0 } }
#define HD4(f, a0, a1, a2, a3) \
	{ .func = (f), .nargs = 4, \
	  .arg_kind = { (a0), (a1), (a2), (a3), 0 } }

/*
 * Per-prog-type helper descriptor tables.
 *
 * Curated set: zero-arg helpers (always safe to call), plus a small
 * arg-bearing core — map_lookup/update/delete, probe_read_kernel —
 * whose prototypes we can satisfy from this generator's vocabulary.
 * No privileged helpers, no kfuncs, no socket sendmsg / override_return,
 * no skb-mutating helpers that need a live skb context.  Helpers whose
 * verifier prototype demands kinds we don't model yet stay out.
 */
static const struct helper_desc helpers_universal[] = {
	HD0(BPF_FUNC_ktime_get_ns),
	HD0(BPF_FUNC_get_prandom_u32),
	HD0(BPF_FUNC_get_smp_processor_id),
	HD0(BPF_FUNC_get_current_pid_tgid),
	HD0(BPF_FUNC_get_current_uid_gid),
	HD0(BPF_FUNC_get_numa_node_id),
	HD0(BPF_FUNC_ktime_get_boot_ns),
	HD0(BPF_FUNC_ktime_get_coarse_ns),
	HD0(BPF_FUNC_jiffies64),
	HD0(BPF_FUNC_ktime_get_tai_ns),
	HD2(BPF_FUNC_map_lookup_elem, ARG_MAP_PTR, ARG_STACK_PTR),
	HD4(BPF_FUNC_map_update_elem, ARG_MAP_PTR, ARG_STACK_PTR,
	    ARG_STACK_PTR, ARG_SCALAR),
	HD2(BPF_FUNC_map_delete_elem, ARG_MAP_PTR, ARG_STACK_PTR),
};

/* Tracing types: kprobe, tracepoint, perf_event, raw_tracepoint */
static const struct helper_desc helpers_tracing[] = {
	HD0(BPF_FUNC_ktime_get_ns),
	HD0(BPF_FUNC_get_prandom_u32),
	HD0(BPF_FUNC_get_smp_processor_id),
	HD0(BPF_FUNC_get_current_pid_tgid),
	HD0(BPF_FUNC_get_current_uid_gid),
	HD0(BPF_FUNC_get_numa_node_id),
	HD0(BPF_FUNC_ktime_get_boot_ns),
	HD0(BPF_FUNC_get_current_task),
	HD0(BPF_FUNC_get_current_cgroup_id),
	HD2(BPF_FUNC_map_lookup_elem, ARG_MAP_PTR, ARG_STACK_PTR),
	HD4(BPF_FUNC_map_update_elem, ARG_MAP_PTR, ARG_STACK_PTR,
	    ARG_STACK_PTR, ARG_SCALAR),
	HD2(BPF_FUNC_map_delete_elem, ARG_MAP_PTR, ARG_STACK_PTR),
	HD3(BPF_FUNC_probe_read_kernel, ARG_STACK_PTR, ARG_STACK_SIZE,
	    ARG_SCALAR),
};

/* Networking types: socket_filter, sched_cls, sched_act, xdp, lwt, etc. */
static const struct helper_desc helpers_networking[] = {
	HD0(BPF_FUNC_ktime_get_ns),
	HD0(BPF_FUNC_get_prandom_u32),
	HD0(BPF_FUNC_get_smp_processor_id),
	HD0(BPF_FUNC_get_current_pid_tgid),
	HD0(BPF_FUNC_get_current_uid_gid),
	HD0(BPF_FUNC_get_numa_node_id),
	HD0(BPF_FUNC_ktime_get_boot_ns),
	HD2(BPF_FUNC_map_lookup_elem, ARG_MAP_PTR, ARG_STACK_PTR),
	HD4(BPF_FUNC_map_update_elem, ARG_MAP_PTR, ARG_STACK_PTR,
	    ARG_STACK_PTR, ARG_SCALAR),
	HD2(BPF_FUNC_map_delete_elem, ARG_MAP_PTR, ARG_STACK_PTR),
};

/* Cgroup types */
static const struct helper_desc helpers_cgroup[] = {
	HD0(BPF_FUNC_ktime_get_ns),
	HD0(BPF_FUNC_get_prandom_u32),
	HD0(BPF_FUNC_get_smp_processor_id),
	HD0(BPF_FUNC_get_current_pid_tgid),
	HD0(BPF_FUNC_get_current_uid_gid),
	HD0(BPF_FUNC_get_numa_node_id),
	HD0(BPF_FUNC_ktime_get_boot_ns),
	HD0(BPF_FUNC_get_current_cgroup_id),
	HD2(BPF_FUNC_map_lookup_elem, ARG_MAP_PTR, ARG_STACK_PTR),
	HD4(BPF_FUNC_map_update_elem, ARG_MAP_PTR, ARG_STACK_PTR,
	    ARG_STACK_PTR, ARG_SCALAR),
	HD2(BPF_FUNC_map_delete_elem, ARG_MAP_PTR, ARG_STACK_PTR),
};

#define HELPER_SET(arr) { .helpers = (arr), .count = ARRAY_SIZE(arr) }

struct helper_set get_helpers_for_prog_type(unsigned int prog_type)
{
	switch (prog_type) {
	case BPF_PROG_TYPE_KPROBE:
	case BPF_PROG_TYPE_TRACEPOINT:
	case BPF_PROG_TYPE_PERF_EVENT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
	case BPF_PROG_TYPE_TRACING:
	case BPF_PROG_TYPE_LSM:
		return (struct helper_set) HELPER_SET(helpers_tracing);

	case BPF_PROG_TYPE_SOCKET_FILTER:
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
	case BPF_PROG_TYPE_XDP:
	case BPF_PROG_TYPE_LWT_IN:
	case BPF_PROG_TYPE_LWT_OUT:
	case BPF_PROG_TYPE_LWT_XMIT:
	case BPF_PROG_TYPE_LWT_SEG6LOCAL:
	case BPF_PROG_TYPE_SK_SKB:
	case BPF_PROG_TYPE_SK_MSG:
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
	case BPF_PROG_TYPE_SK_REUSEPORT:
	case BPF_PROG_TYPE_SK_LOOKUP:
	case BPF_PROG_TYPE_NETFILTER:
	case BPF_PROG_TYPE_SOCK_OPS:
		return (struct helper_set) HELPER_SET(helpers_networking);

	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		return (struct helper_set) HELPER_SET(helpers_cgroup);

	default:
		return (struct helper_set) HELPER_SET(helpers_universal);
	}
}

int helper_call_insns(const struct helper_desc *h, bool *need_init)
{
	int n = 1;	/* the BPF_CALL itself */
	int i;

	*need_init = false;
	for (i = 0; i < h->nargs; i++) {
		switch (h->arg_kind[i]) {
		case ARG_SCALAR:
		case ARG_STACK_SIZE:
		case ARG_MAP_PTR:
			n += 1;	/* MOV / MOV64_IMM */
			break;
		case ARG_STACK_PTR:
			n += 2;	/* MOV64_REG r,R10 ; ALU64_IMM SUB */
			*need_init = true;
			break;
		}
	}
	if (*need_init)
		n += 1;		/* one ST_MEM DW zero-init */
	return n;
}

/*
 * Pick a helper whose prerequisites the current reg state satisfies.
 * Only ARG_MAP_PTR has a runtime prereq (a live PTR_TO_MAP
 * register from a prior LD_MAP_FD); everything else is unconditional.
 * Returns NULL after a few unsuccessful picks so the caller can re-roll
 * the outer dispatch rather than burn the slot on a NOP.
 */
const struct helper_desc *
pick_helper_satisfiable(struct helper_set hs, const struct reg_state *rs)
{
	const struct helper_desc *h;
	int i, attempt;
	bool wants_map;

	for (attempt = 0; attempt < HELPER_PICK_RETRIES; attempt++) {
		h = &hs.helpers[rnd_modulo_u32(hs.count)];
		wants_map = false;
		for (i = 0; i < h->nargs; i++) {
			if (h->arg_kind[i] == ARG_MAP_PTR) {
				wants_map = true;
				break;
			}
		}
		if (!wants_map || rs->map_reg >= 0)
			return h;
	}
	return NULL;
}

#endif /* USE_BPF */
