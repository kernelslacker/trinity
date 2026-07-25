/*
 * struct_catalog/bpf-link.c -- BPF_LINK_* command family field tables
 * carved out of struct_catalog/bpf.c.  Covers BPF_LINK_UPDATE /
 * BPF_LINK_DETACH plus the nested LINK_CREATE sub-variant fan-out
 * (BASE, ITER, PERF_EVENT, TRACING, TRACING_MULTI, KPROBE_MULTI,
 * UPROBE_MULTI, NETFILTER, TCX, NETKIT, CGROUP).
 *
 * Tables are `const` (not `static const`) so the aggregator variant
 * table's designated-init `.fields =` references resolve via the
 * externs in struct_catalog-internal.h.  struct_catalog.h and arch.h
 * are #included unconditionally so this TU is never empty when USE_BPF
 * is off.
 */

#include <stddef.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

#ifdef USE_BPF
#include <linux/netfilter.h>

#include "bpf.h"

/*
 * uprobe_multi.flags bit added in v7.2-rc1: when set, the kernel reads
 * link_create.uprobe_multi.path_fd as an fd referring to the target
 * binary instead of copying path in as a filename string.  Fallback to
 * the upstream value so older /usr/include/linux/bpf.h still builds.
 */
#ifndef BPF_F_UPROBE_MULTI_PATH_FD
#define BPF_F_UPROBE_MULTI_PATH_FD	(1U << 1)
#endif

/*
 * The remaining annotated variants live inside NAMED struct
 * members of union bpf_attr (link_update.*, link_detach.*, ...),
 * so offsetof and the schema field names use dotted forms.
 * find_field_index_in walks the local fields[] by strcmp on the
 * dotted name; FT_LEN_BYTES.buf_field below uses the same form
 * so the pairing resolves.
 *
 * BPF_PROG_ASSOC_STRUCT_OPS is one of the variants in this tail
 * group per the design doc, but the prog_assoc_struct_ops named
 * struct member is absent from the local uapi vintage; the cmd
 * itself is only available via syscalls/bpf.c's fallback #define.
 * Intentionally skipped.
 */
const struct struct_field bpf_attr_LINK_UPDATE_fields[BPF_ATTR_LINK_UPDATE_FIELDS_N] = {
	FIELDX(union bpf_attr, link_update.link_fd, FT_FD),
	FIELDX(union bpf_attr, link_update.new_prog_fd, FT_FD),
	FIELDX(union bpf_attr, link_update.flags, FT_FLAGS,
	       .u.flags.mask = BPF_F_REPLACE),
	FIELDX(union bpf_attr, link_update.old_prog_fd, FT_FD),
};

const struct struct_field bpf_attr_LINK_DETACH_fields[BPF_ATTR_LINK_DETACH_FIELDS_N] = {
	FIELDX(union bpf_attr, link_detach.link_fd, FT_FD),
};

/*
 * LINK_CREATE outer variant.  attach_type is the inner discriminator
 * for the link_create tail sub-union -- nested_variants[] is not yet
 * populated with the per-attach-type tails.  The four head fields
 * (prog_fd/map_fd, target_fd/target_ifindex, attach_type, flags) sit
 * at the union's offsets 0/4/8/12 and are shared across every
 * sub-variant, so they live here on the outer variant rather than
 * being repeated on each arm.
 *
 * The two anonymous unions (prog_fd|map_fd, target_fd|target_ifindex)
 * each get one FT_FD slot; the kernel reads the same bytes either
 * way, and the broader-semantic arm (prog_fd, target_fd) is the more
 * common live shape.
 *
 * flags annotated FT_RAW: the mask is per-attach-type and the head
 * field can't express that -- leaving it as a random splat lets the
 * verifier reject unknown bits without us committing to a wrong-
 * per-attach mask.  Revisit by moving flags onto each sub-variant.
 */
const struct struct_field bpf_attr_LINK_CREATE_fields[BPF_ATTR_LINK_CREATE_FIELDS_N] = {
	FIELDX(union bpf_attr, link_create.prog_fd, FT_FD),
	FIELDX(union bpf_attr, link_create.target_fd, FT_FD),
	FIELDX(union bpf_attr, link_create.attach_type, FT_ENUM,
	       .u.enum_ = { bpf_attach_types, ARRAY_SIZE(bpf_attach_types) },
	       .mutate_weight = 200),
	FIELD(union bpf_attr, link_create.flags),
};

/*
 * BASE sub-variant.  Catch-all for attach types that have no
 * specific arm (BPF_FLOW_DISSECTOR, BPF_SK_LOOKUP, ...).  Also runs
 * unconditionally as the shared head pass before any specific arm
 * overlays its tail -- the TRACING arm relies on this for the
 * target_btf_id slot it overlays a cookie on top of.
 */
const struct struct_field bpf_attr_LINK_CREATE_BASE_fields[] = {
	FIELD(union bpf_attr, link_create.target_btf_id),
};

const struct union_variant bpf_attr_LINK_CREATE_base = {
	.name		= "LINK_CREATE/BASE",
	.fields		= bpf_attr_LINK_CREATE_BASE_fields,
	.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_BASE_fields),
	.effective_size	= offsetof(union bpf_attr, link_create.target_btf_id) +
			  sizeof(((union bpf_attr *)NULL)->link_create.target_btf_id),
};

/*
 * Per-attach-type discriminator-value sets for the link_create
 * sub-variants.  Single-value arms use the .discrim_value scalar on
 * the union_variant entry; multi-value arms (TRACING here, CGROUP
 * later) use .discrim_values[] so one entry covers them all.
 *
 * TRACING covers the fentry/fexit/modify-return/LSM/raw-tp/fsession
 * family -- any attach type that the kernel routes through the
 * tracing-link path, all of which share the (target_btf_id, cookie)
 * tail shape on top of the BASE arm's target_btf_id slot.
 */
const unsigned long bpf_attach_types_tracing[] = {
	BPF_TRACE_FENTRY, BPF_TRACE_FEXIT, BPF_MODIFY_RETURN,
	BPF_LSM_MAC, BPF_LSM_CGROUP, BPF_TRACE_RAW_TP,
	BPF_TRACE_FSESSION,
#ifndef USE_BPF_LINK_CREATE_TRACING_MULTI
	/*
	 * Older uapi without link_create.tracing_multi: fall back to
	 * this arm's (target_btf_id, cookie) overlay so the multi
	 * attach types still get a cataloged tail.  When the gate is
	 * on they migrate to the TRACING_MULTI arm below.
	 */
	BPF_TRACE_FENTRY_MULTI, BPF_TRACE_FEXIT_MULTI,
	BPF_TRACE_FSESSION_MULTI,
#endif
};

/*
 * ITER sub-variant: iter_info is a user pointer to a bpf_iter_link_info
 * blob the verifier walks; the schema fill plants random bytes so the
 * kernel's first-pass copy_from_user succeeds and the iter-type
 * dispatch runs.  iter_info_len pairs back via FT_LEN_BYTES.
 */
const struct struct_field bpf_attr_LINK_CREATE_ITER_fields[] = {
	FIELDX(union bpf_attr, link_create.iter_info, FT_PTR_BYTES,
	       .u.ptr_bytes = { .len_field = "link_create.iter_info_len",
				.optional = true,
				.max_bytes = 128 }),
	FIELDX(union bpf_attr, link_create.iter_info_len, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "link_create.iter_info",
			     .optional = true }),
};

/*
 * PERF_EVENT sub-variant: a single u64 cookie at the inner-union
 * leading offset.  Random bytes are fine -- the kernel passes the
 * value through verbatim to BPF helpers without interpretation.
 */
const struct struct_field bpf_attr_LINK_CREATE_PERF_EVENT_fields[] = {
	FIELD(union bpf_attr, link_create.perf_event.bpf_cookie),
};

/*
 * TRACING sub-variant: overlays a u64 cookie on top of the BASE arm's
 * target_btf_id (the inner struct's first 4 bytes alias the BASE
 * target_btf_id slot per the uapi comment).  cookie lives at offset 8
 * within the inner struct -- u64 natural alignment puts it after
 * 4 bytes of pad, not immediately after target_btf_id as the spec
 * draft assumed.  effective_size therefore lands at 32, not 28.
 */
const struct struct_field bpf_attr_LINK_CREATE_TRACING_fields[] = {
	FIELD(union bpf_attr, link_create.tracing.cookie),
};

/*
 * NETFILTER / TCX / NETKIT / CGROUP_MULTI sub-variants for
 * LINK_CREATE.  Three share an identical inner layout
 * (relative_fd|relative_id + expected_revision); the cgroup arm
 * claims every BPF_CGROUP_* attach type via discrim_values[] so one
 * entry covers the ~28-way fan-out without cloning.
 *
 * Netfilter's hooknum is bounded by NF_INET_NUMHOOKS (5 hooks,
 * PREROUTING..POSTROUTING); pf is a small fixed NFPROTO_* set --
 * INET/IPV4/IPV6/ARP/NETDEV/BRIDGE -- without which the kernel's
 * dispatch never reaches the per-pf hook list.
 */
const unsigned long netfilter_pfs[] = {
	NFPROTO_INET, NFPROTO_IPV4, NFPROTO_IPV6,
	NFPROTO_ARP, NFPROTO_NETDEV, NFPROTO_BRIDGE,
};

const struct struct_field bpf_attr_LINK_CREATE_NETFILTER_fields[] = {
	FIELDX(union bpf_attr, link_create.netfilter.pf, FT_ENUM,
	       .u.enum_ = { netfilter_pfs, ARRAY_SIZE(netfilter_pfs) },
	       .mutate_weight = 150),
	FIELDX(union bpf_attr, link_create.netfilter.hooknum, FT_RANGE,
	       .u.range = { 0, NF_INET_NUMHOOKS - 1 }),
	FIELD(union bpf_attr, link_create.netfilter.priority),
	FIELDX(union bpf_attr, link_create.netfilter.flags, FT_FLAGS,
	       .u.flags.mask = BPF_F_NETFILTER_IP_DEFRAG),
};

/*
 * TCX and NETKIT share the layout (relative_fd|relative_id +
 * expected_revision); the field annotations differ only in dotted
 * path so the two are typed out separately rather than aliased.
 */
const struct struct_field bpf_attr_LINK_CREATE_TCX_fields[] = {
	FIELDX(union bpf_attr, link_create.tcx.relative_fd, FT_FD),
	FIELD(union bpf_attr, link_create.tcx.expected_revision),
};

const struct struct_field bpf_attr_LINK_CREATE_NETKIT_fields[] = {
	FIELDX(union bpf_attr, link_create.netkit.relative_fd, FT_FD),
	FIELD(union bpf_attr, link_create.netkit.expected_revision),
};

/*
 * The link_create.cgroup named member (mprog relative_fd /
 * expected_revision for cgroup links) was added in 6.13, so this table
 * and its nested-variant entry below are gated on
 * USE_BPF_LINK_CREATE_CGROUP.  When absent, cgroup attach types fall
 * through to the LINK_CREATE base pass rather than this arm.
 */
#ifdef USE_BPF_LINK_CREATE_CGROUP
const struct struct_field bpf_attr_LINK_CREATE_CGROUP_fields[] = {
	FIELDX(union bpf_attr, link_create.cgroup.relative_fd, FT_FD),
	FIELD(union bpf_attr, link_create.cgroup.expected_revision),
};
#endif

const unsigned long bpf_attach_types_tcx[] = {
	BPF_TCX_INGRESS, BPF_TCX_EGRESS,
};

const unsigned long bpf_attach_types_netkit[] = {
	BPF_NETKIT_PRIMARY, BPF_NETKIT_PEER,
};

/*
 * CGROUP_MULTI claims every BPF_CGROUP_* attach type.  The cgroup
 * arm's inner struct is shared across all of them; per-attach
 * semantics live in kernel/bpf/cgroup.c and don't affect the wire
 * shape sanitise produces.
 */
const unsigned long bpf_attach_types_cgroup[] = {
	BPF_CGROUP_INET_INGRESS, BPF_CGROUP_INET_EGRESS,
	BPF_CGROUP_INET_SOCK_CREATE, BPF_CGROUP_SOCK_OPS,
	BPF_CGROUP_DEVICE,
	BPF_CGROUP_INET4_BIND, BPF_CGROUP_INET6_BIND,
	BPF_CGROUP_INET4_CONNECT, BPF_CGROUP_INET6_CONNECT,
	BPF_CGROUP_INET4_POST_BIND, BPF_CGROUP_INET6_POST_BIND,
	BPF_CGROUP_UDP4_SENDMSG, BPF_CGROUP_UDP6_SENDMSG,
	BPF_CGROUP_SYSCTL,
	BPF_CGROUP_UDP4_RECVMSG, BPF_CGROUP_UDP6_RECVMSG,
	BPF_CGROUP_GETSOCKOPT, BPF_CGROUP_SETSOCKOPT,
	BPF_CGROUP_INET4_GETPEERNAME, BPF_CGROUP_INET6_GETPEERNAME,
	BPF_CGROUP_INET4_GETSOCKNAME, BPF_CGROUP_INET6_GETSOCKNAME,
	BPF_CGROUP_INET_SOCK_RELEASE,
	BPF_CGROUP_UNIX_CONNECT, BPF_CGROUP_UNIX_SENDMSG,
	BPF_CGROUP_UNIX_RECVMSG, BPF_CGROUP_UNIX_GETPEERNAME,
	BPF_CGROUP_UNIX_GETSOCKNAME,
};

/*
 * KPROBE_MULTI / UPROBE_MULTI sub-variants.  Both gate three or four
 * sibling pointer arrays with a single cnt slot, exercising the new
 * multi-pair LEN extension (buf_fields[]).  cookies (KPROBE) /
 * ref_ctr_offsets+cookies (UPROBE) stay optional via .max_count and
 * the pre-pin pass treats them uniformly with the required siblings.
 *
 * The element type is scalar (u64 for symbol pointers, addresses,
 * file offsets, cookies) -- this is the first user of FT_PTR_ARRAY's
 * elem_size override path that lets the pointer pass size its
 * sub-buffer without a cataloged elem_struct.
 */
const unsigned long bpf_attach_types_kprobe_multi[] = {
	BPF_TRACE_KPROBE_MULTI, BPF_TRACE_KPROBE_SESSION,
};

const char *const bpf_attr_link_create_kprobe_multi_arrays[] = {
	"link_create.kprobe_multi.syms",
	"link_create.kprobe_multi.addrs",
	"link_create.kprobe_multi.cookies",
};

const struct struct_field bpf_attr_LINK_CREATE_KPROBE_MULTI_fields[] = {
	FIELDX(union bpf_attr, link_create.kprobe_multi.flags, FT_FLAGS,
	       .u.flags.mask = BPF_F_KPROBE_MULTI_RETURN),
	FIELDX(union bpf_attr, link_create.kprobe_multi.cnt, FT_LEN_COUNT,
	       .u.len_of = { .buf_fields = bpf_attr_link_create_kprobe_multi_arrays,
			     .n_buf_fields = ARRAY_SIZE(bpf_attr_link_create_kprobe_multi_arrays) }),
	FIELDX(union bpf_attr, link_create.kprobe_multi.syms, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.kprobe_multi.addrs, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.kprobe_multi.cookies, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
};

const unsigned long bpf_attach_types_uprobe_multi[] = {
	BPF_TRACE_UPROBE_MULTI, BPF_TRACE_UPROBE_SESSION,
};

const char *const bpf_attr_link_create_uprobe_multi_arrays[] = {
	"link_create.uprobe_multi.offsets",
	"link_create.uprobe_multi.ref_ctr_offsets",
	"link_create.uprobe_multi.cookies",
};

const struct struct_field bpf_attr_LINK_CREATE_UPROBE_MULTI_fields[] = {
	FIELDX(union bpf_attr, link_create.uprobe_multi.path, FT_PTR_BYTES,
	       .u.ptr_bytes = { .null_terminated = true,
				.optional = true,
				.max_bytes = 256 }),
	FIELDX(union bpf_attr, link_create.uprobe_multi.offsets, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.uprobe_multi.ref_ctr_offsets, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.uprobe_multi.cookies, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.uprobe_multi.cnt, FT_LEN_COUNT,
	       .u.len_of = { .buf_fields = bpf_attr_link_create_uprobe_multi_arrays,
			     .n_buf_fields = ARRAY_SIZE(bpf_attr_link_create_uprobe_multi_arrays) }),
	FIELDX(union bpf_attr, link_create.uprobe_multi.flags, FT_FLAGS,
	       .u.flags.mask = BPF_F_UPROBE_MULTI_RETURN |
			       BPF_F_UPROBE_MULTI_PATH_FD),
	FIELD(union bpf_attr, link_create.uprobe_multi.pid),
};

/*
 * TRACING_MULTI sub-variant: attaches a single tracing program to a
 * set of kernel functions in one call.  ids[] is the btf_id array of
 * targets, cookies[] the paired per-target cookie array, cnt bounds
 * both -- the FT_LEN_COUNT tail sizes both sibling pointer arrays off
 * the single count field, same shape as the *probe_multi arms.
 *
 * Gated on USE_BPF_LINK_CREATE_TRACING_MULTI because the tracing_multi
 * named union member postdates the trinity baseline and struct members
 * can't be #ifndef-shimmed -- offsetof() needs the real member.  When
 * the gate is off the multi attach types stay in
 * bpf_attach_types_tracing[] above and fall through to the TRACING
 * arm's (target_btf_id, cookie) overlay.
 */
#ifdef USE_BPF_LINK_CREATE_TRACING_MULTI
const unsigned long bpf_attach_types_tracing_multi[] = {
	BPF_TRACE_FENTRY_MULTI, BPF_TRACE_FEXIT_MULTI,
	BPF_TRACE_FSESSION_MULTI,
};

const char *const bpf_attr_link_create_tracing_multi_arrays[] = {
	"link_create.tracing_multi.ids",
	"link_create.tracing_multi.cookies",
};

const struct struct_field bpf_attr_LINK_CREATE_TRACING_MULTI_fields[] = {
	FIELDX(union bpf_attr, link_create.tracing_multi.ids, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.tracing_multi.cookies, FT_PTR_ARRAY,
	       .u.ptr_array = { .elem_size = sizeof(uint64_t),
				.max_count = 32 }),
	FIELDX(union bpf_attr, link_create.tracing_multi.cnt, FT_LEN_COUNT,
	       .u.len_of = { .buf_fields = bpf_attr_link_create_tracing_multi_arrays,
			     .n_buf_fields = ARRAY_SIZE(bpf_attr_link_create_tracing_multi_arrays) }),
};
#endif

/*
 * LINK_CREATE nested sub-variant table.  attach_type read off the
 * just-filled buffer at offset 8 (relative to the union, equal to
 * link_create.attach_type since link_create is at union offset 0)
 * selects which entry's tail fields[] overlay onto the BASE pass.
 */
const struct union_variant bpf_attr_LINK_CREATE_nested[BPF_ATTR_LINK_CREATE_NESTED_N] = {
	{
		.discrim_value	= BPF_TRACE_ITER,
		.name		= "LINK_CREATE/ITER",
		.fields		= bpf_attr_LINK_CREATE_ITER_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_ITER_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.iter_info_len) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.iter_info_len),
	},
	{
		.discrim_value	= BPF_PERF_EVENT,
		.name		= "LINK_CREATE/PERF_EVENT",
		.fields		= bpf_attr_LINK_CREATE_PERF_EVENT_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_PERF_EVENT_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.perf_event.bpf_cookie) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.perf_event.bpf_cookie),
	},
	{
		.discrim_values	    = bpf_attach_types_tracing,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_tracing),
		.name		= "LINK_CREATE/TRACING",
		.fields		= bpf_attr_LINK_CREATE_TRACING_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_TRACING_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.tracing.cookie) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.tracing.cookie),
	},
#ifdef USE_BPF_LINK_CREATE_TRACING_MULTI
	{
		.discrim_values	    = bpf_attach_types_tracing_multi,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_tracing_multi),
		.name		= "LINK_CREATE/TRACING_MULTI",
		.fields		= bpf_attr_LINK_CREATE_TRACING_MULTI_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_TRACING_MULTI_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.tracing_multi.cnt) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.tracing_multi.cnt),
	},
#endif
	{
		.discrim_values	    = bpf_attach_types_kprobe_multi,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_kprobe_multi),
		.name		= "LINK_CREATE/KPROBE_MULTI",
		.fields		= bpf_attr_LINK_CREATE_KPROBE_MULTI_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_KPROBE_MULTI_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.kprobe_multi.cookies) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.kprobe_multi.cookies),
	},
	{
		.discrim_values	    = bpf_attach_types_uprobe_multi,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_uprobe_multi),
		.name		= "LINK_CREATE/UPROBE_MULTI",
		.fields		= bpf_attr_LINK_CREATE_UPROBE_MULTI_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_UPROBE_MULTI_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.uprobe_multi.pid) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.uprobe_multi.pid),
	},
	{
		.discrim_value	= BPF_NETFILTER,
		.name		= "LINK_CREATE/NETFILTER",
		.fields		= bpf_attr_LINK_CREATE_NETFILTER_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_NETFILTER_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.netfilter.flags) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.netfilter.flags),
	},
	{
		.discrim_values	    = bpf_attach_types_tcx,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_tcx),
		.name		= "LINK_CREATE/TCX",
		.fields		= bpf_attr_LINK_CREATE_TCX_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_TCX_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.tcx.expected_revision) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.tcx.expected_revision),
	},
	{
		.discrim_values	    = bpf_attach_types_netkit,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_netkit),
		.name		= "LINK_CREATE/NETKIT",
		.fields		= bpf_attr_LINK_CREATE_NETKIT_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_NETKIT_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.netkit.expected_revision) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.netkit.expected_revision),
	},
#ifdef USE_BPF_LINK_CREATE_CGROUP
	{
		.discrim_values	    = bpf_attach_types_cgroup,
		.num_discrim_values = ARRAY_SIZE(bpf_attach_types_cgroup),
		.name		= "LINK_CREATE/CGROUP",
		.fields		= bpf_attr_LINK_CREATE_CGROUP_fields,
		.num_fields	= ARRAY_SIZE(bpf_attr_LINK_CREATE_CGROUP_fields),
		.effective_size	= offsetof(union bpf_attr,
					   link_create.cgroup.expected_revision) +
				  sizeof(((union bpf_attr *)NULL)
					 ->link_create.cgroup.expected_revision),
	},
#endif
};

#endif /* USE_BPF */
