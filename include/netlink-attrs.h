#pragma once

/*
 * Per-attribute kind metadata used by the netlink message generator's
 * spec-driven attribute path.  Lives in its own header so per-genetlink
 * family grammar tables (net/netlink/genl/<family>.c) can populate
 * nla_attr_spec arrays without depending on net/netlink/msg.c
 * internals.  The fields mirror what the kernel-side nla_policy struct
 * cares about so the generator can size each attribute the way the
 * family's nla_validate gate expects.
 */
enum nla_kind {
	NLA_KIND_U8,
	NLA_KIND_U16,
	NLA_KIND_U32,
	NLA_KIND_U64,
	NLA_KIND_BINARY,
	NLA_KIND_STRING,
	NLA_KIND_NESTED,
	NLA_KIND_FLAG,
	/* Binary blob whose length the kernel constrains to exactly one
	 * of two values (typically AES-128 vs AES-256 key bytes).  Picks
	 * uniformly between min_len and max_len per emission rather than
	 * sweeping the [min_len, max_len] range NLA_KIND_BINARY uses: any
	 * intermediate length is a guaranteed kernel reject, so spending
	 * fuzz budget there is wasted work that only flips -EINVAL on
	 * the validate side. */
	NLA_KIND_BINARY_FIXED2,
	/* Sized the same way as NLA_KIND_STRING, but filled by the
	 * cpu-list / bitmap-list generator (rand/text-payloads.c) so the
	 * kernel-side cpulist_parse() / bitmap_parselist() path actually
	 * sees plausibly-shaped input.  Use for attrs the kernel feeds
	 * to those parsers — e.g. taskstats REGISTER_CPUMASK. */
	NLA_KIND_STRING_CPULIST,
	/* A scalar the kernel policy bounds, in network byte order, which is
	 * how the netfilter NLA_BE16 / NLA_BE32 policies read it.  max_len
	 * holds the bound rather than a length.  The _MASK kinds mirror
	 * NLA_POLICY_MASK and fill a random subset of the max_len bits, so
	 * the mask has to fit in 16 bits; NLA_KIND_BE32_MAX mirrors
	 * NLA_POLICY_MAX and fills a number in [0, max_len].  One draw in
	 * eight is random bytes, so the policy's reject arm still sees
	 * traffic. */
	NLA_KIND_BE16_MASK,
	NLA_KIND_BE32_MASK,
	NLA_KIND_BE32_MAX,
	/* A scalar the handler, not the policy, narrows to a few values,
	 * which the spec lists in oneof.  Stored as the policy's width reads
	 * it: a byte, or big-endian.  One draw in eight is random bytes, so
	 * the handler's reject arm still sees traffic. */
	NLA_KIND_U8_ONEOF,
	NLA_KIND_BE16_ONEOF,
	NLA_KIND_BE32_ONEOF,
	/* A nest the kernel validates as NLA_POLICY_NESTED_ARRAY: its
	 * children are elements, each an NLA_F_NESTED attribute holding an
	 * attribute stream of its own, drawn from the spec's nest table.
	 * The elements' own types are not checked; they are numbered from
	 * 0. */
	NLA_KIND_NESTED_ARRAY,
};

struct nla_attr_spec {
	unsigned short type;
	unsigned short kind;
	unsigned short max_len;	/* upper bound on payload; 0 for fixed kinds;
				 * the mask or maximum for the bounded
				 * scalar kinds */
	unsigned short min_len;	/* lower bound; for NLA_KIND_BINARY_FIXED2 the
				 * payload is exactly one of {min_len,
				 * max_len}.  Zero on other kinds. */

	/* NLA_KIND_NESTED, NLA_KIND_NESTED_ARRAY: the table the nest's
	 * children are drawn from, n_nest long, typed as the nest's own
	 * kernel policy types them.  NULL draws them from the table the
	 * nest is in, whose ids belong to the outer policy.  A child that
	 * does not fit a nest with a table is dropped, where the last child
	 * of one without is cut short to fill the window. */
	const struct nla_attr_spec *nest;
	unsigned int n_nest;

	/* The *_ONEOF kinds: the n_oneof values the attribute is drawn
	 * from, in host order. */
	const unsigned int *oneof;
	unsigned int n_oneof;
};
