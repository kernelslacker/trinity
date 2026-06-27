#pragma once

/*
 * Per-attribute kind metadata used by the netlink message generator's
 * spec-driven attribute path.  Lives in its own header so per-genetlink
 * family grammar tables (net/netlink-genl-fam-*.c) can populate
 * nla_attr_spec arrays without depending on net/netlink-msg.c
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
	 * sweeping the [4, max_len] range NLA_KIND_BINARY uses: any
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
};

struct nla_attr_spec {
	unsigned short type;
	unsigned short kind;
	unsigned short max_len;	/* upper bound on payload; 0 for fixed kinds */
	unsigned short min_len;	/* lower bound; for NLA_KIND_BINARY_FIXED2 the
				 * payload is exactly one of {min_len,
				 * max_len}.  Zero on other kinds. */
};
