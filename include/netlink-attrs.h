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
};

struct nla_attr_spec {
	unsigned short type;
	unsigned short kind;
	unsigned short max_len;	/* upper bound on payload; 0 for fixed kinds */
};
