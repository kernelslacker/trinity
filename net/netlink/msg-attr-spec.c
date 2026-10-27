/*
 * Spec-driven attribute emission for families with a curated nla_attr_spec
 * table (genl, nfnl, XFRM, sock_diag): each payload is sized by the spec's
 * kind so the family's policy lets the message reach its handler.  Families
 * without a table use the random emitter in msg-attr-random.c.
 */
#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include "msg-internal.h"
#include "netlink-genl-families.h"
#include "netlink-nfnl-subsystems.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "text-payloads.h"
#include "utils.h"

/*
 * Compute payload length implied by an nla_attr_spec.  Variable-length
 * kinds (STRING, BINARY) draw a length in [min_len, max_len], or just
 * return max_len when it equals min_len.
 */
static size_t spec_payload_len(const struct nla_attr_spec *spec)
{
	switch (spec->kind) {
	case NLA_KIND_U8:
	case NLA_KIND_U8_ONEOF:
		return 1;
	case NLA_KIND_U16:	return 2;
	case NLA_KIND_U32:	return 4;
	case NLA_KIND_U64:	return 8;
	case NLA_KIND_BE16_MASK:
	case NLA_KIND_BE16_ONEOF:
		return 2;
	case NLA_KIND_BE32_MASK:
	case NLA_KIND_BE32_MAX:
	case NLA_KIND_BE32_ONEOF:
		return 4;
	case NLA_KIND_FLAG:	return 0;
	case NLA_KIND_STRING_WORD:
		return strlen(spec->word) + 1;
	case NLA_KIND_STRING:
	case NLA_KIND_STRING_CPULIST:
	case NLA_KIND_BINARY: {
		unsigned int lo = spec->min_len; /* no artificial floor */

		if (spec->max_len > lo)
			return RAND_RANGE(lo, spec->max_len);
		return spec->max_len;
	}
	case NLA_KIND_BINARY_FIXED2:
		return ONE_IN(2) ? spec->min_len : spec->max_len;
	case NLA_KIND_NESTED:
		/* Caller decides: append_specced_nested() builds the container */
		return 0;
	default:
		return 0;
	}
}

/*
 * Fill a scalar the kernel narrows: a random subset of the policy's mask
 * bits, a number in [0, max], or one of the values the handler accepts, in
 * network byte order as the NLA_BE16 / NLA_BE32 policies read it, or the
 * byte of an NLA_U8.  One draw in eight stays random bytes so the reject
 * arm keeps seeing traffic, as does a payload that a full buffer cut short
 * of the scalar's width.
 */
static void spec_fill_bounded(unsigned char *p, size_t len,
			      const struct nla_attr_spec *spec)
{
	uint32_t v;

	if (len != spec_payload_len(spec) || ONE_IN(8)) {
		generate_rand_bytes(p, len);
		return;
	}

	switch (spec->kind) {
	case NLA_KIND_BE32_MAX:
		v = rnd_modulo_u32(spec->max_len + 1U);
		break;
	case NLA_KIND_U8_ONEOF:
	case NLA_KIND_BE16_ONEOF:
	case NLA_KIND_BE32_ONEOF:
		v = spec->oneof[rnd_modulo_u32(spec->n_oneof)];
		break;
	default:	/* the mask kinds */
		v = rnd_u32() & spec->max_len;
	}

	if (len == 1) {
		*p = v;
	} else if (len == 2) {
		uint16_t be = htons(v);

		memcpy(p, &be, sizeof(be));
	} else {
		uint32_t be = htonl(v);

		memcpy(p, &be, sizeof(be));
	}
}

/*
 * Fill a payload buffer per spec kind: STRING gets NUL-terminated random
 * lowercase ASCII (the typical shape of names like NFTA_TABLE_NAME or
 * IFLA_INFO_KIND), a WORD its word, the bounded scalars a value their policy
 * or handler accepts, and everything else gets random bytes.
 */
static void spec_fill_payload(unsigned char *p, size_t len,
			      const struct nla_attr_spec *spec)
{
	size_t i;

	if (len == 0)
		return;

	switch (spec->kind) {
	case NLA_KIND_STRING_WORD:
	case NLA_KIND_STRING:
		/* A word's len is its own, less only when a full buffer cut
		 * the attribute short; the draw in eight that is not the word
		 * is the random string a STRING is. */
		if (spec->kind == NLA_KIND_STRING_WORD && !ONE_IN(8)) {
			memcpy(p, spec->word, len);
			break;
		}
		for (i = 0; i + 1 < len; i++)
			p[i] = 'a' + (rnd_modulo_u32(26));
		p[len - 1] = '\0';
		break;
	case NLA_KIND_STRING_CPULIST:
		gen_cpu_list_string((char *)p, (unsigned int)len);
		/* Force NUL termination inside the on-wire payload so
		 * cpulist_parse() can't run past the attribute. */
		p[len - 1] = '\0';
		break;
	case NLA_KIND_BE16_MASK:
	case NLA_KIND_BE32_MASK:
	case NLA_KIND_BE32_MAX:
	case NLA_KIND_U8_ONEOF:
	case NLA_KIND_BE16_ONEOF:
	case NLA_KIND_BE32_ONEOF:
		spec_fill_bounded(p, len, spec);
		break;
	default:
		generate_rand_bytes(p, len);
	}
}

static size_t append_specced_nested(unsigned char *buf, size_t offset,
				    size_t buflen,
				    const struct nla_attr_spec *spec,
				    const struct nla_attr_spec *table,
				    size_t nr_specs);

/*
 * Emit a single attribute described by a freshly picked spec.  A nest with
 * a table of its own is built by append_specced_nested(); any other nest is
 * a small binary payload, so children stay one level deep.  own is set when
 * table is a nest's own: a child that does not fit is dropped rather than
 * cut short, since a shortened one fails the nest's policy.
 */
static size_t append_specced_flat(unsigned char *buf, size_t offset,
				  size_t buflen,
				  const struct nla_attr_spec *table,
				  size_t nr_specs, bool own)
{
	const struct nla_attr_spec *spec;
	struct nlattr nla;
	size_t payload_len;
	size_t total;

	if (!table || nr_specs == 0)
		return offset;
	if (offset + NLA_HDRLEN > buflen)
		return offset;

	spec = &table[rnd_modulo_u32(nr_specs)];

	if (spec->nest != NULL)
		return append_specced_nested(buf, offset, buflen, spec,
					     table, nr_specs);

	if (spec->kind == NLA_KIND_NESTED || spec->kind == NLA_KIND_NESTED_ARRAY)
		payload_len = 16;	/* placeholder bytes — no recursion */
	else
		payload_len = spec_payload_len(spec);

	/* Cap any single child inside a nested container at 64 bytes so
	 * one greedy STRING/BINARY can't push out the rest of the
	 * children.  The kernel-side nla_strlen / max_len gates only care
	 * about the upper bound of each individual attr, not the sum. */
	if (payload_len > 64)
		payload_len = 64;

	total = NLA_ALIGN(NLA_HDRLEN + payload_len);
	if (offset + total > buflen) {
		if (own || buflen - offset < NLA_HDRLEN)
			return offset;
		total = buflen - offset;
		payload_len = total - NLA_HDRLEN;
	}

	nla.nla_len = NLA_HDRLEN + payload_len;
	nla.nla_type = spec->type;
	memcpy(buf + offset, &nla, NLA_HDRLEN);
	spec_fill_payload(buf + offset + NLA_HDRLEN, payload_len, spec);

	return offset + total;
}

/* 1-3 attributes drawn from table into the avail bytes at inner; returns
 * the bytes used. */
static size_t append_nest_children(unsigned char *inner, size_t avail,
				   const struct nla_attr_spec *table,
				   size_t nr_specs, bool own)
{
	size_t off = 0;
	int child_count = RAND_RANGE(1, 3);

	while (child_count-- > 0) {
		size_t new_off = append_specced_flat(inner, off, avail,
						     table, nr_specs, own);
		if (new_off == off)
			break;
		off = new_off;
	}
	return off;
}

/*
 * 1-3 elements of an NLA_POLICY_NESTED_ARRAY: each an NLA_F_NESTED
 * attribute, numbered from 0, that holds children drawn from table.
 */
static size_t append_nest_elements(unsigned char *inner, size_t avail,
				   const struct nla_attr_spec *table,
				   size_t nr_specs, bool own)
{
	size_t off = 0;
	int elem_count = RAND_RANGE(1, 3);
	unsigned short elem_no = 0;

	while (elem_count-- > 0) {
		struct nlattr nla;
		size_t stream;

		if (off + NLA_HDRLEN + NLA_HDRLEN + 4 > avail)
			break;
		stream = append_nest_children(inner + off + NLA_HDRLEN,
					      avail - off - NLA_HDRLEN,
					      table, nr_specs, own);
		if (stream == 0)
			break;

		nla.nla_len = NLA_HDRLEN + stream;
		nla.nla_type = NLA_F_NESTED | elem_no++;
		memcpy(inner + off, &nla, NLA_HDRLEN);
		off += NLA_ALIGN(NLA_HDRLEN + stream);
	}
	return off > avail ? avail : off;
}

/*
 * Emit a NLA_F_NESTED outer attr whose payload is 1-3 children drawn
 * from the spec's nest table, or from table, the one the spec is in, when it
 * names none; an array's payload is 1-3 elements holding such children.
 * Mirrors append_nested_attr_container() but walks a typed spec table for
 * kind/max_len information.  Increments the same nested counter so the dump
 * output stays consistent across spec-driven and pick_attr_hint-driven
 * nesting.
 */
static size_t append_specced_nested(unsigned char *buf, size_t offset,
				    size_t buflen,
				    const struct nla_attr_spec *spec,
				    const struct nla_attr_spec *table,
				    size_t nr_specs)
{
	struct nlattr nla;
	unsigned char *inner;
	size_t inner_avail;
	size_t inner_off;
	size_t total;
	bool own = spec->nest != NULL;

	if (offset + NLA_HDRLEN + NLA_HDRLEN + 4 > buflen)
		return offset;

	inner = buf + offset + NLA_HDRLEN;
	inner_avail = buflen - offset - NLA_HDRLEN;
	if (inner_avail > 256)
		inner_avail = 256;

	if (own) {
		table = spec->nest;
		nr_specs = spec->n_nest;
	}
	if (spec->kind == NLA_KIND_NESTED_ARRAY)
		inner_off = append_nest_elements(inner, inner_avail,
						 table, nr_specs, own);
	else
		inner_off = append_nest_children(inner, inner_avail,
						 table, nr_specs, own);

	if (inner_off == 0)
		return offset;

	nla.nla_len = NLA_HDRLEN + inner_off;
	nla.nla_type = spec->type | NLA_F_NESTED;
	memcpy(buf + offset, &nla, NLA_HDRLEN);

	total = NLA_ALIGN(NLA_HDRLEN + inner_off);
	if (offset + total > buflen)
		total = buflen - offset;

	__atomic_add_fetch(&shm->stats.netlink_nested_attrs_emitted, 1,
			   __ATOMIC_RELAXED);

	return offset + total;
}

/*
 * Top-level entry for spec-driven attribute emission.  Picks a random
 * spec and delegates to the nested or flat path as appropriate.  Used
 * exclusively by build_one_nlmsg for families with a curated
 * nla_attr_spec table; the legacy random-payload append_nlattr() path
 * still serves families without specs.
 */
size_t append_specced_nlattr(unsigned char *buf, size_t offset,
			     size_t buflen,
			     const struct nla_attr_spec *table,
			     size_t nr_specs)
{
	const struct nla_attr_spec *spec;
	struct nlattr nla;
	size_t payload_len;
	size_t total;

	if (!table || nr_specs == 0)
		return offset;
	if (offset + NLA_HDRLEN > buflen)
		return offset;

	spec = &table[rnd_modulo_u32(nr_specs)];

	if (spec->kind == NLA_KIND_NESTED || spec->kind == NLA_KIND_NESTED_ARRAY)
		return append_specced_nested(buf, offset, buflen, spec,
					     table, nr_specs);

	payload_len = spec_payload_len(spec);

	total = NLA_ALIGN(NLA_HDRLEN + payload_len);
	if (offset + total > buflen) {
		if (buflen - offset < NLA_HDRLEN)
			return offset;
		total = buflen - offset;
		payload_len = total - NLA_HDRLEN;
	}

	nla.nla_len = NLA_HDRLEN + payload_len;
	nla.nla_type = spec->type;
	memcpy(buf + offset, &nla, NLA_HDRLEN);
	spec_fill_payload(buf + offset + NLA_HDRLEN, payload_len, spec);

	return offset + total;
}

/*
 * Return the nla_attr_spec table for the message whose header is nlh and
 * whose body is already built, setting *nr_out to its element count.
 * NULL means the family is not spec-aware and the caller should fall back
 * to the legacy flat-attr generator.  Netfilter dispatches by NFNL_SUBSYS_x
 * nibble of nlmsg_type via the per-subsys grammar registry; generic netlink
 * dispatches by runtime-resolved family_id via the genl registry, and then
 * by the cmd and dump flag the message carries, since the policies are the
 * cmd's.
 */
const struct nla_attr_spec *pick_spec_table(int protocol,
					    const struct nlmsghdr *nlh,
					    size_t *nr_out)
{
	unsigned short nlmsg_type = nlh->nlmsg_type;

	switch (protocol) {
	case NETLINK_GENERIC: {
		const struct genl_family_grammar *fam;
		const struct genlmsghdr *genl;

		if (nlmsg_type == GENL_ID_CTRL) {
			*nr_out = ctrl_specs_n;
			return ctrl_specs;
		}
		fam = genl_lookup_by_id(nlmsg_type);
		if (fam == NULL)
			return NULL;
		genl = NLMSG_DATA(nlh);
		return genl_cmd_attrs(fam, genl->cmd,
				      (nlh->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP,
				      nr_out);
	}
	case NETLINK_XFRM:
		*nr_out = xfrma_specs_n;
		return xfrma_specs;
	case NETLINK_NETFILTER: {
		const struct nfnl_subsys_grammar *sub;

		sub = nfnl_lookup_by_subsys(nlmsg_type >> 8);
		if (sub != NULL && sub->n_attrs > 0) {
			*nr_out = sub->n_attrs;
			return sub->attrs;
		}
		return NULL;
	}
	case NETLINK_SOCK_DIAG:
		*nr_out = inet_diag_specs_n;
		return inet_diag_specs;
	default:
		return NULL;
	}
}
