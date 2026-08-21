/*
 * Spec-driven attribute emission split out of net/netlink/msg-core.c.
 *
 * Families with a curated nla_attr_spec table (XFRM, ctnetlink,
 * nftables, genl-ctrl, sock_diag, ...) go through this path instead
 * of the legacy random-payload emitter in msg-attr-random.c.  Each
 * attribute's payload is sized by the spec's kind (U8/U16/U32/U64,
 * STRING, BINARY, NESTED, ...) so the kernel's per-family policy
 * gate lets us reach the actual command handler instead of bouncing
 * every attr with EINVAL.
 *
 * pick_spec_table() returns the (table, count) pair for a given
 * protocol/nlmsg_type or NULL to fall through to the random path.
 * append_specced_nlattr() is the top-level entry point and routes
 * NLA_KIND_NESTED specs through append_specced_nested(), which
 * builds a 1-3 child container and shares the same nested-attr
 * counter with append_nested_attr_container() so the dump output
 * stays consistent across both nesting paths.
 */
#include <stddef.h>
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
	case NLA_KIND_U8:	return 1;
	case NLA_KIND_U16:	return 2;
	case NLA_KIND_U32:	return 4;
	case NLA_KIND_U64:	return 8;
	case NLA_KIND_FLAG:	return 0;
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
		/* Caller decides — nested kinds get a recursive emission */
		return 0;
	default:
		return 0;
	}
}

/*
 * Fill a payload buffer per spec kind: STRING gets NUL-terminated random
 * lowercase ASCII (the typical shape of names like NFTA_TABLE_NAME or
 * IFLA_INFO_KIND), everything else gets random bytes.
 */
static void spec_fill_payload(unsigned char *p, size_t len,
			      const struct nla_attr_spec *spec)
{
	if (len == 0)
		return;
	if (spec->kind == NLA_KIND_STRING) {
		size_t i;

		for (i = 0; i + 1 < len; i++)
			p[i] = 'a' + (rnd_modulo_u32(26));
		p[len - 1] = '\0';
	} else if (spec->kind == NLA_KIND_STRING_CPULIST) {
		gen_cpu_list_string((char *)p, (unsigned int)len);
		/* Force NUL termination inside the on-wire payload so
		 * cpulist_parse() can't run past the attribute. */
		p[len - 1] = '\0';
	} else {
		generate_rand_bytes(p, len);
	}
}

/*
 * Emit a single attribute described by a freshly picked spec, treating
 * NESTED as a small binary payload.  Used inside append_specced_nested
 * so children stay one level deep — matches the depth limit set by
 * commit "net/netlink: add nested NLA_F_NESTED attribute support".
 */
static size_t append_specced_flat(unsigned char *buf, size_t offset,
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

	if (spec->kind == NLA_KIND_NESTED)
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
 * Emit a NLA_F_NESTED outer attr whose payload is 1-3 children drawn
 * from the same spec table.  Mirrors append_nested_attr_container() but
 * walks a typed spec table for kind/max_len information.  Increments
 * the same nested counter so the dump output stays consistent across
 * spec-driven and pick_attr_hint-driven nesting.
 */
static size_t append_specced_nested(unsigned char *buf, size_t offset,
				    size_t buflen,
				    unsigned short outer_type,
				    const struct nla_attr_spec *table,
				    size_t nr_specs)
{
	struct nlattr nla;
	unsigned char *inner;
	size_t inner_avail;
	size_t inner_off = 0;
	size_t total;
	int child_count;

	if (offset + NLA_HDRLEN + NLA_HDRLEN + 4 > buflen)
		return offset;

	inner = buf + offset + NLA_HDRLEN;
	inner_avail = buflen - offset - NLA_HDRLEN;
	if (inner_avail > 256)
		inner_avail = 256;

	child_count = RAND_RANGE(1, 3);
	while (child_count-- > 0) {
		size_t new_off = append_specced_flat(inner, inner_off,
						     inner_avail,
						     table, nr_specs);
		if (new_off == inner_off)
			break;
		inner_off = new_off;
	}

	if (inner_off == 0)
		return offset;

	nla.nla_len = NLA_HDRLEN + inner_off;
	nla.nla_type = outer_type | NLA_F_NESTED;
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

	if (spec->kind == NLA_KIND_NESTED)
		return append_specced_nested(buf, offset, buflen, spec->type,
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
 * Return the nla_attr_spec table for a given protocol/nlmsg_type pair,
 * setting *nr_out to its element count.  NULL means the family is not
 * spec-aware and the caller should fall back to the legacy flat-attr
 * generator.  Netfilter dispatches by NFNL_SUBSYS_x nibble of
 * nlmsg_type via the per-subsys grammar registry; generic netlink
 * dispatches by runtime-resolved family_id via the genl registry.
 */
const struct nla_attr_spec *pick_spec_table(int protocol,
					    unsigned short nlmsg_type,
					    size_t *nr_out)
{
	switch (protocol) {
	case NETLINK_GENERIC: {
		const struct genl_family_grammar *fam;

		if (nlmsg_type == GENL_ID_CTRL) {
			*nr_out = ctrl_specs_n;
			return ctrl_specs;
		}
		fam = genl_lookup_by_id(nlmsg_type);
		if (fam != NULL && fam->n_attrs > 0) {
			*nr_out = fam->n_attrs;
			return fam->attrs;
		}
		return NULL;
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
