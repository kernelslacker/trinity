/*
 * Per-protocol body-struct builders split out of net/netlink/msg-core.c.
 *
 * Each NETLINK_* protocol family carries a small fixed header (or a
 * per-type struct) immediately after the nlmsghdr; the kernel
 * validates its size and family byte before the attribute walker
 * ever runs.  The builders here size and fill that header so the
 * message survives the initial copy_from_user length check and
 * reaches the family-specific parser.
 *
 * The entry points (gen_genl_body, gen_nfnl_body, gen_xfrm_body,
 * gen_audit_body, gen_sockdiag_body, pick_genl_attr_type) are
 * declared in msg-internal.h; xfrm_pin_family is a helper local to
 * gen_xfrm_body and stays file-static here.  rand_family() is
 * defined in msg-rtnl-body.c and declared in msg-internal.h.
 */
#include <sys/socket.h>
#include <stddef.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/xfrm.h>
#include <linux/audit.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include "msg-internal.h"
#include "netlink-genl-families.h"
#include "netlink-nfnl-subsystems.h"
#include "random.h"
#include "rnd.h"
#include "utils.h"

/*
 * Generate body for NETLINK_GENERIC messages.
 * All genl messages have a genlmsghdr (4 bytes) immediately after nlmsghdr.
 * Some families (openvswitch's six, for example) declare a non-zero
 * family->hdrsize that the kernel skips past before walking attributes —
 * for those we append fam->hdrsize random bytes after the genlmsghdr so
 * the per-cmd attribute parser sees TLVs at the offset it expects.
 * For the controller (GENL_ID_CTRL), we pick from CTRL_CMD_* commands.
 * For other families, we use random cmd values since we don't know
 * which families are loaded at runtime.
 */
size_t gen_genl_body(unsigned char *body, unsigned short nlmsg_type,
		     size_t buflen)
{
	const struct genl_family_grammar *fam = NULL;
	struct genlmsghdr genl;
	size_t len;

	if (sizeof(genl) > buflen)
		return 0;

	if (nlmsg_type == GENL_ID_CTRL) {
		/* Controller commands: GETFAMILY is the most useful */
		genl.cmd = RAND_RANGE(CTRL_CMD_UNSPEC, CTRL_CMD_MAX);
		genl.version = RAND_BOOL() ? 1 : rnd_modulo_u32(4);
	} else if ((fam = genl_lookup_by_id(nlmsg_type)) != NULL) {
		/* Resolved family: pick a known cmd from its grammar so the
		 * family's command dispatcher accepts it.  Use the family's
		 * preferred version when set so the version gate also
		 * passes; the kernel-side check is usually >= so a small
		 * version is fine. */
		genl.cmd = genl_pick_cmd(fam);
		genl.version = fam->default_version ? fam->default_version : 1;
		genl_family_bump_calls(fam);
	} else {
		/* Unknown family: random command, biased toward low values */
		if (RAND_BOOL())
			genl.cmd = rnd_modulo_u32(16);
		else
			genl.cmd = rnd_modulo_u32(256);
		genl.version = RAND_BOOL() ? 1 : rnd_modulo_u32(4);
	}
	/* reserved: usually 0, but fuzz it sometimes to test validation */
	genl.reserved = ONE_IN(4) ? rand16() : 0;

	memcpy(body, &genl, sizeof(genl));
	len = sizeof(genl);

	if (fam && fam->hdrsize) {
		if (len + fam->hdrsize > buflen)
			return len;
		generate_rand_bytes(body + len, fam->hdrsize);
		return len + fam->hdrsize;
	}
	return len;
}

/* Pick an nlattr type for genl controller messages.  Reads through the
 * ctrl_specs spec table; the legacy flat-attr code path still needs a
 * raw nla_type when nesting a NETLINK_GENERIC controller attr via
 * append_nested_attr_container().  The spec-driven path bypasses this. */
unsigned short pick_genl_attr_type(unsigned short nlmsg_type)
{
	if (nlmsg_type == GENL_ID_CTRL)
		return ctrl_specs[rnd_modulo_u32(ctrl_specs_n)].type;
	return 0; /* unknown family: fall back to random */
}

/*
 * Generate body for NETLINK_NETFILTER messages.
 * nfnetlink messages have a nfgenmsg (4 bytes) after nlmsghdr.
 * The nlmsg_type encodes subsystem << 8 | message.  After building
 * the body, bump the per-subsys dispatch counter so the live
 * subsystem mix is visible in the periodic stats dump and end-of-run
 * summary; bump degrades to a no-op when nlmsg_type's high byte
 * doesn't match any registered subsys.
 */
size_t gen_nfnl_body(unsigned char *body, unsigned short nlmsg_type,
		     size_t buflen)
{
	struct nfgenmsg nfg;
	static const unsigned char nf_families[] = {
		AF_INET, AF_INET6, AF_BRIDGE, AF_UNSPEC,
	};

	if (sizeof(nfg) > buflen)
		return 0;

	if (ONE_IN(8))
		nfg.nfgen_family = rnd_modulo_u32(256);
	else
		nfg.nfgen_family = RAND_ARRAY(nf_families);
	nfg.version = RAND_BOOL() ? NFNETLINK_V0 : rnd_modulo_u32(4);
	nfg.res_id = ONE_IN(4) ? rand16() : 0;

	memcpy(body, &nfg, sizeof(nfg));
	nfnl_subsys_bump_calls(nfnl_lookup_by_subsys(nlmsg_type >> 8));
	return sizeof(nfg);
}

static void xfrm_pin_family(unsigned char *body, size_t body_len,
			    unsigned short nlmsg_type)
{
	unsigned char family = RAND_BOOL() ? AF_INET : AF_INET6;
	unsigned int i;

	for (i = 0; i < xfrm_family_offsets_n; i++) {
		if (xfrm_family_offsets[i].msg_type != nlmsg_type)
			continue;
		if (xfrm_family_offsets[i].family_offset + 1 < body_len) {
			body[xfrm_family_offsets[i].family_offset] = family;
			body[xfrm_family_offsets[i].family_offset + 1] = 0;
		}
		if (xfrm_family_offsets[i].sel_family_offset != ~0u &&
		    xfrm_family_offsets[i].sel_family_offset + 1 < body_len) {
			body[xfrm_family_offsets[i].sel_family_offset] = family;
			body[xfrm_family_offsets[i].sel_family_offset + 1] = 0;
		}
		return;
	}
}

/*
 * Generate body for NETLINK_XFRM messages.
 * Body struct varies by message type. The big structs (xfrm_usersa_info
 * at 224 bytes, xfrm_userpolicy_info at 168 bytes) are filled with
 * random data of the correct size. Getting the size right is what
 * matters — it gets us past the initial copy_from_user length check
 * into the deeper validation code where the interesting bugs live.
 */
size_t gen_xfrm_body(unsigned char *body, unsigned short nlmsg_type,
		     size_t buflen)
{
	size_t body_len;

	switch (nlmsg_type) {
	case XFRM_MSG_NEWSA:
	case XFRM_MSG_UPDSA:
		body_len = sizeof(struct xfrm_usersa_info);
		break;
	case XFRM_MSG_DELSA:
	case XFRM_MSG_GETSA:
		body_len = sizeof(struct xfrm_usersa_id);
		break;
	case XFRM_MSG_NEWPOLICY:
	case XFRM_MSG_UPDPOLICY:
		body_len = sizeof(struct xfrm_userpolicy_info);
		break;
	case XFRM_MSG_DELPOLICY:
	case XFRM_MSG_GETPOLICY:
		body_len = sizeof(struct xfrm_userpolicy_id);
		break;
	case XFRM_MSG_ALLOCSPI:
		body_len = sizeof(struct xfrm_userspi_info);
		break;
	case XFRM_MSG_ACQUIRE:
		body_len = sizeof(struct xfrm_user_acquire);
		break;
	case XFRM_MSG_EXPIRE:
		body_len = sizeof(struct xfrm_user_expire);
		break;
	case XFRM_MSG_POLEXPIRE:
		body_len = sizeof(struct xfrm_user_polexpire);
		break;
	case XFRM_MSG_FLUSHSA:
		body_len = sizeof(struct xfrm_usersa_flush);
		break;
	case XFRM_MSG_FLUSHPOLICY:
		body_len = 0; /* no body */
		break;
	case XFRM_MSG_NEWAE:
	case XFRM_MSG_GETAE:
		body_len = sizeof(struct xfrm_aevent_id);
		break;
	case XFRM_MSG_MIGRATE:
		body_len = sizeof(struct xfrm_user_migrate);
		break;
	case XFRM_MSG_GETSADINFO:
	case XFRM_MSG_GETSPDINFO:
	case XFRM_MSG_NEWSADINFO:
	case XFRM_MSG_NEWSPDINFO:
		body_len = sizeof(__u32);
		break;
	case XFRM_MSG_SETDEFAULT:
	case XFRM_MSG_GETDEFAULT:
		body_len = sizeof(struct xfrm_userpolicy_default);
		break;
	case XFRM_MSG_MAPPING:
		body_len = sizeof(struct xfrm_user_mapping);
		break;
	case XFRM_MSG_REPORT:
		body_len = sizeof(struct xfrm_user_report);
		break;
	default:
		/* Unknown xfrm type: random body */
		body_len = RAND_RANGE(4, 32);
		break;
	}

	if (body_len > buflen)
		return 0;
	if (body_len > 0) {
		generate_rand_bytes(body, body_len);
		xfrm_pin_family(body, body_len, nlmsg_type);
	}
	return body_len;
}

/*
 * Generate body for NETLINK_AUDIT messages.
 * Audit is special: it doesn't use nlattr TLVs. Message payloads are
 * either binary structs (audit_status, audit_rule_data) or raw text.
 * The caller should skip nlattr generation for audit messages.
 */
size_t gen_audit_body(unsigned char *body, unsigned short nlmsg_type,
		      size_t buflen)
{
	size_t body_len;

	switch (nlmsg_type) {
	case AUDIT_GET:
		/* GET takes no body (kernel ignores payload) */
		return 0;
	case AUDIT_SET:
		body_len = sizeof(struct audit_status);
		break;
	case AUDIT_ADD_RULE:
	case AUDIT_DEL_RULE:
	case AUDIT_LIST_RULES: {
		/*
		 * audit_rule_data is 1040 bytes base + variable buf[].
		 * Generate the fixed part with fuzzed fields and a small
		 * random buffer extension.
		 */
		size_t extra = rnd_modulo_u32(64);
		body_len = sizeof(struct audit_rule_data) + extra;
		if (body_len > buflen)
			body_len = buflen;
		generate_rand_bytes(body, body_len);
		return body_len;
	}
	case AUDIT_USER:
	case AUDIT_LOGIN:
		/* Raw text payload */
		body_len = RAND_RANGE(4, 128);
		if (body_len > buflen)
			body_len = buflen;
		generate_rand_bytes(body, body_len);
		return body_len;
	case AUDIT_TTY_GET:
	case AUDIT_TTY_SET:
	case AUDIT_GET_FEATURE:
	case AUDIT_SET_FEATURE:
		body_len = sizeof(struct audit_status);
		break;
	case AUDIT_SIGNAL_INFO:
		return 0; /* no body for get requests */
	case AUDIT_TRIM:
		return 0; /* no body */
	case AUDIT_MAKE_EQUIV:
		/* Two paths separated by NUL */
		body_len = RAND_RANGE(4, 64);
		if (body_len > buflen)
			body_len = buflen;
		generate_rand_bytes(body, body_len);
		return body_len;
	default:
		body_len = RAND_RANGE(4, 64);
		if (body_len > buflen)
			body_len = buflen;
		generate_rand_bytes(body, body_len);
		return body_len;
	}

	if (body_len > buflen)
		body_len = buflen;
	generate_rand_bytes(body, body_len);
	return body_len;
}

/*
 * Generate body for NETLINK_SOCK_DIAG messages.
 * Two main message types:
 * - SOCK_DIAG_BY_FAMILY (20): generic sock_diag_req, then the kernel
 *   dispatches to per-family handlers based on sdiag_family.
 * - SOCK_DESTROY (21): inet_diag_req_v2 with socket identification.
 * - Legacy types (< 20): inet_diag_req_v2.
 */
size_t gen_sockdiag_body(unsigned char *body,
			 unsigned short nlmsg_type, size_t buflen)
{
	switch (nlmsg_type) {
	case SOCK_DIAG_BY_FAMILY: {
		struct sock_diag_req req;

		if (sizeof(req) > buflen)
			return 0;
		req.sdiag_family = rand_family();
		req.sdiag_protocol = rnd_modulo_u32(256);
		memcpy(body, &req, sizeof(req));
		return sizeof(req);
	}
	default: {
		/*
		 * SOCK_DESTROY and legacy inet_diag types use
		 * inet_diag_req_v2 (56 bytes). Fill with random data
		 * but set sdiag_family to something useful.
		 */
		struct inet_diag_req_v2 req;

		if (sizeof(req) > buflen)
			return 0;
		generate_rand_bytes((unsigned char *)&req, sizeof(req));
		req.sdiag_family = rand_family();
		req.sdiag_protocol = rnd_modulo_u32(256);
		memcpy(body, &req, sizeof(req));
		return sizeof(req);
	}
	}
}
