/*
 * Genetlink family grammar: nfc (Near-Field Communication).
 *
 * The nfc subsystem exposes its userspace control plane through a
 * single generic-netlink family ("nfc") with nineteen user-callable
 * commands covering device enumeration / power control, polling and
 * target activation, the LLCP parameter / service-discovery surface,
 * secure-element enable / disable / APDU exchange, firmware download,
 * and the vendor-specific passthrough.  The eleven NFC_EVENT_* ids in
 * <linux/nfc.h> are kernel->user notifications and are intentionally
 * omitted: net/nfc/netlink.c never dispatches them from genl_ops, so
 * sending one is a guaranteed -EOPNOTSUPP at the family demuxer.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "nfc", so net/nfc/netlink.c's nfc_genl_policy walker
 * plus the per-command setup paths have been routinely cold under
 * generic netlink fuzzing; resolving the family at first
 * NETLINK_GENERIC use lets the message generator address real nfc
 * messages whose attribute shapes plausibly survive the per-cmd policy.
 *
 * Per the nbd / fou / l2tp model, a single flat nla_attr_spec table
 * lists every id used by this family's commands.  The kernel policy
 * declares a subset of NFC_ATTR_* — the unlisted ids are response-side
 * payloads emitted by GET_DEVICE / GET_TARGET / GET_SE; listing them
 * here exercises the validator's "ignore on input" branch the same way
 * the fou / l2tp grammars do.  LLC_SDP is the one nested container and
 * is emitted as an empty NESTED so nla_validate accepts it without
 * recursing into the per-service NFC_SDP_ATTR_* sub-policy.
 */

#if __has_include(<linux/nfc.h>)

/*
 * kernel/nfc.h pulls <linux/nfc.h> and backfills the post-6.12
 * NFC_ATTR_TARGET_ATS / NFC_ATS_MAXSIZE the spec table references, so a
 * host shipping an older <linux/nfc.h> -- which still satisfies the
 * __has_include gate above -- builds instead of failing on the missing
 * enumerator.
 */
#include "kernel/nfc.h"

#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar nfc_cmds[] = {
	{ NFC_CMD_GET_DEVICE,		"NFC_CMD_GET_DEVICE" },
	{ NFC_CMD_DEV_UP,		"NFC_CMD_DEV_UP" },
	{ NFC_CMD_DEV_DOWN,		"NFC_CMD_DEV_DOWN" },
	{ NFC_CMD_DEP_LINK_UP,		"NFC_CMD_DEP_LINK_UP" },
	{ NFC_CMD_DEP_LINK_DOWN,	"NFC_CMD_DEP_LINK_DOWN" },
	{ NFC_CMD_START_POLL,		"NFC_CMD_START_POLL" },
	{ NFC_CMD_STOP_POLL,		"NFC_CMD_STOP_POLL" },
	{ NFC_CMD_GET_TARGET,		"NFC_CMD_GET_TARGET" },
	{ NFC_CMD_LLC_GET_PARAMS,	"NFC_CMD_LLC_GET_PARAMS" },
	{ NFC_CMD_LLC_SET_PARAMS,	"NFC_CMD_LLC_SET_PARAMS" },
	{ NFC_CMD_ENABLE_SE,		"NFC_CMD_ENABLE_SE" },
	{ NFC_CMD_DISABLE_SE,		"NFC_CMD_DISABLE_SE" },
	{ NFC_CMD_LLC_SDREQ,		"NFC_CMD_LLC_SDREQ" },
	{ NFC_CMD_FW_DOWNLOAD,		"NFC_CMD_FW_DOWNLOAD" },
	{ NFC_CMD_GET_SE,		"NFC_CMD_GET_SE" },
	{ NFC_CMD_SE_IO,		"NFC_CMD_SE_IO" },
	{ NFC_CMD_ACTIVATE_TARGET,	"NFC_CMD_ACTIVATE_TARGET" },
	{ NFC_CMD_VENDOR,		"NFC_CMD_VENDOR" },
	{ NFC_CMD_DEACTIVATE_TARGET,	"NFC_CMD_DEACTIVATE_TARGET" },
};

/*
 * Attribute spec follows the NFC_ATTR_* enum in <linux/nfc.h>.  Sizes
 * for input-side attributes match nfc_genl_policy in net/nfc/netlink.c;
 * the response-side TARGET_* / SE / SE_TYPE / SE_AID / SE_PARAMS /
 * FIRMWARE_DOWNLOAD_STATUS / TARGET_ISO15693_* / TARGET_ATS scalars are
 * sized per the corresponding nla_put_u{8,16,32} / nla_put callsites in
 * the same file.  Binary blobs for the open-ended SE_APDU / VENDOR_DATA
 * payloads get a 256-byte ceiling; the bounded TARGET_NFCID1 /
 * TARGET_SENSB_RES / TARGET_SENSF_RES / TARGET_ISO15693_UID / TARGET_ATS
 * binaries use the NFC_*_MAXSIZE constants from the same header.
 */
static const struct nla_attr_spec nfc_attrs[] = {
	{ NFC_ATTR_DEVICE_INDEX,	NLA_KIND_U32,    4 },
	{ NFC_ATTR_DEVICE_NAME,		NLA_KIND_STRING, NFC_DEVICE_NAME_MAXSIZE },
	{ NFC_ATTR_PROTOCOLS,		NLA_KIND_U32,    4 },
	{ NFC_ATTR_TARGET_INDEX,	NLA_KIND_U32,    4 },
	{ NFC_ATTR_TARGET_SENS_RES,	NLA_KIND_U16,    2 },
	{ NFC_ATTR_TARGET_SEL_RES,	NLA_KIND_U8,     1 },
	{ NFC_ATTR_TARGET_NFCID1,	NLA_KIND_BINARY, NFC_NFCID1_MAXSIZE },
	{ NFC_ATTR_TARGET_SENSB_RES,	NLA_KIND_BINARY, NFC_SENSB_RES_MAXSIZE },
	{ NFC_ATTR_TARGET_SENSF_RES,	NLA_KIND_BINARY, NFC_SENSF_RES_MAXSIZE },
	{ NFC_ATTR_COMM_MODE,		NLA_KIND_U8,     1 },
	{ NFC_ATTR_RF_MODE,		NLA_KIND_U8,     1 },
	{ NFC_ATTR_DEVICE_POWERED,	NLA_KIND_U8,     1 },
	{ NFC_ATTR_IM_PROTOCOLS,	NLA_KIND_U32,    4 },
	{ NFC_ATTR_TM_PROTOCOLS,	NLA_KIND_U32,    4 },
	{ NFC_ATTR_LLC_PARAM_LTO,	NLA_KIND_U8,     1 },
	{ NFC_ATTR_LLC_PARAM_RW,	NLA_KIND_U8,     1 },
	{ NFC_ATTR_LLC_PARAM_MIUX,	NLA_KIND_U16,    2 },
	{ NFC_ATTR_SE,			NLA_KIND_U32,    4 },
	{ NFC_ATTR_LLC_SDP,		NLA_KIND_NESTED, 0 },
	{ NFC_ATTR_FIRMWARE_NAME,	NLA_KIND_STRING, NFC_FIRMWARE_NAME_MAXSIZE },
	{ NFC_ATTR_SE_INDEX,		NLA_KIND_U32,    4 },
	{ NFC_ATTR_SE_TYPE,		NLA_KIND_U8,     1 },
	{ NFC_ATTR_SE_AID,		NLA_KIND_BINARY, 64 },
	{ NFC_ATTR_FIRMWARE_DOWNLOAD_STATUS, NLA_KIND_U32, 4 },
	{ NFC_ATTR_SE_APDU,		NLA_KIND_BINARY, 256 },
	{ NFC_ATTR_TARGET_ISO15693_DSFID, NLA_KIND_U8,  1 },
	{ NFC_ATTR_TARGET_ISO15693_UID,	NLA_KIND_BINARY, NFC_ISO15693_UID_MAXSIZE },
	{ NFC_ATTR_SE_PARAMS,		NLA_KIND_BINARY, 256 },
	{ NFC_ATTR_VENDOR_ID,		NLA_KIND_U32,    4 },
	{ NFC_ATTR_VENDOR_SUBCMD,	NLA_KIND_U32,    4 },
	{ NFC_ATTR_VENDOR_DATA,		NLA_KIND_BINARY, 256 },
	{ NFC_ATTR_TARGET_ATS,		NLA_KIND_BINARY, NFC_ATS_MAXSIZE },
};

struct genl_family_grammar fam_nfc = {
	.name = NFC_GENL_NAME,
	.cmds = nfc_cmds,
	.n_cmds = ARRAY_SIZE(nfc_cmds),
	.attrs = nfc_attrs,
	.n_attrs = ARRAY_SIZE(nfc_attrs),
	.default_version = NFC_GENL_VERSION,
	.hdrsize = 0,
};

#endif /* __has_include(<linux/nfc.h>) */
