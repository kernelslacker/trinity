/*
 * Genetlink family grammar: nbd (Network Block Device).
 *
 * The nbd module exposes its userspace control plane through a single
 * generic-netlink family ("nbd") with five user-callable commands:
 * NBD_CMD_CONNECT, NBD_CMD_DISCONNECT, NBD_CMD_RECONFIGURE,
 * NBD_CMD_LINK_DEAD, and NBD_CMD_STATUS.  CONNECT / RECONFIGURE walk
 * the full attribute policy (INDEX selector, SIZE_BYTES /
 * BLOCK_SIZE_BYTES / TIMEOUT / DEAD_CONN_TIMEOUT u64 scalars, the
 * SERVER_FLAGS / CLIENT_FLAGS u64 bitfields, the BACKEND_IDENTIFIER
 * NUL-terminated string, and the SOCKETS / DEVICE_LIST nested
 * containers); DISCONNECT / LINK_DEAD / STATUS gate primarily on
 * NBD_ATTR_INDEX.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "nbd", so the per-cmd nla_policy walker in
 * drivers/block/nbd.c plus the CONNECT / RECONFIGURE setup paths have
 * been routinely cold under generic netlink fuzzing; resolving the
 * family at first NETLINK_GENERIC use lets the message generator
 * address real nbd messages whose attribute shapes plausibly survive
 * the per-cmd policy.  The handlers gate destructive work on a
 * capable(CAP_SYS_ADMIN) check inside the handler body, not on a
 * GENL_ADMIN_PERM flag, so the nla_policy walk runs unprivileged and
 * the policy validator is genuinely exercised even from a non-root
 * fuzz child.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample model,
 * a single flat nla_attr_spec table lists every id used by this
 * family's commands.  nbd uses a single flat NBD_ATTR_* namespace;
 * SOCKETS and DEVICE_LIST are emitted as empty NESTED containers so
 * the kernel's nla_validate accepts them without recursing into the
 * per-socket / per-device sub-policies.  BACKEND_IDENTIFIER is a
 * NUL-terminated string identifying the backing store across a
 * RECONFIGURE.
 *
 * Header gating mirrors the team / hsr / fou / psample families:
 * <linux/nbd-netlink.h> is the upstream UAPI header carrying every
 * NBD_CMD_* and NBD_ATTR_* enum referenced below.  Build hosts lacking
 * the header silently drop the family from the registry instead of
 * failing the build.  Per-symbol #ifndef shims fill in the enum ids on
 * build hosts whose stale uapi predates BACKEND_IDENTIFIER /
 * DEVICE_LIST / DEAD_CONN_TIMEOUT.
 */

#if __has_include(<linux/nbd-netlink.h>)

#include <linux/nbd-netlink.h>

#include "netlink-genl-families.h"
#include "utils.h"

#ifndef NBD_GENL_FAMILY_NAME
#define NBD_GENL_FAMILY_NAME		"nbd"
#endif
#ifndef NBD_GENL_VERSION
#define NBD_GENL_VERSION		0x1
#endif

#ifndef NBD_CMD_CONNECT
#define NBD_CMD_CONNECT			1
#endif
#ifndef NBD_CMD_DISCONNECT
#define NBD_CMD_DISCONNECT		2
#endif
#ifndef NBD_CMD_RECONFIGURE
#define NBD_CMD_RECONFIGURE		3
#endif
#ifndef NBD_CMD_LINK_DEAD
#define NBD_CMD_LINK_DEAD		4
#endif
#ifndef NBD_CMD_STATUS
#define NBD_CMD_STATUS			5
#endif

#ifndef NBD_ATTR_INDEX
#define NBD_ATTR_INDEX			1
#endif
#ifndef NBD_ATTR_SIZE_BYTES
#define NBD_ATTR_SIZE_BYTES		2
#endif
#ifndef NBD_ATTR_BLOCK_SIZE_BYTES
#define NBD_ATTR_BLOCK_SIZE_BYTES	3
#endif
#ifndef NBD_ATTR_TIMEOUT
#define NBD_ATTR_TIMEOUT		4
#endif
#ifndef NBD_ATTR_SERVER_FLAGS
#define NBD_ATTR_SERVER_FLAGS		5
#endif
#ifndef NBD_ATTR_CLIENT_FLAGS
#define NBD_ATTR_CLIENT_FLAGS		6
#endif
#ifndef NBD_ATTR_SOCKETS
#define NBD_ATTR_SOCKETS		7
#endif
#ifndef NBD_ATTR_DEAD_CONN_TIMEOUT
#define NBD_ATTR_DEAD_CONN_TIMEOUT	8
#endif
#ifndef NBD_ATTR_DEVICE_LIST
#define NBD_ATTR_DEVICE_LIST		9
#endif
#ifndef NBD_ATTR_BACKEND_IDENTIFIER
#define NBD_ATTR_BACKEND_IDENTIFIER	10
#endif

static const struct genl_cmd_grammar nbd_cmds[] = {
	{ NBD_CMD_CONNECT,	"NBD_CMD_CONNECT" },
	{ NBD_CMD_DISCONNECT,	"NBD_CMD_DISCONNECT" },
	{ NBD_CMD_RECONFIGURE,	"NBD_CMD_RECONFIGURE" },
	{ NBD_CMD_LINK_DEAD,	"NBD_CMD_LINK_DEAD" },
	{ NBD_CMD_STATUS,	"NBD_CMD_STATUS" },
};

/*
 * Attribute spec follows the NBD_ATTR_* enum in <linux/nbd-netlink.h>.
 * INDEX is a u32 nbd-device index selector (matching nbd_attr_policy
 * in drivers/block/nbd.c).  SIZE_BYTES / BLOCK_SIZE_BYTES / TIMEOUT /
 * DEAD_CONN_TIMEOUT are u64 scalars carrying the device export size,
 * block size, IO timeout, and dead-connection timeout respectively.
 * SERVER_FLAGS / CLIENT_FLAGS are u64 bitfields negotiated between
 * server / client at CONNECT time.  SOCKETS and DEVICE_LIST are
 * nominally nested containers — emitted here as empty containers so
 * the kernel's nla_validate accepts them without recursing into the
 * per-socket / per-device sub-policies.  BACKEND_IDENTIFIER is a
 * NUL-terminated string identifying the backing store across a
 * RECONFIGURE.
 */
static const struct nla_attr_spec nbd_attrs[] = {
	{ NBD_ATTR_INDEX,		NLA_KIND_U32,    4 },
	{ NBD_ATTR_SIZE_BYTES,		NLA_KIND_U64,    8 },
	{ NBD_ATTR_BLOCK_SIZE_BYTES,	NLA_KIND_U64,    8 },
	{ NBD_ATTR_TIMEOUT,		NLA_KIND_U64,    8 },
	{ NBD_ATTR_SERVER_FLAGS,	NLA_KIND_U64,    8 },
	{ NBD_ATTR_CLIENT_FLAGS,	NLA_KIND_U64,    8 },
	{ NBD_ATTR_SOCKETS,		NLA_KIND_NESTED, 0 },
	{ NBD_ATTR_DEAD_CONN_TIMEOUT,	NLA_KIND_U64,    8 },
	{ NBD_ATTR_DEVICE_LIST,		NLA_KIND_NESTED, 0 },
	{ NBD_ATTR_BACKEND_IDENTIFIER,	NLA_KIND_STRING, 32 },
};

struct genl_family_grammar fam_nbd = {
	.name = NBD_GENL_FAMILY_NAME,
	.cmds = nbd_cmds,
	.n_cmds = ARRAY_SIZE(nbd_cmds),
	.attrs = nbd_attrs,
	.n_attrs = ARRAY_SIZE(nbd_attrs),
	.default_version = NBD_GENL_VERSION,
	.hdrsize = 0,
};

#endif /* __has_include(<linux/nbd-netlink.h>) */
