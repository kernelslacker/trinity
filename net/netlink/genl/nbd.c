/*
 * Genetlink family grammar: nbd (Network Block Device), targeting
 * nbd_attr_policy and the handlers in drivers/block/nbd.c.  The ops carry
 * no admin flag: CONNECT, DISCONNECT and RECONFIGURE test CAP_SYS_ADMIN
 * with netlink_capable() in the handler, after the policy walk.
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

/* LINK_DEAD is a multicast notification, not an op, so it is not listed. */
static const struct genl_cmd_grammar nbd_cmds[] = {
	{ NBD_CMD_CONNECT,	"NBD_CMD_CONNECT" },
	{ NBD_CMD_DISCONNECT,	"NBD_CMD_DISCONNECT" },
	{ NBD_CMD_RECONFIGURE,	"NBD_CMD_RECONFIGURE" },
	{ NBD_CMD_STATUS,	"NBD_CMD_STATUS" },
};

/*
 * Attribute spec follows the NBD_ATTR_* enum in <linux/nbd-netlink.h>.
 * INDEX is a u32 nbd-device index selector (matching nbd_attr_policy
 * in drivers/block/nbd.c).  SIZE_BYTES / BLOCK_SIZE_BYTES / TIMEOUT /
 * DEAD_CONN_TIMEOUT are u64 scalars carrying the device export size,
 * block size, IO timeout, and dead-connection timeout respectively.
 * SERVER_FLAGS / CLIENT_FLAGS are u64 bitfields negotiated between
 * server / client at CONNECT time.  SOCKETS and DEVICE_LIST are bare
 * NLA_NESTED in nbd_attr_policy, so nla_validate does not recurse into
 * them.  CONNECT and RECONFIGURE walk SOCKETS in nbd_genl_foreach_sock(),
 * which wants NBD_SOCK_ITEM children and parses each against
 * nbd_sock_policy; DEVICE_LIST is only emitted by STATUS, never parsed
 * on input.  BACKEND_IDENTIFIER is a NUL-terminated string identifying
 * the backing store across a RECONFIGURE.
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
