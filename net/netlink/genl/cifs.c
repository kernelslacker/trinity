/*
 * Genetlink family grammar: cifs (SMB Witness Service upcall).
 *
 * The cifs client (fs/smb/client/netlink.c) exposes its userspace
 * witness-daemon upcall through a single generic-netlink family
 * ("cifs") with one user-callable .doit command,
 * CIFS_GENL_CMD_SWN_NOTIFY: the witness daemon delivers a SWN
 * notification (resource state change / client- or share-move /
 * IP-change) back to the kernel after the in-kernel SWN client has
 * issued a SWN_REGISTER as a multicast event.  REGISTER / UNREGISTER
 * are kernel-to-userspace events, not driveable .doit ids, so listing
 * only SWN_NOTIFY keeps the message generator on the cmd that lands in
 * a real dispatcher instead of bouncing off -EOPNOTSUPP at the family
 * demuxer.
 *
 * Random nlmsg_type ids essentially never matched the runtime-assigned
 * family_id for "cifs", so the per-cmd nla_policy walker plus the
 * cifs_swn_notify dispatcher have been routinely cold under generic
 * netlink fuzzing; resolving the family at first NETLINK_GENERIC use
 * lets the message generator address real cifs messages whose attribute
 * shapes plausibly survive the per-cmd policy.  cifs_swn_notify gates
 * on the SWN_REGISTRATION_ID matching an in-kernel registration before
 * doing real work, but the nla_policy walk plus the sockaddr_storage
 * copy-in for SWN_IP_NOTIFY is reached regardless of whether a live
 * cifs SWN registration exists on the running kernel.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample / nbd
 * model, a single flat nla_attr_spec table lists every id the kernel's
 * cifs_genl_policy gates on: SWN_REGISTRATION_ID / SWN_NOTIFICATION_TYPE
 * / SWN_RESOURCE_STATE are u32 scalars; SWN_NET_NAME / SWN_SHARE_NAME /
 * SWN_USER_NAME / SWN_PASSWORD / SWN_DOMAIN_NAME / SWN_RESOURCE_NAME
 * are NLA_STRING (the kernel doesn't bound them in the policy; cap at
 * 64 here to keep the generator's string picker focused).  SWN_IP is a
 * raw struct sockaddr_storage blob (the policy gates on
 * .len = sizeof(struct sockaddr_storage)).  The five _NOTIFY / KRB_AUTH
 * ids are NLA_FLAG (payload-less presence bits).
 *
 * default_version mirrors the declared CIFS_GENL_VERSION (1) so the
 * generator's wire format matches the kernel's declared family
 * version.  hdrsize stays 0: cifs has no family-specific fixed header,
 * attributes follow the genlmsghdr directly.
 *
 * Header gating mirrors the team / hsr / fou / psample / nbd / ncsi
 * families: <linux/cifs/cifs_netlink.h> (note the cifs/ subdir — the
 * uapi header is shipped under linux/cifs/, not linux/) is the upstream
 * UAPI header carrying every CIFS_GENL_CMD_* / CIFS_GENL_ATTR_* enum
 * referenced below.  Build hosts lacking the header silently drop the
 * family from the registry instead of failing the build.  Per-symbol
 * #ifndef shims fill in the enum ids on build hosts whose stale uapi
 * predates this family.
 */

#if __has_include(<linux/cifs/cifs_netlink.h>)

#include <linux/cifs/cifs_netlink.h>

#include "netlink-genl-families.h"
#include "utils.h"

#ifndef CIFS_GENL_NAME
#define CIFS_GENL_NAME			"cifs"
#endif
#ifndef CIFS_GENL_VERSION
#define CIFS_GENL_VERSION		0x1
#endif

#ifndef CIFS_GENL_CMD_SWN_NOTIFY
#define CIFS_GENL_CMD_SWN_NOTIFY	3
#endif

#ifndef CIFS_GENL_ATTR_SWN_REGISTRATION_ID
#define CIFS_GENL_ATTR_SWN_REGISTRATION_ID	1
#endif
#ifndef CIFS_GENL_ATTR_SWN_NET_NAME
#define CIFS_GENL_ATTR_SWN_NET_NAME		2
#endif
#ifndef CIFS_GENL_ATTR_SWN_SHARE_NAME
#define CIFS_GENL_ATTR_SWN_SHARE_NAME		3
#endif
#ifndef CIFS_GENL_ATTR_SWN_IP
#define CIFS_GENL_ATTR_SWN_IP			4
#endif
#ifndef CIFS_GENL_ATTR_SWN_NET_NAME_NOTIFY
#define CIFS_GENL_ATTR_SWN_NET_NAME_NOTIFY	5
#endif
#ifndef CIFS_GENL_ATTR_SWN_SHARE_NAME_NOTIFY
#define CIFS_GENL_ATTR_SWN_SHARE_NAME_NOTIFY	6
#endif
#ifndef CIFS_GENL_ATTR_SWN_IP_NOTIFY
#define CIFS_GENL_ATTR_SWN_IP_NOTIFY		7
#endif
#ifndef CIFS_GENL_ATTR_SWN_KRB_AUTH
#define CIFS_GENL_ATTR_SWN_KRB_AUTH		8
#endif
#ifndef CIFS_GENL_ATTR_SWN_USER_NAME
#define CIFS_GENL_ATTR_SWN_USER_NAME		9
#endif
#ifndef CIFS_GENL_ATTR_SWN_PASSWORD
#define CIFS_GENL_ATTR_SWN_PASSWORD		10
#endif
#ifndef CIFS_GENL_ATTR_SWN_DOMAIN_NAME
#define CIFS_GENL_ATTR_SWN_DOMAIN_NAME		11
#endif
#ifndef CIFS_GENL_ATTR_SWN_NOTIFICATION_TYPE
#define CIFS_GENL_ATTR_SWN_NOTIFICATION_TYPE	12
#endif
#ifndef CIFS_GENL_ATTR_SWN_RESOURCE_STATE
#define CIFS_GENL_ATTR_SWN_RESOURCE_STATE	13
#endif
#ifndef CIFS_GENL_ATTR_SWN_RESOURCE_NAME
#define CIFS_GENL_ATTR_SWN_RESOURCE_NAME	14
#endif

static const struct genl_cmd_grammar cifs_cmds[] = {
	{ CIFS_GENL_CMD_SWN_NOTIFY,	"CIFS_GENL_CMD_SWN_NOTIFY" },
};

/*
 * Attribute spec mirrors cifs_genl_policy in fs/smb/client/netlink.c.
 * SWN_IP is the sockaddr_storage blob the policy gates on by length
 * (.len = sizeof(struct sockaddr_storage) = 128); emit it as a binary
 * payload of that exact upper bound.  The five FLAG entries
 * (_NOTIFY / KRB_AUTH) are payload-less presence bits.  Strings are
 * unbounded in the kernel policy; cap at 64 here to keep the
 * generator's string picker focused on plausible witness names.
 */
static const struct nla_attr_spec cifs_attrs[] = {
	{ CIFS_GENL_ATTR_SWN_REGISTRATION_ID,	NLA_KIND_U32,    4   },
	{ CIFS_GENL_ATTR_SWN_NET_NAME,		NLA_KIND_STRING, 64  },
	{ CIFS_GENL_ATTR_SWN_SHARE_NAME,	NLA_KIND_STRING, 64  },
	{ CIFS_GENL_ATTR_SWN_IP,		NLA_KIND_BINARY, 128 },
	{ CIFS_GENL_ATTR_SWN_NET_NAME_NOTIFY,	NLA_KIND_FLAG,   0   },
	{ CIFS_GENL_ATTR_SWN_SHARE_NAME_NOTIFY,	NLA_KIND_FLAG,   0   },
	{ CIFS_GENL_ATTR_SWN_IP_NOTIFY,		NLA_KIND_FLAG,   0   },
	{ CIFS_GENL_ATTR_SWN_KRB_AUTH,		NLA_KIND_FLAG,   0   },
	{ CIFS_GENL_ATTR_SWN_USER_NAME,		NLA_KIND_STRING, 64  },
	{ CIFS_GENL_ATTR_SWN_PASSWORD,		NLA_KIND_STRING, 64  },
	{ CIFS_GENL_ATTR_SWN_DOMAIN_NAME,	NLA_KIND_STRING, 64  },
	{ CIFS_GENL_ATTR_SWN_NOTIFICATION_TYPE,	NLA_KIND_U32,    4   },
	{ CIFS_GENL_ATTR_SWN_RESOURCE_STATE,	NLA_KIND_U32,    4   },
	{ CIFS_GENL_ATTR_SWN_RESOURCE_NAME,	NLA_KIND_STRING, 64  },
};

struct genl_family_grammar fam_cifs = {
	.name = CIFS_GENL_NAME,
	.cmds = cifs_cmds,
	.n_cmds = ARRAY_SIZE(cifs_cmds),
	.attrs = cifs_attrs,
	.n_attrs = ARRAY_SIZE(cifs_attrs),
	.default_version = CIFS_GENL_VERSION,
	.hdrsize = 0,
};

#endif /* __has_include(<linux/cifs/cifs_netlink.h>) */
