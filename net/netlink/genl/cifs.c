/*
 * Genetlink family grammar: cifs (SMB Witness Service upcall), targeting
 * fs/smb/client/netlink.c.  The ops table lists only SWN_NOTIFY, which is
 * GENL_ADMIN_PERM; REGISTER / UNREGISTER are events the kernel multicasts.
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
 * payload of that exact upper bound.  The four FLAG entries
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
