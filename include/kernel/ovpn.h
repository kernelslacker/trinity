#pragma once

/*
 * Wrapper around <linux/ovpn.h> that ships the #ifndef-guarded
 * fallbacks for OVPN_CMD_* / OVPN_A_* ids and the OVPN_FAMILY_NAME /
 * OVPN_FAMILY_VERSION macros.  The .c side includes this from inside
 * its `#if __has_include(<linux/ovpn.h>)` gate, so the header itself
 * can include <linux/ovpn.h> unconditionally.
 */
#include <linux/ovpn.h>

#ifndef OVPN_FAMILY_NAME
#define OVPN_FAMILY_NAME		"ovpn"
#endif
#ifndef OVPN_FAMILY_VERSION
#define OVPN_FAMILY_VERSION		1
#endif

/*
 * Per-symbol shims for OVPN_CMD_* / OVPN_A_* ids.  Build hosts whose
 * <linux/ovpn.h> is older than the upstream uapi silently miss the
 * newer ids; the fallback values match the upstream uapi enum ordering
 * so the wire-format ids the kernel parses match the ones the
 * generator emits.  The *_NTF notification command ids are intentionally
 * omitted: the kernel rejects them when issued from userspace, so
 * listing them in the grammar would only burn fuzz budget on a
 * guaranteed -EOPNOTSUPP fast-reject.
 */
#ifndef OVPN_CMD_PEER_NEW
#define OVPN_CMD_PEER_NEW			1
#endif
#ifndef OVPN_CMD_PEER_SET
#define OVPN_CMD_PEER_SET			2
#endif
#ifndef OVPN_CMD_PEER_GET
#define OVPN_CMD_PEER_GET			3
#endif
#ifndef OVPN_CMD_PEER_DEL
#define OVPN_CMD_PEER_DEL			4
#endif
#ifndef OVPN_CMD_KEY_NEW
#define OVPN_CMD_KEY_NEW			6
#endif
#ifndef OVPN_CMD_KEY_GET
#define OVPN_CMD_KEY_GET			7
#endif
#ifndef OVPN_CMD_KEY_SWAP
#define OVPN_CMD_KEY_SWAP			8
#endif
#ifndef OVPN_CMD_KEY_DEL
#define OVPN_CMD_KEY_DEL			10
#endif

#ifndef OVPN_A_IFINDEX
#define OVPN_A_IFINDEX				1
#endif
#ifndef OVPN_A_PEER
#define OVPN_A_PEER				2
#endif
#ifndef OVPN_A_KEYCONF
#define OVPN_A_KEYCONF				3
#endif

#ifndef OVPN_A_PEER_ID
#define OVPN_A_PEER_ID				1
#endif
#ifndef OVPN_A_PEER_REMOTE_IPV4
#define OVPN_A_PEER_REMOTE_IPV4			2
#endif
#ifndef OVPN_A_PEER_REMOTE_IPV6
#define OVPN_A_PEER_REMOTE_IPV6			3
#endif
#ifndef OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID
#define OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID	4
#endif
#ifndef OVPN_A_PEER_REMOTE_PORT
#define OVPN_A_PEER_REMOTE_PORT			5
#endif
#ifndef OVPN_A_PEER_SOCKET
#define OVPN_A_PEER_SOCKET			6
#endif
#ifndef OVPN_A_PEER_SOCKET_NETNSID
#define OVPN_A_PEER_SOCKET_NETNSID		7
#endif
#ifndef OVPN_A_PEER_VPN_IPV4
#define OVPN_A_PEER_VPN_IPV4			8
#endif
#ifndef OVPN_A_PEER_VPN_IPV6
#define OVPN_A_PEER_VPN_IPV6			9
#endif
#ifndef OVPN_A_PEER_LOCAL_IPV4
#define OVPN_A_PEER_LOCAL_IPV4			10
#endif
#ifndef OVPN_A_PEER_LOCAL_IPV6
#define OVPN_A_PEER_LOCAL_IPV6			11
#endif
#ifndef OVPN_A_PEER_LOCAL_PORT
#define OVPN_A_PEER_LOCAL_PORT			12
#endif
#ifndef OVPN_A_PEER_KEEPALIVE_INTERVAL
#define OVPN_A_PEER_KEEPALIVE_INTERVAL		13
#endif
#ifndef OVPN_A_PEER_KEEPALIVE_TIMEOUT
#define OVPN_A_PEER_KEEPALIVE_TIMEOUT		14
#endif
#ifndef OVPN_A_PEER_DEL_REASON
#define OVPN_A_PEER_DEL_REASON			15
#endif
#ifndef OVPN_A_PEER_VPN_RX_BYTES
#define OVPN_A_PEER_VPN_RX_BYTES		16
#endif
#ifndef OVPN_A_PEER_VPN_TX_BYTES
#define OVPN_A_PEER_VPN_TX_BYTES		17
#endif
#ifndef OVPN_A_PEER_VPN_RX_PACKETS
#define OVPN_A_PEER_VPN_RX_PACKETS		18
#endif
#ifndef OVPN_A_PEER_VPN_TX_PACKETS
#define OVPN_A_PEER_VPN_TX_PACKETS		19
#endif
#ifndef OVPN_A_PEER_LINK_RX_BYTES
#define OVPN_A_PEER_LINK_RX_BYTES		20
#endif
#ifndef OVPN_A_PEER_LINK_TX_BYTES
#define OVPN_A_PEER_LINK_TX_BYTES		21
#endif
#ifndef OVPN_A_PEER_LINK_RX_PACKETS
#define OVPN_A_PEER_LINK_RX_PACKETS		22
#endif
#ifndef OVPN_A_PEER_LINK_TX_PACKETS
#define OVPN_A_PEER_LINK_TX_PACKETS		23
#endif

#ifndef OVPN_A_KEYCONF_PEER_ID
#define OVPN_A_KEYCONF_PEER_ID			1
#endif
#ifndef OVPN_A_KEYCONF_SLOT
#define OVPN_A_KEYCONF_SLOT			2
#endif
#ifndef OVPN_A_KEYCONF_KEY_ID
#define OVPN_A_KEYCONF_KEY_ID			3
#endif
#ifndef OVPN_A_KEYCONF_CIPHER_ALG
#define OVPN_A_KEYCONF_CIPHER_ALG		4
#endif
#ifndef OVPN_A_KEYCONF_ENCRYPT_DIR
#define OVPN_A_KEYCONF_ENCRYPT_DIR		5
#endif
#ifndef OVPN_A_KEYCONF_DECRYPT_DIR
#define OVPN_A_KEYCONF_DECRYPT_DIR		6
#endif

#ifndef OVPN_A_KEYDIR_CIPHER_KEY
#define OVPN_A_KEYDIR_CIPHER_KEY		1
#endif
#ifndef OVPN_A_KEYDIR_NONCE_TAIL
#define OVPN_A_KEYDIR_NONCE_TAIL		2
#endif

#ifndef OVPN_NONCE_TAIL_SIZE
#define OVPN_NONCE_TAIL_SIZE			8
#endif
