/*
 * Genetlink family grammar: ovpn (OpenVPN data-channel offload).
 *
 * The ovpn-dco kernel module exposes its userspace control plane
 * through a single generic-netlink family ("ovpn") covering the peer
 * lifecycle (PEER_NEW / PEER_SET / PEER_GET / PEER_DEL) and the
 * symmetric-key lifecycle (KEY_NEW / KEY_GET / KEY_SWAP / KEY_DEL).
 * All eight user-callable commands carry GENL_ADMIN_PERM (CAP_NET_ADMIN
 * gated), but the per-cmd nla_policy walker runs before the capability
 * check so the validator coverage lands unprivileged — penetrating the
 * family demuxer with a real family_id puts every parser plus the
 * peer-table and key-slot mutation paths directly in the fuzzer's reach.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-assigned
 * family_id for "ovpn", so the per-cmd policy walker plus the peer /
 * key dispatch chains have been routinely cold under generic netlink
 * fuzzing; resolving the family at first NETLINK_GENERIC use lets the
 * message generator address real ovpn messages whose attribute shapes
 * plausibly survive the per-cmd policy.
 *
 * The two *_NTF notification command ids (PEER_DEL_NTF, KEY_SWAP_NTF)
 * are intentionally omitted: the kernel rejects them when issued from
 * userspace, so listing them in the grammar would only burn fuzz
 * budget on a guaranteed -EOPNOTSUPP fast-reject.
 *
 * Per the wireguard / tipc / l2tp / team / hsr / fou / psample /
 * tcp_metrics model, a single flat nla_attr_spec table lists every id
 * used by this family's commands.  ovpn's top-level OVPN_A_* namespace
 * is small (IFINDEX scalar plus the PEER / KEYCONF nested containers);
 * the rich content — the per-peer transport-endpoint quad (REMOTE_IPV4
 * / REMOTE_IPV6 / REMOTE_IPV6_SCOPE_ID / REMOTE_PORT), the per-peer
 * VPN-side addresses (VPN_IPV4 / VPN_IPV6), the matching LOCAL_IPV4 /
 * LOCAL_IPV6 / LOCAL_PORT triple, the keepalive interval / timeout
 * pair, the response-side per-direction byte / packet counters, the
 * KEYCONF slot / key-id / cipher-alg / encrypt-dir / decrypt-dir tuple,
 * and the inner KEYDIR cipher-key + nonce-tail payloads — lives inside
 * those nested containers.  Following the psample-TUNNEL precedent the
 * two nested containers are emitted as empty NLA_KIND_NESTED entries
 * so the kernel's nla_validate accepts them at the outer level without
 * recursing into a per-nest sub-policy.
 *
 * The family carries a nonzero declared version (OVPN_FAMILY_VERSION =
 * 1) so the default_version member is initialised — the kernel's
 * dispatchers don't actually gate on the genlmsghdr.version byte today,
 * but matching the declared family version keeps the message generator
 * honest against any future version-gated dispatch.  hdrsize stays 0:
 * ovpn has no family-specific fixed header, attributes follow the
 * genlmsghdr directly.
 *
 * Header gating mirrors the team / hsr / fou / psample / batadv /
 * tcp_metrics families: <linux/ovpn.h> is the upstream UAPI header
 * carrying every OVPN_CMD_* / OVPN_A_* enum referenced below.  Build
 * hosts lacking the header silently drop the family from the registry
 * instead of failing the build.  Per-symbol #ifndef shims in
 * include/kernel/ovpn.h fill in OVPN_CMD_* / OVPN_A_* on build hosts
 * whose installed uapi predates this family.
 *
 * arch.h is included unconditionally above the __has_include guard so
 * the translation unit is never empty even on build hosts whose uapi
 * lacks <linux/ovpn.h> — the toolchain emits no compile-unit-empty
 * warning and the registry-side ifdef'd extern stays consistent with
 * the absent strong symbol.
 */

#include "arch.h"

#if __has_include(<linux/ovpn.h>)

#include "kernel/ovpn.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * ovpn exposes eight user-callable commands: a four-command peer
 * lifecycle (NEW / SET / GET / DEL) and a four-command symmetric-key
 * lifecycle (NEW / GET / SWAP / DEL).  All eight are GENL_ADMIN_PERM
 * but the nla_policy walker runs before the capability check, so
 * listing all eight ids exercises every per-cmd parser symmetrically
 * under the unprivileged fuzzer.  The two *_NTF notification ids
 * (PEER_DEL_NTF, KEY_SWAP_NTF) are kernel-to-userspace only and the
 * dispatcher rejects them on input — they are omitted by design.
 */
static const struct genl_cmd_grammar ovpn_cmds[] = {
	{ OVPN_CMD_PEER_NEW,	"OVPN_CMD_PEER_NEW" },
	{ OVPN_CMD_PEER_SET,	"OVPN_CMD_PEER_SET" },
	{ OVPN_CMD_PEER_GET,	"OVPN_CMD_PEER_GET" },
	{ OVPN_CMD_PEER_DEL,	"OVPN_CMD_PEER_DEL" },
	{ OVPN_CMD_KEY_NEW,	"OVPN_CMD_KEY_NEW" },
	{ OVPN_CMD_KEY_GET,	"OVPN_CMD_KEY_GET" },
	{ OVPN_CMD_KEY_SWAP,	"OVPN_CMD_KEY_SWAP" },
	{ OVPN_CMD_KEY_DEL,	"OVPN_CMD_KEY_DEL" },
};

/*
 * Attribute spec follows the top-level OVPN_A_* enum in <linux/ovpn.h>.
 * IFINDEX is a u32 ovpn-device netdev selector that every command keys
 * on.  PEER and KEYCONF are the two nominally nested attrs — emitted
 * as empty containers psample-TUNNEL style so the kernel's
 * nla_validate accepts them at the outer level without recursing into
 * the per-nest sub-policies.  The richer inner content (the per-peer
 * REMOTE_* / LOCAL_* / VPN_* address-and-port set, keepalive pair, and
 * per-direction byte / packet counters under OVPN_A_PEER; the
 * SLOT / KEY_ID / CIPHER_ALG / ENCRYPT_DIR / DECRYPT_DIR tuple and the
 * inner KEYDIR CIPHER_KEY / NONCE_TAIL payloads under OVPN_A_KEYCONF)
 * is described above for the next reader who extends the grammar to
 * recursive nested emission; it is not enumerated in the flat spec
 * table because the OVPN_A_PEER_* / OVPN_A_KEYCONF_* / OVPN_A_KEYDIR_*
 * enums share id 1..N with the top-level OVPN_A_* namespace and a
 * single flat table cannot disambiguate the overlapping keys.
 */
static const struct nla_attr_spec ovpn_attrs[] = {
	{ OVPN_A_IFINDEX,	NLA_KIND_U32,    4 },
	{ OVPN_A_PEER,		NLA_KIND_NESTED, 0 },
	{ OVPN_A_KEYCONF,	NLA_KIND_NESTED, 0 },
};

struct genl_family_grammar fam_ovpn = {
	.name = OVPN_FAMILY_NAME,
	.cmds = ovpn_cmds,
	.n_cmds = ARRAY_SIZE(ovpn_cmds),
	.attrs = ovpn_attrs,
	.n_attrs = ARRAY_SIZE(ovpn_attrs),
	.default_version = OVPN_FAMILY_VERSION,
};

#endif /* __has_include(<linux/ovpn.h>) */
