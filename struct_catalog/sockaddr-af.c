/*
 * struct_catalog/sockaddr-af.c -- sockaddr_storage tagged-union
 * variants and per-address-family field arrays.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` / `.variants =` references resolve via the externs in
 * struct_catalog-internal.h.  struct_catalog.h and arch.h are #included
 * unconditionally so this TU is never empty when USE_<X> is off.
 */

#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/tipc.h>
/*
 * <linux/fs.h> defines FILE_ATTR_SIZE_VER0 + struct file_attr; bring
 * it in before the kernel fallback header so that header's older-headers fallback for
 * struct file_attr stays inactive.  Sockaddr leaf data does not use
 * the type, but struct_catalog.h pulls <linux/aio_abi.h> -> <linux/fs.h>
 * below and a duplicate definition would -Werror.
 */
#include <linux/fs.h>

#include "config.h"
/*
 * linux/if_pppox.h pulls in linux/l2tp.h, whose enum declares
 * L2TP_ATTR_IP6_SADDR / RX_COOKIE_DISCARDS / ... as identifiers.
 * include/kernel headers define those same names as fallback numeric macros for
 * older kernel-headers packages, so the include must precede the kernel fallback header;
 * otherwise the macro expansion turns the enum members into integer
 * literals and -Werror trips.
 */
#ifdef USE_PPPOX
#include <linux/if_pppox.h>
#endif
#ifdef USE_VSOCK
#include <linux/vm_sockets.h>
#endif
#ifdef USE_CAIF
#include <linux/caif/caif_socket.h>
#endif
#ifdef USE_CAN
#include <linux/can.h>
#endif
#ifdef USE_RXRPC
#include <linux/rxrpc.h>
#endif
#ifdef USE_X25
#include <linux/x25.h>
#endif
#ifdef USE_PHONET
#include <linux/phonet.h>
#endif
#ifdef USE_AX25
#include <linux/ax25.h>
#endif
#ifdef USE_ROSE
#include <linux/rose.h>
#endif
#ifdef USE_ATM
#include <linux/atm.h>
#endif
#ifdef USE_LLC
#include <linux/llc.h>
#endif
#ifdef USE_MCTP
#include <linux/mctp.h>
#endif
#ifdef USE_IF_ALG
#include <linux/if_alg.h>
#endif
#ifdef USE_XDP
#include <linux/if_xdp.h>
/*
 * XDP_USE_NEED_WAKEUP landed in 5.4 (commit 77cd0d7b3f25); older
 * toolchain headers won't carry it even when the rest of the
 * sockaddr_xdp definitions are present.  Fall back to the upstream
 * bit value so the FT_FLAGS mask stays the same on either side.
 */
#ifndef XDP_USE_NEED_WAKEUP
#define XDP_USE_NEED_WAKEUP	(1 << 3)
#endif
#ifndef XDP_USE_SG
#define XDP_USE_SG		(1 << 4)
#endif
#endif

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"
#include "utils.h"

#include "kernel/qrtr.h"
#include "kernel/nfc.h"
#include "kernel/l2tp.h"
#include "kernel/socket.h"
#include "kernel/fs.h"
/* ------------------------------------------------------------------ */
/* struct sockaddr_storage (bind, connect, sendto, ...)                */
/* ------------------------------------------------------------------ */

/*
 * Tagged-union on ss_family.  Per-AF sub-variants live below; each
 * variant's fields[] runs against the same sockaddr_storage envelope
 * so offsets are buffer-relative (offsetof on the per-AF struct
 * happens to match offsetof on sockaddr_storage for the shared head).
 *
 * ss_family itself is FT_ENUM over the curated vocab so the scalar
 * pass writes a value the resolver will then match; an FT_RAW splat
 * lands on a known AF roughly 1-in-8 instead of 1-in-32768, which is
 * the difference between "variant fires" and "variant is theoretical".
 *
 * Variants intentionally omit ss_family from their fields[] -- the
 * shared head pass already wrote it.  Each variant declares an
 * effective_size matching the per-AF sizeof(struct sockaddr_XX) so
 * the paired FT_LEN_BYTES (msghdr.msg_namelen) reports the kernel-
 * expected length rather than the full 128-byte envelope.
 *
 * Long-tail families (AF_BLUETOOTH, AF_RDS, ...) fall
 * through to the shared head pass alone: ss_family lands on a known
 * AF value but the rest of the buffer stays opaque, matching today's
 * pre-variant placeholder behaviour for those families.  AF_BLUETOOTH
 * needs socket-state to disambiguate L2CAP / RFCOMM / HCI / SCO and
 * AF_RDS reuses sockaddr_in / sockaddr_in6 wholesale, so neither
 * fits the single-buffer discriminator the variants table walks.
 */
const unsigned long sockaddr_storage_af_vocab[] = {
	AF_UNIX, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET,
#ifdef USE_VSOCK
	AF_VSOCK,
#endif
#ifdef USE_PPPOX
	AF_PPPOX,
#endif
#ifdef USE_CAIF
	AF_CAIF,
#endif
#ifdef USE_CAN
	AF_CAN,
#endif
#ifdef USE_RXRPC
	AF_RXRPC,
#endif
#ifdef USE_X25
	AF_X25,
#endif
#ifdef USE_PHONET
	AF_PHONET,
#endif
#ifdef USE_AX25
	AF_AX25,
	AF_NETROM,
#endif
#ifdef USE_ROSE
	AF_ROSE,
#endif
#ifdef USE_ATM
	AF_ATMPVC,
#endif
#ifdef USE_LLC
	AF_LLC,
#endif
#ifdef USE_MCTP
	AF_MCTP,
#endif
#ifdef USE_IF_ALG
	AF_ALG,
#endif
	AF_TIPC,
	AF_QIPCRTR,
	AF_NFC,
#ifdef USE_XDP
	AF_XDP,
#endif
};

/*
 * AF_PACKET curated vocabularies.  Each enum table targets a
 * specific dispatch the kernel does in packet_rcv / af_packet's
 * deliver paths -- protocol decode, ARP hardware type lookup, and
 * the rx-type classifier respectively.  Sets stay small to keep
 * the enum-pick distribution biased toward kernel-visible buckets.
 */
const unsigned long packet_eth_p_vocab[] = {
	ETH_P_LOOP, ETH_P_ALL, ETH_P_IP, ETH_P_ARP, ETH_P_RARP,
	ETH_P_8021Q, ETH_P_IPV6, ETH_P_MPLS_UC, ETH_P_MPLS_MC,
	ETH_P_LOOPBACK,
};

const unsigned long packet_arphrd_vocab[] = {
	ARPHRD_ETHER, ARPHRD_PPP, ARPHRD_TUNNEL, ARPHRD_TUNNEL6,
	ARPHRD_LOOPBACK, ARPHRD_SIT, ARPHRD_IPGRE, ARPHRD_VOID,
	ARPHRD_NONE,
};

const unsigned long packet_pkttype_vocab[] = {
	PACKET_HOST, PACKET_BROADCAST, PACKET_MULTICAST, PACKET_OTHERHOST,
	PACKET_OUTGOING, PACKET_LOOPBACK, PACKET_USER, PACKET_KERNEL,
};

/* AF_UNIX (sockaddr_un) -- 2-byte family + 108-byte sun_path. */
const struct struct_field sockaddr_un_variant_fields[] = {
	FIELD(struct sockaddr_un, sun_path),
};

/* AF_INET (sockaddr_in) -- u16 port + 32-bit IPv4 + 8 bytes pad. */
const struct struct_field sockaddr_in_variant_fields[] = {
	FIELD(struct sockaddr_in, sin_port),
	FIELD(struct sockaddr_in, sin_addr),
};

/*
 * AF_INET6 (sockaddr_in6) -- IPv6 endpoint.  sin6_scope_id is an
 * ifindex; trinity has no live ifindex pool so a coarse range covers
 * the typical machine's interface count without paying for a /proc
 * scan at init.
 */
const struct struct_field sockaddr_in6_variant_fields[] = {
	FIELD(struct sockaddr_in6, sin6_port),
	FIELD(struct sockaddr_in6, sin6_flowinfo),
	FIELD(struct sockaddr_in6, sin6_addr),
	FIELDX(struct sockaddr_in6, sin6_scope_id, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 64 }),
};

/*
 * AF_NETLINK (sockaddr_nl) -- nl_groups is a multicast bitmask whose
 * meaning depends on which NETLINK_* family the socket was opened
 * with; that's not discoverable from sockaddr_nl alone so the mask
 * stays generic-full-32.  Family-aware biasing is currently unmodeled.
 */
const struct struct_field sockaddr_nl_variant_fields[] = {
	FIELD(struct sockaddr_nl, nl_pad),
	FIELD(struct sockaddr_nl, nl_pid),
	FIELDX(struct sockaddr_nl, nl_groups, FT_FLAGS,
	       .u.flags.mask = 0xFFFFFFFFUL),
};

/*
 * AF_PACKET (sockaddr_ll) -- raw socket endpoint.  sll_halen is
 * bounded by the 8-byte sll_addr buffer the variant emits; the
 * kernel reads only the first sll_halen bytes regardless of what
 * landed in the tail, so leaving sll_addr as FT_RAW and sll_halen
 * as FT_RANGE without coupling them is fine.
 */
const struct struct_field sockaddr_ll_variant_fields[] = {
	FIELDX(struct sockaddr_ll, sll_protocol, FT_ENUM,
	       .u.enum_ = { .vals = packet_eth_p_vocab,
			    .n    = ARRAY_SIZE(packet_eth_p_vocab) }),
	FIELDX(struct sockaddr_ll, sll_ifindex, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 64 }),
	FIELDX(struct sockaddr_ll, sll_hatype, FT_ENUM,
	       .u.enum_ = { .vals = packet_arphrd_vocab,
			    .n    = ARRAY_SIZE(packet_arphrd_vocab) }),
	FIELDX(struct sockaddr_ll, sll_pkttype, FT_ENUM,
	       .u.enum_ = { .vals = packet_pkttype_vocab,
			    .n    = ARRAY_SIZE(packet_pkttype_vocab) }),
	FIELDX(struct sockaddr_ll, sll_halen, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 8 }),
	FIELD(struct sockaddr_ll, sll_addr),
};

#ifdef USE_VSOCK
/*
 * AF_VSOCK (sockaddr_vm) -- VMware/hypervisor socket endpoint.
 * svm_cid picks from the small set of well-known CIDs the kernel
 * recognises (any/hypervisor/local/host); arbitrary CIDs are rare
 * and bias toward unrouteable.  svm_flags has exactly one defined
 * bit today.  svm_reserved1 and svm_zero stay FT_RAW; the kernel
 * doesn't enforce them but accepts whatever the buffer carries.
 */
const unsigned long vsock_cid_vocab[] = {
	VMADDR_CID_ANY, VMADDR_CID_HYPERVISOR,
	VMADDR_CID_LOCAL, VMADDR_CID_HOST,
};

const struct struct_field sockaddr_vm_variant_fields[] = {
	FIELD(struct sockaddr_vm, svm_reserved1),
	FIELD(struct sockaddr_vm, svm_port),
	FIELDX(struct sockaddr_vm, svm_cid, FT_ENUM,
	       .u.enum_ = { .vals = vsock_cid_vocab,
			    .n    = ARRAY_SIZE(vsock_cid_vocab) }),
	FIELDX(struct sockaddr_vm, svm_flags, FT_FLAGS,
	       .u.flags.mask = VMADDR_FLAG_TO_HOST),
};
#endif

#ifdef USE_PPPOX
/*
 * AF_PPPOX (sockaddr_pppox) -- PPP-over-X transport endpoint.  The
 * scalar head carries sa_protocol (PX_PROTO_OE / PX_PROTO_OL2TP / ...
 * the kernel dispatches on); an unsigned int that reaches dispatch
 * as raw, so FT_RAW covers the surface without a curated vocabulary.
 * sa_family is omitted; the shared-head pass already writes
 * ss_family.  struct sockaddr_pppox is packed, so sa_protocol sits
 * at offset 2 (not 4).  The trailing union sa_addr (pppoe / pptp /
 * ...) stays HELD and zeroed -- the kernel parses it conditional on
 * sa_protocol and an unmodeled inner address won't bias dispatch.
 */
const struct struct_field sockaddr_pppox_variant_fields[] = {
	FIELD(struct sockaddr_pppox, sa_protocol),
};
#endif

#ifdef USE_CAIF
/*
 * AF_CAIF (sockaddr_caif) -- ST-Ericsson modem CAIF endpoint.  The
 * scalar head carries u.dgm.connection_id (datagram service id the
 * kernel dispatches on); a __u32 that reaches dispatch as raw, so
 * FT_RAW covers the surface without a curated vocabulary.  The
 * family field is omitted; the shared-head pass already writes
 * ss_family.  The remaining union u arms (at/util/rfm/dbg) stay
 * HELD and zeroed -- the kernel parses them conditional on the
 * socket protocol (CAIFPROTO_*) and an unmodeled inner address
 * won't bias dispatch.
 */
const struct struct_field sockaddr_caif_variant_fields[] = {
	FIELD(struct sockaddr_caif, u.dgm.connection_id),
};
#endif

#ifdef USE_CAN
/*
 * AF_CAN (sockaddr_can) -- Controller Area Network endpoint.  The
 * scalar head carries can_ifindex (CAN network interface), which
 * reaches dispatch as a raw int; FT_RAW covers the surface without
 * a live ifindex pool.  can_family is omitted; the shared-head pass
 * already writes ss_family.  The trailing union can_addr is
 * protocol-specific (raw/bcm/tp16/tp20/mcnet/isotp/j1939) and stays
 * HELD and zeroed -- the kernel parses it conditional on the socket
 * protocol and an unmodeled inner address won't bias dispatch.
 */
const struct struct_field sockaddr_can_variant_fields[] = {
	FIELD(struct sockaddr_can, can_ifindex),
};
#endif

#ifdef USE_RXRPC
/*
 * AF_RXRPC (sockaddr_rxrpc) -- AFS/RxRPC endpoint.  The scalar head
 * carries srx_service (service-id the kernel dispatches on),
 * transport_type (SOCK_DGRAM-style selector), and transport_len
 * (size of the trailing transport union).  All three reach dispatch
 * as raw __u16s, so FT_RAW covers the surface without a curated
 * vocabulary.  srx_family is omitted; the shared-head pass already
 * writes ss_family.  The union transport (sa/sin/sin6) stays HELD
 * and zeroed -- the kernel parses it conditional on transport_len
 * and an unmodeled inner address won't bias dispatch.
 */
const struct struct_field sockaddr_rxrpc_variant_fields[] = {
	FIELD(struct sockaddr_rxrpc, srx_service),
	FIELD(struct sockaddr_rxrpc, transport_type),
	FIELD(struct sockaddr_rxrpc, transport_len),
};
#endif

#ifdef USE_X25
/*
 * AF_X25 (sockaddr_x25) -- ITU-T X.25 packet-switched endpoint.
 * The only payload member is sx25_addr.x25_addr, a 16-byte buffer
 * carrying an ASCII X.121 address (up to 15 digits plus NUL).  The
 * kernel walks the bytes via strncmp against the bound listener and
 * does not enforce digit-only content at bind, so FT_RAW covers the
 * dispatch surface without a digit vocabulary.  sx25_family is
 * omitted; the shared-head pass already writes ss_family.
 */
const struct struct_field sockaddr_x25_variant_fields[] = {
	FIELD(struct sockaddr_x25, sx25_addr.x25_addr),
};
#endif

#ifdef USE_PHONET
/*
 * AF_PHONET (sockaddr_pn) -- Nokia Phonet endpoint.  The address tuple
 * is three packed __u8 scalars: spn_obj (object id within the device),
 * spn_dev (device byte; low two bits steal port high-bits via the
 * pn_sockaddr_set_port helper), and spn_resource (the routed-to
 * resource id matched in pn_find_sock_by_res()).  All three reach
 * dispatch as raw bytes, so FT_RAW covers the surface without a
 * curated vocabulary.  struct sockaddr_pn is packed, so offsetof
 * honours the lack of natural alignment.  spn_family and spn_zero[]
 * are omitted; the shared-head pass writes ss_family and the zero
 * padding stays zeroed.
 */
const struct struct_field sockaddr_pn_variant_fields[] = {
	FIELD(struct sockaddr_pn, spn_obj),
	FIELD(struct sockaddr_pn, spn_dev),
	FIELD(struct sockaddr_pn, spn_resource),
};
#endif

#ifdef USE_AX25
/*
 * AF_AX25 (sockaddr_ax25) -- amateur-radio packet endpoint.  The
 * base struct carries the 7-byte AX.25 callsign (ax25_address, a
 * shifted-ASCII callsign + SSID byte the kernel walks via ax25cmp()
 * in ax25_bind / ax25_connect) and sax25_ndigis, the digipeater
 * count the kernel uses to decide whether to read the trailing
 * fsa_digipeater[] array of full_sockaddr_ax25.  trinity steers the
 * base sockaddr_ax25 only; full_sockaddr_ax25's variable-length
 * digipeater tail is intentionally out of scope here so the variant
 * stays a fixed-size record.  sax25_family is omitted; the shared-
 * head pass already writes ss_family.
 */
const struct struct_field sockaddr_ax25_variant_fields[] = {
	FIELD(struct sockaddr_ax25, sax25_call),
	FIELD(struct sockaddr_ax25, sax25_ndigis),
};
#endif

#ifdef USE_ROSE
/*
 * AF_ROSE (sockaddr_rose) -- ROSE (Rec.X.25 over amateur radio) endpoint.
 * The address tuple is a 5-byte ROSE address (rose_address), the 7-byte
 * AX.25 source callsign (ax25_address), the digipeater count the kernel
 * uses to gate consumption of the trailing digipeater slot, and a single
 * 7-byte AX.25 digipeater callsign.  The kernel walks these raw via
 * rose_bind / rose_connect (net/rose/af_rose.c) against the bound ROSE
 * neighbour table; FT_RAW covers the dispatch surface without curated
 * callsign / ROSE-address vocabularies.  trinity steers the base
 * sockaddr_rose only; full_sockaddr_rose's variable-length digipeater
 * tail is intentionally out of scope here so the variant stays a
 * fixed-size record.  srose_family is omitted; the shared-head pass
 * already writes ss_family.
 */
const struct struct_field sockaddr_rose_variant_fields[] = {
	FIELD(struct sockaddr_rose, srose_addr),
	FIELD(struct sockaddr_rose, srose_call),
	FIELD(struct sockaddr_rose, srose_ndigis),
	FIELD(struct sockaddr_rose, srose_digi),
};
#endif

#ifdef USE_ATM
/*
 * AF_ATMPVC (sockaddr_atmpvc) -- ATM PVC endpoint.  The address is a
 * nested sap_addr aggregate of three scalars: the ATM interface index
 * (itf), the virtual path identifier (vpi) and the virtual channel
 * identifier (vci).  pvc_bind / pvc_connect (atm/pvc.c) consume the
 * tuple raw against the device's installed PVC table.  sap_family is
 * omitted; the shared-head pass writes ss_family.
 */
const struct struct_field sockaddr_atmpvc_variant_fields[] = {
	FIELD(struct sockaddr_atmpvc, sap_addr.itf),
	FIELD(struct sockaddr_atmpvc, sap_addr.vpi),
	FIELD(struct sockaddr_atmpvc, sap_addr.vci),
};
#endif

#ifdef USE_LLC
/*
 * AF_LLC (sockaddr_llc) -- IEEE 802.2 LLC endpoint.  The 16-byte
 * address is a flat (family, arphrd, test, xid, ua, sap, mac) tuple;
 * no inner tagged union, so this variant stays single-arm.  sllc_arphrd
 * is canonically ARPHRD_ETHER but the kernel does not reject other
 * values at bind, so it stays FT_RAW.  sllc_sap is the LSAP byte the
 * kernel matches in llc_ui_bind() via llc_sap_find(); leaving it
 * FT_RAW keeps the full 0x00-0xFF dispatch surface exposed.  sllc_mac
 * is a 6-byte hardware address the kernel walks via dev_get_by_index
 * / __dev_get_by_index against the bound interface; FT_RAW covers the
 * generic case without a /sys/class/net walk at init.
 */
const struct struct_field sockaddr_llc_variant_fields[] = {
	FIELD(struct sockaddr_llc, sllc_arphrd),
	FIELD(struct sockaddr_llc, sllc_test),
	FIELD(struct sockaddr_llc, sllc_xid),
	FIELD(struct sockaddr_llc, sllc_ua),
	FIELD(struct sockaddr_llc, sllc_sap),
	FIELD(struct sockaddr_llc, sllc_mac),
};
#endif

#ifdef USE_MCTP
/*
 * AF_MCTP (sockaddr_mctp) -- Management Component Transport Protocol
 * endpoint.  smctp_network / smctp_addr.s_addr / smctp_type carry the
 * raw routing bytes the kernel dispatches on; smctp_tag has one defined
 * owner bit.  smctp_family + the two pad bytes stay zeroed (the shared
 * head pass writes the family).
 */
const struct struct_field sockaddr_mctp_variant_fields[] = {
	FIELD(struct sockaddr_mctp, smctp_network),
	FIELD(struct sockaddr_mctp, smctp_addr.s_addr),
	FIELD(struct sockaddr_mctp, smctp_type),
	FIELDX(struct sockaddr_mctp, smctp_tag, FT_FLAGS,
	       .u.flags.mask = MCTP_TAG_OWNER),
};
#endif

#ifdef USE_IF_ALG
/*
 * AF_ALG (sockaddr_alg) -- crypto userspace endpoint.  salg_type and
 * salg_name are 14- and 64-byte NUL-padded strings the kernel feeds
 * straight into crypto_find_alg().  FT_VOCAB plants a curated string
 * from a known bucket / algorithm name so the bind path walks past
 * the lookup loop rather than tripping at -ENOENT on random bytes.
 * Per-field draws are independent: a type/name mismatch still drives
 * the full lookup, which is the kernel boundary trinity's proto-alg
 * dictionary documents as worth fuzzing.  salg_feat / salg_mask stay
 * FT_RAW pending a curated CRYPTO_ALG_* mask.
 */
const char *const salg_type_vocab[] = {
	"hash", "skcipher", "aead", "rng",
	"akcipher", "kpp", "shash", "ahash",
};

const char *const salg_name_vocab[] = {
	"sha1", "sha256", "sha512", "md5",
	"hmac(sha256)", "hmac(sha512)",
	"aes-cbc-essiv:sha256", "chacha20",
	"poly1305", "gcm(aes)", "ccm(aes)",
	"xts(aes)", "cbc(aes)", "ecb(aes)",
	"rfc4106(gcm(aes))",
};

const struct struct_field sockaddr_alg_variant_fields[] = {
	FIELDX(struct sockaddr_alg, salg_type, FT_VOCAB,
	       .u.vocab = { .vocab = salg_type_vocab,
			    .vocab_len = ARRAY_SIZE(salg_type_vocab),
			    .element_stride = sizeof(((struct sockaddr_alg *)NULL)->salg_type) }),
	FIELD(struct sockaddr_alg, salg_feat),
	FIELD(struct sockaddr_alg, salg_mask),
	FIELDX(struct sockaddr_alg, salg_name, FT_VOCAB,
	       .u.vocab = { .vocab = salg_name_vocab,
			    .vocab_len = ARRAY_SIZE(salg_name_vocab),
			    .element_stride = sizeof(((struct sockaddr_alg *)NULL)->salg_name) }),
};
#endif

/*
 * AF_TIPC (sockaddr_tipc) -- TIPC endpoint.  The outer variant fills
 * the (family, addrtype, scope) prefix; addrtype is itself a sub-
 * discriminator over the 12-byte inner addr union, so the per-arm
 * member layout is overlaid via nested_variants[].  Each arm leaves
 * its u32 sub-fields FT_RAW so the random splat carries through; the
 * tagged-union plumbing exists to anchor future ENUM/RANGE
 * annotations on type/instance/domain without re-touching the
 * sockaddr_storage entry.  effective_size stays at sizeof(struct
 * sockaddr_tipc) on every arm -- the kernel ABI rejects shorter
 * addrlens regardless of which inner arm is live.
 */
const unsigned long tipc_addrtype_vocab[] = {
	TIPC_ADDR_NAMESEQ, TIPC_ADDR_NAME, TIPC_ADDR_ID,
};

const unsigned long tipc_scope_vocab[] = {
	TIPC_ZONE_SCOPE, TIPC_CLUSTER_SCOPE, TIPC_NODE_SCOPE,
};

const struct struct_field sockaddr_tipc_variant_fields[] = {
	FIELDX(struct sockaddr_tipc, addrtype, FT_ENUM,
	       .u.enum_ = { .vals = tipc_addrtype_vocab,
			    .n    = ARRAY_SIZE(tipc_addrtype_vocab) }),
	FIELDX(struct sockaddr_tipc, scope, FT_ENUM,
	       .u.enum_ = { .vals = tipc_scope_vocab,
			    .n    = ARRAY_SIZE(tipc_scope_vocab) }),
};

const struct struct_field sockaddr_tipc_id_fields[] = {
	FIELD(struct sockaddr_tipc, addr.id.ref),
	FIELD(struct sockaddr_tipc, addr.id.node),
};

const struct struct_field sockaddr_tipc_nameseq_fields[] = {
	FIELD(struct sockaddr_tipc, addr.nameseq.type),
	FIELD(struct sockaddr_tipc, addr.nameseq.lower),
	FIELD(struct sockaddr_tipc, addr.nameseq.upper),
};

const struct struct_field sockaddr_tipc_name_fields[] = {
	FIELD(struct sockaddr_tipc, addr.name.name.type),
	FIELD(struct sockaddr_tipc, addr.name.name.instance),
	FIELD(struct sockaddr_tipc, addr.name.domain),
};

const struct union_variant sockaddr_tipc_addr_nested[] = {
	{
		.discrim_value	 = TIPC_ADDR_ID,
		.name		 = "TIPC_ADDR_ID",
		.fields		 = sockaddr_tipc_id_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_tipc_id_fields),
		.effective_size	 = sizeof(struct sockaddr_tipc),
	},
	{
		.discrim_value	 = TIPC_ADDR_NAMESEQ,
		.name		 = "TIPC_ADDR_NAMESEQ",
		.fields		 = sockaddr_tipc_nameseq_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_tipc_nameseq_fields),
		.effective_size	 = sizeof(struct sockaddr_tipc),
	},
	{
		.discrim_value	 = TIPC_ADDR_NAME,
		.name		 = "TIPC_ADDR_NAME",
		.fields		 = sockaddr_tipc_name_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_tipc_name_fields),
		.effective_size	 = sizeof(struct sockaddr_tipc),
	},
};

/*
 * AF_QIPCRTR (sockaddr_qrtr) -- Qualcomm IPC Router endpoint.  The
 * 12-byte address is a flat (family, node, port) triple -- no inner
 * tagged union, so this variant stays single-arm.  sq_family is the
 * outer discriminator and is filled by the family ENUM; sq_node and
 * sq_port are u32 routing IDs.
 *
 * Both ID spaces are sparsely populated in practice (a handful of
 * registered nodes, low-numbered well-known ports plus an auto-
 * allocated ephemeral range), so a curated FT_ENUM pool that mixes
 * low integers with the two magic sentinels (QRTR_NODE_BCAST, the
 * broadcast node, and QRTR_PORT_CTRL, the control-channel port the
 * kernel routes to qrtr_ctrl_recv()) drives more useful coverage
 * than a uniform 32-bit splat that almost always misses.  Mirrors
 * the vsock_cid_vocab FT_ENUM shape.
 */
const unsigned long qrtr_node_vocab[] = {
	0, 1, 2, 3, QRTR_NODE_BCAST,
};

const unsigned long qrtr_port_vocab[] = {
	0, 1, 2, QRTR_PORT_CTRL,
};

const struct struct_field sockaddr_qrtr_variant_fields[] = {
	FIELDX(struct sockaddr_qrtr, sq_node, FT_ENUM,
	       .u.enum_ = { .vals = qrtr_node_vocab,
			    .n    = ARRAY_SIZE(qrtr_node_vocab) }),
	FIELDX(struct sockaddr_qrtr, sq_port, FT_ENUM,
	       .u.enum_ = { .vals = qrtr_port_vocab,
			    .n    = ARRAY_SIZE(qrtr_port_vocab) }),
};

/*
 * AF_NFC (sockaddr_nfc) -- NFC raw socket endpoint.  The 16-byte
 * address is a flat (family, dev_idx, target_idx, nfc_protocol)
 * tuple -- no inner tagged union, so this variant stays single-arm
 * (mirrors AF_QIPCRTR).  sockaddr_nfc_llcp is a separate, larger
 * address only valid on NFC_SOCKPROTO_LLCP sockets; modelling it
 * needs a socket-state-aware discriminator the sockaddr_storage
 * envelope does not carry, so it stays out of this variant table.
 *
 * dev_idx / target_idx are the kernel's nfc_dev->idx and nfc_target
 * ->idx; both are densely packed from 0 and rarely exceed a handful
 * on real hardware, so a small FT_RANGE covers the live pool without
 * a /sys/class/nfc walk at init.  nfc_protocol is the per-target
 * protocol selector the kernel matches in rawsock_bind() via
 * nfc_find_target(); a curated FT_ENUM over the seven NFC_PROTO_*
 * values keeps the bind walk hitting registered protocols instead
 * of -EINVAL on a u32 splat.
 */
const unsigned long nfc_proto_vocab[] = {
	NFC_PROTO_JEWEL, NFC_PROTO_MIFARE, NFC_PROTO_FELICA,
	NFC_PROTO_ISO14443, NFC_PROTO_NFC_DEP, NFC_PROTO_ISO14443_B,
	NFC_PROTO_ISO15693,
};

const struct struct_field sockaddr_nfc_variant_fields[] = {
	FIELDX(struct sockaddr_nfc, dev_idx, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 }),
	FIELDX(struct sockaddr_nfc, target_idx, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 16 }),
	FIELDX(struct sockaddr_nfc, nfc_protocol, FT_ENUM,
	       .u.enum_ = { .vals = nfc_proto_vocab,
			    .n    = ARRAY_SIZE(nfc_proto_vocab) }),
};

#ifdef USE_XDP
/*
 * AF_XDP (sockaddr_xdp) -- XSK endpoint.  sxdp_flags drives the
 * UMEM / queue binding semantics; the kernel's xsk_bind() accepts
 * XDP_SHARED_UMEM | XDP_COPY | XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP |
 * XDP_USE_SG, so an FT_FLAGS pick over that mask keeps coverage on
 * the registered codepaths (including the multi-frag bind path).
 * sxdp_ifindex is a generic 32-bit ifindex -- trinity has no live
 * ifindex pool here, so leave it FT_RAW; bind() mostly fails at the
 * netlink lookup but xsk_bind itself still runs.  sxdp_queue_id
 * stays small since real NICs rarely expose many queues, biasing
 * the range toward something xsk_get_pool_from_qid may actually
 * accept.  sxdp_shared_umem_fd is only honoured with XDP_SHARED_UMEM
 * set, but an FT_FD slot biases toward an existing fd in the pool
 * so the rare accept path exercises something other than -EBADF.
 */
#define SOCKADDR_XDP_FLAGS_MASK						\
	(XDP_SHARED_UMEM | XDP_COPY | XDP_ZEROCOPY |			\
	 XDP_USE_NEED_WAKEUP | XDP_USE_SG)

const struct struct_field sockaddr_xdp_variant_fields[] = {
	FIELDX(struct sockaddr_xdp, sxdp_flags, FT_FLAGS,
	       .u.flags.mask = SOCKADDR_XDP_FLAGS_MASK),
	FIELD(struct sockaddr_xdp, sxdp_ifindex),
	FIELDX(struct sockaddr_xdp, sxdp_queue_id, FT_RANGE,
	       .u.range = { .lo = 0, .hi = 64 }),
	FIELDX(struct sockaddr_xdp, sxdp_shared_umem_fd, FT_FD),
};
#endif

const struct union_variant sockaddr_storage_variants[] = {
	{
		.discrim_value	 = AF_UNIX,
		.name		 = "AF_UNIX",
		.fields		 = sockaddr_un_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_un_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_un),
	},
	{
		.discrim_value	 = AF_INET,
		.name		 = "AF_INET",
		.fields		 = sockaddr_in_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_in_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_in),
	},
	{
		.discrim_value	 = AF_INET6,
		.name		 = "AF_INET6",
		.fields		 = sockaddr_in6_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_in6_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_in6),
	},
	{
		.discrim_value	 = AF_NETLINK,
		.name		 = "AF_NETLINK",
		.fields		 = sockaddr_nl_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_nl_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_nl),
	},
	{
		.discrim_value	 = AF_PACKET,
		.name		 = "AF_PACKET",
		.fields		 = sockaddr_ll_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_ll_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_ll),
	},
#ifdef USE_VSOCK
	{
		.discrim_value	 = AF_VSOCK,
		.name		 = "AF_VSOCK",
		.fields		 = sockaddr_vm_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_vm_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_vm),
	},
#endif
#ifdef USE_PPPOX
	{
		.discrim_value	 = AF_PPPOX,
		.name		 = "AF_PPPOX",
		.fields		 = sockaddr_pppox_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_pppox_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_pppox),
	},
#endif
#ifdef USE_CAIF
	{
		.discrim_value	 = AF_CAIF,
		.name		 = "AF_CAIF",
		.fields		 = sockaddr_caif_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_caif_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_caif),
	},
#endif
#ifdef USE_CAN
	{
		.discrim_value	 = AF_CAN,
		.name		 = "AF_CAN",
		.fields		 = sockaddr_can_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_can_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_can),
	},
#endif
#ifdef USE_RXRPC
	{
		.discrim_value	 = AF_RXRPC,
		.name		 = "AF_RXRPC",
		.fields		 = sockaddr_rxrpc_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_rxrpc_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_rxrpc),
	},
#endif
#ifdef USE_X25
	{
		.discrim_value	 = AF_X25,
		.name		 = "AF_X25",
		.fields		 = sockaddr_x25_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_x25_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_x25),
	},
#endif
#ifdef USE_PHONET
	{
		.discrim_value	 = AF_PHONET,
		.name		 = "AF_PHONET",
		.fields		 = sockaddr_pn_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_pn_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_pn),
	},
#endif
#ifdef USE_AX25
	{
		.discrim_value	 = AF_AX25,
		.name		 = "AF_AX25",
		.fields		 = sockaddr_ax25_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_ax25_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_ax25),
	},
	{
		.discrim_value	 = AF_NETROM,
		.name		 = "AF_NETROM",
		.fields		 = sockaddr_ax25_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_ax25_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_ax25),
	},
#endif
#ifdef USE_ROSE
	{
		.discrim_value	 = AF_ROSE,
		.name		 = "AF_ROSE",
		.fields		 = sockaddr_rose_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_rose_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_rose),
	},
#endif
#ifdef USE_ATM
	{
		.discrim_value	 = AF_ATMPVC,
		.name		 = "AF_ATMPVC",
		.fields		 = sockaddr_atmpvc_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_atmpvc_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_atmpvc),
	},
#endif
#ifdef USE_LLC
	{
		.discrim_value	 = AF_LLC,
		.name		 = "AF_LLC",
		.fields		 = sockaddr_llc_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_llc_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_llc),
	},
#endif
#ifdef USE_MCTP
	{
		.discrim_value	 = AF_MCTP,
		.name		 = "AF_MCTP",
		.fields		 = sockaddr_mctp_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_mctp_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_mctp),
	},
#endif
#ifdef USE_IF_ALG
	{
		.discrim_value	 = AF_ALG,
		.name		 = "AF_ALG",
		.fields		 = sockaddr_alg_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_alg_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_alg),
	},
#endif
	{
		.discrim_value	 = AF_TIPC,
		.name		 = "AF_TIPC",
		.fields		 = sockaddr_tipc_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_tipc_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_tipc),
		.nested_discrim_offset = offsetof(struct sockaddr_tipc, addrtype),
		.nested_discrim_size   = 1,
		.nested_variants     = sockaddr_tipc_addr_nested,
		.num_nested_variants = ARRAY_SIZE(sockaddr_tipc_addr_nested),
	},
	{
		.discrim_value	 = AF_QIPCRTR,
		.name		 = "AF_QIPCRTR",
		.fields		 = sockaddr_qrtr_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_qrtr_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_qrtr),
	},
	{
		.discrim_value	 = AF_NFC,
		.name		 = "AF_NFC",
		.fields		 = sockaddr_nfc_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_nfc_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_nfc),
	},
#ifdef USE_XDP
	{
		.discrim_value	 = AF_XDP,
		.name		 = "AF_XDP",
		.fields		 = sockaddr_xdp_variant_fields,
		.num_fields	 = ARRAY_SIZE(sockaddr_xdp_variant_fields),
		.effective_size	 = sizeof(struct sockaddr_xdp),
	},
#endif
};

const struct struct_field sockaddr_storage_fields[] = {
	FIELDX(struct sockaddr_storage, ss_family, FT_ENUM,
	       .u.enum_ = { .vals = sockaddr_storage_af_vocab,
			    .n    = ARRAY_SIZE(sockaddr_storage_af_vocab) },
	       .mutate_weight = 200),
};

