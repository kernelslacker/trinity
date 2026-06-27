#pragma once
#include <linux/if_macsec.h>

/* linux/if_macsec.h
 *
 * The original 4.6 MACsec merge shipped MACSEC_ATTR_* through SECY_STATS,
 * MACSEC_CMD_* through UPD_RXSA, and the macsec_sa_attrs enum through
 * SA_ATTR_PAD.  The XPN (Extended Packet Number) and hardware-offload
 * extensions landed together in 5.7 (commits 48ef50fa866a / 3cf3227a21d1):
 * MACSEC_CMD_UPD_OFFLOAD, MACSEC_ATTR_OFFLOAD, the entire
 * macsec_offload_attrs enum, and the per-SA SSCI / SALT pair plus
 * MACSEC_SALT_LEN.  The walker references each constant unconditionally;
 * compat fallbacks below carry whatever the host header doesn't ship,
 * matching the upstream uapi enum values exactly.
 *
 * MACSEC_ATTR_* / MACSEC_CMD_* / MACSEC_SA_ATTR_* / MACSEC_OFFLOAD_ATTR_*
 * are enum members, not preprocessor macros, so the #ifndef guards
 * always fire.  This header pulls <linux/if_macsec.h> first so the
 * canonical enum bodies are parsed before the fallback macros become
 * live, regardless of the consumer's include order.
 */
#ifndef MACSEC_ATTR_OFFLOAD
/* MACSEC_ATTR_OFFLOAD appended to enum macsec_attrs in 5.7; the original
 * 4.6 enum stopped at MACSEC_ATTR_SECY_STATS = 8. */
#define MACSEC_ATTR_OFFLOAD		9
#endif
#ifndef MACSEC_CMD_UPD_OFFLOAD
/* MACSEC_CMD_UPD_OFFLOAD appended to enum macsec_nl_commands in 5.7; the
 * original 4.6 enum stopped at MACSEC_CMD_UPD_RXSA = 10. */
#define MACSEC_CMD_UPD_OFFLOAD		11
#endif
#ifndef MACSEC_SA_ATTR_SSCI
/* SSCI / SALT appended to enum macsec_sa_attrs in 5.7 to carry the XPN
 * (Extended Packet Number) short SCI and 96-bit salt; the original 4.6
 * inner enum stopped at MACSEC_SA_ATTR_PAD = 7. */
#define MACSEC_SA_ATTR_SSCI		8
#endif
#ifndef MACSEC_SA_ATTR_SALT
#define MACSEC_SA_ATTR_SALT		9
#endif
#ifndef MACSEC_SALT_LEN
/* GCM-AES-XPN salt length per IEEE802.1AEbw-2013; 96 bits = 12 bytes. */
#define MACSEC_SALT_LEN			12
#endif
#ifndef MACSEC_OFFLOAD_ATTR_TYPE
/* The entire enum macsec_offload_attrs landed in 5.7; the policy
 * validates only TYPE (PAD is response-side padding). */
#define MACSEC_OFFLOAD_ATTR_TYPE	1
#endif
