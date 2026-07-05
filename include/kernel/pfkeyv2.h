#pragma once

/*
 * Wrapper around <linux/pfkeyv2.h> that ships #ifndef-guarded fallbacks
 * for the PF_KEYv2 UAPI values and structs touched by
 * childops/net/xfrm/pfkey-spd-walk.c.  The real header is pulled in
 * behind __has_include so stripped sysroots that don't ship
 * <linux/pfkeyv2.h> still compile; per-symbol #ifndef fallbacks then
 * supply any missing values, and a shared !__has_include block
 * defines the sadb_msg / sadb_ext / sadb_address / sadb_x_policy
 * layouts (frozen since 2.6.x, RFC 2367 + KAME).
 */
#if __has_include(<linux/pfkeyv2.h>)
#include <linux/pfkeyv2.h>
#endif

#include <stdint.h>

#ifndef AF_KEY
#define AF_KEY				15
#endif
#ifndef PF_KEY
#define PF_KEY				AF_KEY
#endif
#ifndef PF_KEY_V2
#define PF_KEY_V2			2
#endif

/* SADB message types.  Numbering matches Linux's <linux/pfkeyv2.h>
 * (the KAME-derived X_SPD* extensions are stable in the UAPI). */
#ifndef SADB_X_SPDADD
#define SADB_X_SPDADD			14
#endif
#ifndef SADB_X_SPDDELETE
#define SADB_X_SPDDELETE		15
#endif
#ifndef SADB_X_SPDGET
#define SADB_X_SPDGET			16
#endif
#ifndef SADB_X_SPDDUMP
#define SADB_X_SPDDUMP			18
#endif
#ifndef SADB_X_SPDFLUSH
#define SADB_X_SPDFLUSH			19
#endif

#ifndef SADB_SATYPE_UNSPEC
#define SADB_SATYPE_UNSPEC		0
#endif

#ifndef SADB_EXT_ADDRESS_SRC
#define SADB_EXT_ADDRESS_SRC		5
#define SADB_EXT_ADDRESS_DST		6
#endif

#ifndef SADB_X_EXT_POLICY
#define SADB_X_EXT_POLICY		18
#endif

/* IPSEC policy direction + type.  RFC 2367 + KAME.  Linux mirrors
 * IPSEC_DIR_INBOUND=1 / OUTBOUND=2 / FWD=3, and policy types
 * IPSEC_POLICY_DISCARD=0 / NONE=1 / IPSEC=2 / BYPASS=4. */
#ifndef IPSEC_DIR_INBOUND
#define IPSEC_DIR_INBOUND		1
#define IPSEC_DIR_OUTBOUND		2
#define IPSEC_DIR_FWD			3
#endif

#ifndef IPSEC_POLICY_DISCARD
#define IPSEC_POLICY_DISCARD		0
#define IPSEC_POLICY_NONE		1
#define IPSEC_POLICY_IPSEC		2
#define IPSEC_POLICY_BYPASS		4
#endif

/* Fallback layouts.  Pulled in only when <linux/pfkeyv2.h> is absent
 * on the build sysroot.  Field names/sizes match the kernel UAPI
 * (frozen since 2.6.x); xfrm-churn-internal.h uses an equivalent
 * sadb_msg fallback under the same gate. */
#if !__has_include(<linux/pfkeyv2.h>)
struct sadb_msg {
	uint8_t		sadb_msg_version;
	uint8_t		sadb_msg_type;
	uint8_t		sadb_msg_errno;
	uint8_t		sadb_msg_satype;
	uint16_t	sadb_msg_len;
	uint16_t	sadb_msg_reserved;
	uint32_t	sadb_msg_seq;
	uint32_t	sadb_msg_pid;
};

struct sadb_ext {
	uint16_t	sadb_ext_len;
	uint16_t	sadb_ext_type;
};

struct sadb_address {
	uint16_t	sadb_address_len;
	uint16_t	sadb_address_exttype;
	uint8_t		sadb_address_proto;
	uint8_t		sadb_address_prefixlen;
	uint16_t	sadb_address_reserved;
};

struct sadb_x_policy {
	uint16_t	sadb_x_policy_len;
	uint16_t	sadb_x_policy_exttype;
	uint16_t	sadb_x_policy_type;
	uint8_t		sadb_x_policy_dir;
	uint8_t		sadb_x_policy_reserved;
	uint32_t	sadb_x_policy_id;
	uint32_t	sadb_x_policy_priority;
};
#endif /* !__has_include(<linux/pfkeyv2.h>) */
