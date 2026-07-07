#pragma once
#include <linux/nfc.h>

/* existing NFC_ATTR fallbacks */
#ifndef NFC_ATTR_TARGET_ATS
#define NFC_ATTR_TARGET_ATS	32
#endif
#ifndef NFC_ATS_MAXSIZE
#define NFC_ATS_MAXSIZE		20
#endif

/* sockaddr_nfc and protocol fallbacks moved from compat.h */
#if __has_include(<linux/nfc.h>)
/* already included */
#else
#include <linux/socket.h>
#include "kernel/nfc.h"
struct sockaddr_nfc {
    __kernel_sa_family_t sa_family;
    __u32 dev_idx;
    __u32 target_idx;
    __u32 nfc_protocol;
};
#endif
#ifndef NFC_PROTO_JEWEL
#define NFC_PROTO_JEWEL			1
#endif
#ifndef NFC_PROTO_MIFARE
#define NFC_PROTO_MIFARE		2
#endif
#ifndef NFC_PROTO_FELICA
#define NFC_PROTO_FELICA		3
#endif
#ifndef NFC_PROTO_ISO14443
#define NFC_PROTO_ISO14443		4
#endif
#ifndef NFC_PROTO_NFC_DEP
#define NFC_PROTO_NFC_DEP		5
#endif
#ifndef NFC_PROTO_ISO14443_B
#define NFC_PROTO_ISO14443_B		6
#endif
#ifndef NFC_PROTO_ISO15693
#define NFC_PROTO_ISO15693		7
#endif
#ifndef NFC_SOCKPROTO_RAW
#define NFC_SOCKPROTO_RAW	0
#endif
#ifndef NFC_SOCKPROTO_LLCP
#define NFC_SOCKPROTO_LLCP	1
#endif
