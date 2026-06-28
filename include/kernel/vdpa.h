#pragma once

/*
 * Wrapper around <linux/vdpa.h> that ships the #ifndef-guarded
 * fallbacks for VDPA_CMD_* / VDPA_ATTR_* ids and the VDPA_GENL_NAME /
 * VDPA_GENL_VERSION constants.  The .c side includes this from inside
 * its `#if __has_include(<linux/vdpa.h>)` gate, so the header itself
 * can include <linux/vdpa.h> unconditionally.
 */
#include <linux/vdpa.h>

/*
 * Per-symbol shims for VDPA_CMD_* / VDPA_ATTR_* ids.  Build hosts whose
 * <linux/vdpa.h> predates a given attribute (the VENDOR_ATTR_NAME /
 * VENDOR_ATTR_VALUE / QUEUE_INDEX additions, the MGMTDEV_MAX_VQS /
 * SUPPORTED_FEATURES additions) silently miss it from the validator
 * coverage; the fallback values match the upstream uapi enum ordering
 * so the wire-format ids the kernel parses match the ones the
 * generator emits.
 */
#ifndef VDPA_GENL_NAME
#define VDPA_GENL_NAME			"vdpa"
#endif
#ifndef VDPA_GENL_VERSION
#define VDPA_GENL_VERSION		0x1
#endif

#ifndef VDPA_CMD_MGMTDEV_NEW
#define VDPA_CMD_MGMTDEV_NEW		1
#endif
#ifndef VDPA_CMD_MGMTDEV_GET
#define VDPA_CMD_MGMTDEV_GET		2
#endif
#ifndef VDPA_CMD_DEV_NEW
#define VDPA_CMD_DEV_NEW		3
#endif
#ifndef VDPA_CMD_DEV_DEL
#define VDPA_CMD_DEV_DEL		4
#endif
#ifndef VDPA_CMD_DEV_GET
#define VDPA_CMD_DEV_GET		5
#endif
#ifndef VDPA_CMD_DEV_CONFIG_GET
#define VDPA_CMD_DEV_CONFIG_GET		6
#endif
#ifndef VDPA_CMD_DEV_VSTATS_GET
#define VDPA_CMD_DEV_VSTATS_GET		7
#endif
#ifndef VDPA_CMD_DEV_ATTR_SET
#define VDPA_CMD_DEV_ATTR_SET		8
#endif

#ifndef VDPA_ATTR_MGMTDEV_BUS_NAME
#define VDPA_ATTR_MGMTDEV_BUS_NAME		1
#endif
#ifndef VDPA_ATTR_MGMTDEV_DEV_NAME
#define VDPA_ATTR_MGMTDEV_DEV_NAME		2
#endif
#ifndef VDPA_ATTR_MGMTDEV_SUPPORTED_CLASSES
#define VDPA_ATTR_MGMTDEV_SUPPORTED_CLASSES	3
#endif
#ifndef VDPA_ATTR_DEV_NAME
#define VDPA_ATTR_DEV_NAME			4
#endif
#ifndef VDPA_ATTR_DEV_ID
#define VDPA_ATTR_DEV_ID			5
#endif
#ifndef VDPA_ATTR_DEV_VENDOR_ID
#define VDPA_ATTR_DEV_VENDOR_ID			6
#endif
#ifndef VDPA_ATTR_DEV_MAX_VQS
#define VDPA_ATTR_DEV_MAX_VQS			7
#endif
#ifndef VDPA_ATTR_DEV_MAX_VQ_SIZE
#define VDPA_ATTR_DEV_MAX_VQ_SIZE		8
#endif
#ifndef VDPA_ATTR_DEV_MIN_VQ_SIZE
#define VDPA_ATTR_DEV_MIN_VQ_SIZE		9
#endif
#ifndef VDPA_ATTR_DEV_NET_CFG_MACADDR
#define VDPA_ATTR_DEV_NET_CFG_MACADDR		10
#endif
#ifndef VDPA_ATTR_DEV_NET_STATUS
#define VDPA_ATTR_DEV_NET_STATUS		11
#endif
#ifndef VDPA_ATTR_DEV_NET_CFG_MAX_VQP
#define VDPA_ATTR_DEV_NET_CFG_MAX_VQP		12
#endif
#ifndef VDPA_ATTR_DEV_NET_CFG_MTU
#define VDPA_ATTR_DEV_NET_CFG_MTU		13
#endif
#ifndef VDPA_ATTR_DEV_NEGOTIATED_FEATURES
#define VDPA_ATTR_DEV_NEGOTIATED_FEATURES	14
#endif
#ifndef VDPA_ATTR_DEV_MGMTDEV_MAX_VQS
#define VDPA_ATTR_DEV_MGMTDEV_MAX_VQS		15
#endif
#ifndef VDPA_ATTR_DEV_SUPPORTED_FEATURES
#define VDPA_ATTR_DEV_SUPPORTED_FEATURES	16
#endif
#ifndef VDPA_ATTR_DEV_QUEUE_INDEX
#define VDPA_ATTR_DEV_QUEUE_INDEX		17
#endif
#ifndef VDPA_ATTR_DEV_VENDOR_ATTR_NAME
#define VDPA_ATTR_DEV_VENDOR_ATTR_NAME		18
#endif
#ifndef VDPA_ATTR_DEV_VENDOR_ATTR_VALUE
#define VDPA_ATTR_DEV_VENDOR_ATTR_VALUE		19
#endif
