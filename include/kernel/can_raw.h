#pragma once

/*
 * CAN_RAW_XL_VCID_OPTS is an enum member of <linux/can/raw.h>, so configure
 * compile-tests it and emits HAVE_CAN_RAW_XL_VCID_OPTS; the fallback, with
 * the struct that arrived beside it (6.9), exists only where the header
 * lacks the member.
 */
#include <linux/types.h>
#include <linux/can/raw.h>

#ifndef HAVE_CAN_RAW_XL_VCID_OPTS
#define CAN_RAW_XL_VCID_OPTS	8
struct can_raw_vcid_options {
	__u8 flags;
	__u8 tx_vcid;
	__u8 rx_vcid;
	__u8 rx_vcid_mask;
};
#endif

#ifndef CAN_RAW_XL_VCID_TX_SET
#define CAN_RAW_XL_VCID_TX_SET		0x01
#endif
#ifndef CAN_RAW_XL_VCID_TX_PASS
#define CAN_RAW_XL_VCID_TX_PASS		0x02
#endif
#ifndef CAN_RAW_XL_VCID_RX_FILTER
#define CAN_RAW_XL_VCID_RX_FILTER	0x04
#endif
