#pragma once

#if __has_include(<bluetooth/bluetooth.h>)
#include <bluetooth/bluetooth.h>
#endif
#if __has_include(<bluetooth/hci.h>)
#include <bluetooth/hci.h>
#endif
#if __has_include(<bluetooth/l2cap.h>)
#include <bluetooth/l2cap.h>
#endif
#if __has_include(<bluetooth/rfcomm.h>)
#include <bluetooth/rfcomm.h>
#endif

#ifndef BT_SECURITY
#define BT_SECURITY	4
#define BT_SECURITY_SDP		0
#define BT_SECURITY_LOW		1
#define BT_SECURITY_MEDIUM	2
#define BT_SECURITY_HIGH	3
#endif

#ifndef BT_DEFER_SETUP
#define BT_DEFER_SETUP	7
#endif
#ifndef BT_FLUSHABLE
#define BT_FLUSHABLE	8
#endif
#ifndef BT_POWER
#define BT_POWER	9
#endif
#ifndef BT_CHANNEL_POLICY
#define BT_CHANNEL_POLICY	10
#endif
#ifndef BT_SNDMTU
#define BT_SNDMTU	12
#endif
#ifndef BT_RCVMTU
#define BT_RCVMTU	13
#endif
#ifndef BT_PHY
#define BT_PHY	14
#endif
#ifndef BT_MODE
#define BT_MODE	15
#endif
#ifndef BT_SUBRATE
#define BT_SUBRATE	16
#endif

#ifndef SOL_BLUETOOTH
#define SOL_BLUETOOTH	274
#define SOL_HCI		273
#define SOL_L2CAP	6
#define SOL_SCO		17
#define SOL_RFCOMM	18
#endif

#ifndef HCI_DATA_DIR
#define HCI_DATA_DIR	1
#define HCI_FILTER	2
#endif
#ifndef HCI_TIME_STAMP
#define HCI_TIME_STAMP	3
#endif

#ifndef L2CAP_OPTIONS
#define L2CAP_OPTIONS	0x01
#endif
#ifndef L2CAP_LM
#define L2CAP_LM		0x03
#define L2CAP_LM_MASTER		0x0001
#define L2CAP_LM_AUTH		0x0002
#define L2CAP_LM_ENCRYPT	0x0004
#define L2CAP_LM_TRUSTED	0x0008
#define L2CAP_LM_RELIABLE	0x0010
#define L2CAP_LM_SECURE		0x0020
#endif

#ifndef RFCOMM_LM
#define RFCOMM_LM		0x03
#endif
#ifndef RFCOMM_LM_AUTH
#define RFCOMM_LM_AUTH		0x0002
#define RFCOMM_LM_ENCRYPT	0x0004
#define RFCOMM_LM_TRUSTED	0x0008
#define RFCOMM_LM_MASTER	0x0001
#define RFCOMM_LM_RELIABLE	0x0010
#define RFCOMM_LM_SECURE	0x0020
#endif
