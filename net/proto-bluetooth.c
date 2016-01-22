#include <stdlib.h>
#include "net.h"
#include "compat.h"
#include "random.h"
#include "utils.h"	// RAND_ARRAY

static const unsigned int bluetooth_opts[] = {
	BT_SECURITY, BT_DEFER_SETUP, BT_FLUSHABLE, BT_POWER,
	BT_CHANNEL_POLICY
};

static const unsigned int bluetooth_hci_opts[] = {
	HCI_DATA_DIR, HCI_FILTER, HCI_TIME_STAMP
};

static const unsigned int bluetooth_l2cap_opts[] = {
	L2CAP_OPTIONS, L2CAP_LM
};

static const unsigned int bluetooth_rfcomm_opts[] = { RFCOMM_LM };


static void bluetooth_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_BLUETOOTH;

	switch(rnd() % 5) {
	case 0: so->level = SOL_HCI; break;
	case 1: so->level = SOL_L2CAP; break;
	case 2: so->level = SOL_SCO; break;
	case 3: so->level = SOL_RFCOMM; break;
	case 4: /* leave level unchanged */
		;;
	default:
		break;
	}

	switch (so->level) {
	case SOL_HCI:
		so->optname = RAND_ARRAY(bluetooth_hci_opts);
		break;

	case SOL_L2CAP:
		so->optname = RAND_ARRAY(bluetooth_l2cap_opts);
		break;

	case SOL_SCO:   /* no options currently */
		break;

	case SOL_RFCOMM:
		so->optname = RAND_ARRAY(bluetooth_rfcomm_opts);
		break;

	case SOL_BLUETOOTH:
		so->optname = RAND_ARRAY(bluetooth_opts);
		break;

	default: break;
	}
}

#define BTPROTO_L2CAP   0
#define BTPROTO_HCI     1
#define BTPROTO_SCO     2
#define BTPROTO_RFCOMM  3
#define BTPROTO_BNEP    4
#define BTPROTO_CMTP    5
#define BTPROTO_HIDP    6
#define BTPROTO_AVDTP   7

static void bluetooth_rand_socket(struct socket_triplet *st)
{
	int bt_protos[] = {
		BTPROTO_L2CAP, BTPROTO_HCI, BTPROTO_SCO, BTPROTO_RFCOMM,
		BTPROTO_BNEP, BTPROTO_CMTP, BTPROTO_HIDP, BTPROTO_AVDTP,
	};
	int types[] = { SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET };

	st->protocol = RAND_ARRAY(bt_protos);
	st->type = RAND_ARRAY(types);
}

struct netproto proto_bluetooth = {
	.name = "bluetooth",
	.socket = bluetooth_rand_socket,
	.setsockopt = bluetooth_setsockopt,
};
