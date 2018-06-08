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

#define SOL_BLUETOOTH 274

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

static struct socket_triplet bluetooth_triplets[] = {
	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_L2CAP, .type = SOCK_SEQPACKET },
	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_SCO, .type = SOCK_SEQPACKET },

	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_L2CAP, .type = SOCK_STREAM },
	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_RFCOMM, .type = SOCK_STREAM },

	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_L2CAP, .type = SOCK_RAW },
	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_HCI, .type = SOCK_RAW },
	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_RFCOMM, .type = SOCK_RAW },
	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_BNEP, .type = SOCK_RAW },
	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_CMTP, .type = SOCK_RAW },
	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_HIDP, .type = SOCK_RAW },
	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_AVDTP, .type = SOCK_RAW },

	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_L2CAP, .type = SOCK_DGRAM },
};

const struct netproto proto_bluetooth = {
	.name = "bluetooth",
	.setsockopt = bluetooth_setsockopt,
	.valid_triplets = bluetooth_triplets,
	.nr_triplets = ARRAY_SIZE(bluetooth_triplets),
};
