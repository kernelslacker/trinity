#include <stdlib.h>
#include "net.h"
#include "compat.h"
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


void bluetooth_setsockopt(struct sockopt *so)
{
	switch(rand() % 5) {
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
