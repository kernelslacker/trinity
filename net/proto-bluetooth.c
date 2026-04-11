#include <stdlib.h>
#include <string.h>
#include "net.h"
#include "compat.h"
#include "random.h"

/* Bluetooth address — 6 bytes, little-endian */
typedef struct {
	unsigned char b[6];
} bdaddr_t;

/* HCI socket address */
struct sockaddr_hci {
	sa_family_t	hci_family;
	unsigned short	hci_dev;
	unsigned short	hci_channel;
};

#ifndef HCI_CHANNEL_RAW
#define HCI_CHANNEL_RAW		0
#define HCI_CHANNEL_USER	1
#define HCI_CHANNEL_MONITOR	2
#define HCI_CHANNEL_CONTROL	3
#define HCI_CHANNEL_LOGGING	4
#endif

/* L2CAP socket address */
struct sockaddr_l2 {
	sa_family_t	l2_family;
	unsigned short	l2_psm;
	bdaddr_t	l2_bdaddr;
	unsigned short	l2_cid;
	unsigned char	l2_bdaddr_type;
};

/* RFCOMM socket address */
struct sockaddr_rc {
	sa_family_t	rc_family;
	bdaddr_t	rc_bdaddr;
	unsigned char	rc_channel;
};

/* SCO socket address */
struct sockaddr_sco {
	sa_family_t	sco_family;
	bdaddr_t	sco_bdaddr;
};

/* ISO socket address (unicast — no broadcast extension) */
struct sockaddr_iso {
	sa_family_t	iso_family;
	bdaddr_t	iso_bdaddr;
	__u8		iso_bdaddr_type;
};

static void bluetooth_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	switch (rand() % 5) {
	case 0: {
		/* HCI — raw access to Bluetooth controller */
		struct sockaddr_hci *hci;

		hci = zmalloc(sizeof(struct sockaddr_hci));
		hci->hci_family = PF_BLUETOOTH;
		hci->hci_dev = rand() % 4;
		hci->hci_channel = rand() % 5;	/* RAW..LOGGING */
		*addr = (struct sockaddr *) hci;
		*addrlen = sizeof(struct sockaddr_hci);
		break;
	}

	case 1: {
		/* L2CAP — logical link control */
		struct sockaddr_l2 *l2;

		l2 = zmalloc(sizeof(struct sockaddr_l2));
		l2->l2_family = PF_BLUETOOTH;
		l2->l2_psm = rand() % 2 ? 1 : rand();	/* 1=SDP */
		generate_rand_bytes(l2->l2_bdaddr.b, 6);
		l2->l2_cid = rand();
		l2->l2_bdaddr_type = rand() % 3;	/* BR/EDR, LE public, LE random */
		*addr = (struct sockaddr *) l2;
		*addrlen = sizeof(struct sockaddr_l2);
		break;
	}

	case 2: {
		/* RFCOMM — serial port emulation */
		struct sockaddr_rc *rc;

		rc = zmalloc(sizeof(struct sockaddr_rc));
		rc->rc_family = PF_BLUETOOTH;
		generate_rand_bytes(rc->rc_bdaddr.b, 6);
		rc->rc_channel = rand() % 31 + 1;	/* 1-30 valid */
		*addr = (struct sockaddr *) rc;
		*addrlen = sizeof(struct sockaddr_rc);
		break;
	}

	case 3: {
		/* SCO — synchronous connection oriented (voice) */
		struct sockaddr_sco *sco;

		sco = zmalloc(sizeof(struct sockaddr_sco));
		sco->sco_family = PF_BLUETOOTH;
		generate_rand_bytes(sco->sco_bdaddr.b, 6);
		*addr = (struct sockaddr *) sco;
		*addrlen = sizeof(struct sockaddr_sco);
		break;
	}

	case 4: {
		/* ISO — LE Audio (unicast, no broadcast extension) */
		struct sockaddr_iso *iso;

		iso = zmalloc(sizeof(struct sockaddr_iso));
		iso->iso_family = AF_BLUETOOTH;
		generate_rand_bytes(iso->iso_bdaddr.b, 6);
		iso->iso_bdaddr_type = rand() % 3;
		*addr = (struct sockaddr *) iso;
		*addrlen = sizeof(struct sockaddr_iso);
		break;
	}
	}
}

#ifndef BT_VOICE
#define BT_VOICE	11
#endif
#ifndef BT_SNDMTU
#define BT_SNDMTU	12
#endif
#ifndef BT_RCVMTU
#define BT_RCVMTU	13
#endif
#ifndef BT_PHY
#define BT_PHY		14
#endif
#ifndef BT_MODE
#define BT_MODE		15
#endif
#ifndef BT_ISO_QOS
#define BT_ISO_QOS	17
#endif

static const unsigned int bluetooth_opts[] = {
	BT_SECURITY, BT_DEFER_SETUP, BT_FLUSHABLE, BT_POWER,
	BT_CHANNEL_POLICY, BT_VOICE, BT_SNDMTU, BT_RCVMTU,
	BT_PHY, BT_MODE, BT_ISO_QOS
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

#define BTPROTO_L2CAP   0
#define BTPROTO_HCI     1
#define BTPROTO_SCO     2
#define BTPROTO_RFCOMM  3
#define BTPROTO_BNEP    4
#define BTPROTO_CMTP    5
#define BTPROTO_HIDP    6
#define BTPROTO_AVDTP   7
#ifndef BTPROTO_ISO
#define BTPROTO_ISO     8
#endif

static struct socket_triplet bluetooth_triplets[] = {
	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_L2CAP, .type = SOCK_SEQPACKET },
	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_SCO, .type = SOCK_SEQPACKET },
	{ .family = PF_BLUETOOTH, .protocol = BTPROTO_ISO, .type = SOCK_SEQPACKET },

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
	.gen_sockaddr = bluetooth_gen_sockaddr,
	.setsockopt = bluetooth_setsockopt,
	.valid_triplets = bluetooth_triplets,
	.nr_triplets = ARRAY_SIZE(bluetooth_triplets),
};
