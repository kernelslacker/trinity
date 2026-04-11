#include <stdlib.h>
#include <string.h>
#include <linux/cdrom.h>

#include "ioctls.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static const struct ioctl cdrom_ioctls[] = {
	IOCTL(CDROMPAUSE),
	IOCTL(CDROMRESUME),
	IOCTL(CDROMPLAYMSF),
	IOCTL(CDROMPLAYTRKIND),
	IOCTL(CDROMREADTOCHDR),
	IOCTL(CDROMREADTOCENTRY),
	IOCTL(CDROMSTOP),
	IOCTL(CDROMSTART),
	IOCTL(CDROMEJECT),
	IOCTL(CDROMVOLCTRL),
	IOCTL(CDROMSUBCHNL),
	IOCTL(CDROMREADMODE2),
	IOCTL(CDROMREADMODE1),
	IOCTL(CDROMREADAUDIO),
	IOCTL(CDROMEJECT_SW),
	IOCTL(CDROMMULTISESSION),
	IOCTL(CDROM_GET_MCN),
	IOCTL(CDROMRESET),
	IOCTL(CDROMVOLREAD),
	IOCTL(CDROMREADRAW),
	IOCTL(CDROMREADCOOKED),
	IOCTL(CDROMSEEK),
	IOCTL(CDROMPLAYBLK),
	IOCTL(CDROMREADALL),
	IOCTL(CDROMGETSPINDOWN),
	IOCTL(CDROMSETSPINDOWN),
	IOCTL(CDROMCLOSETRAY),
	IOCTL(CDROM_SET_OPTIONS),
	IOCTL(CDROM_CLEAR_OPTIONS),
	IOCTL(CDROM_SELECT_SPEED),
	IOCTL(CDROM_SELECT_DISC),
	IOCTL(CDROM_MEDIA_CHANGED),
	IOCTL(CDROM_DRIVE_STATUS),
	IOCTL(CDROM_DISC_STATUS),
	IOCTL(CDROM_CHANGER_NSLOTS),
	IOCTL(CDROM_LOCKDOOR),
	IOCTL(CDROM_DEBUG),
	IOCTL(CDROM_GET_CAPABILITY),
	IOCTL(CDROMAUDIOBUFSIZ),
	IOCTL(DVD_READ_STRUCT),
	IOCTL(DVD_WRITE_STRUCT),
	IOCTL(DVD_AUTH),
	IOCTL(CDROM_SEND_PACKET),
	IOCTL(CDROM_NEXT_WRITABLE),
	IOCTL(CDROM_LAST_WRITTEN),
};

static const char *const cdrom_devs[] = {
	"sr",
};

/* Safe SCSI opcodes for CDROM_SEND_PACKET. */
static const unsigned char cdrom_scsi_opcodes[] = {
	0x00,	/* TEST_UNIT_READY */
	0x03,	/* REQUEST_SENSE */
	0x12,	/* INQUIRY */
	0x43,	/* READ_TOC */
	0x5A,	/* MODE_SENSE */
};

static void cdrom_send_packet_sanitise(struct syscallrecord *rec)
{
	struct cdrom_generic_command *cgc;
	unsigned int i;

	cgc = (struct cdrom_generic_command *) get_writable_address(sizeof(*cgc));

	cgc->cmd[0] = cdrom_scsi_opcodes[rand() % ARRAY_SIZE(cdrom_scsi_opcodes)];
	for (i = 1; i < CDROM_PACKET_SIZE; i++)
		cgc->cmd[i] = (unsigned char) rand();

	cgc->buffer = (unsigned char *) get_writable_address(4096);
	cgc->buflen = 4096;
	cgc->sense = (struct request_sense *) get_writable_address(sizeof(struct request_sense));

	switch (rand() % 3) {
	case 0:	cgc->data_direction = CGC_DATA_READ;	break;
	case 1:	cgc->data_direction = CGC_DATA_WRITE;	break;
	case 2:	cgc->data_direction = CGC_DATA_NONE;	break;
	default: break;
	}

	cgc->timeout = 1000;

	rec->a3 = (unsigned long) cgc;
}

static void cdrom_dvd_auth_sanitise(struct syscallrecord *rec)
{
	static const __u8 auth_types[] = {
		DVD_LU_SEND_AGID,
		DVD_HOST_SEND_CHALLENGE,
		DVD_LU_SEND_KEY1,
		DVD_LU_SEND_CHALLENGE,
		DVD_HOST_SEND_KEY2,
		DVD_LU_SEND_TITLE_KEY,
		DVD_LU_SEND_ASF,
		DVD_INVALIDATE_AGID,
		DVD_LU_SEND_RPC_STATE,
		DVD_HOST_SEND_RPC_STATE,
	};
	dvd_authinfo *dai;

	dai = (dvd_authinfo *) get_writable_address(sizeof(*dai));
	memset(dai, 0, sizeof(*dai));
	dai->type = auth_types[rand() % ARRAY_SIZE(auth_types)];

	rec->a3 = (unsigned long) dai;
}

static void cdrom_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case CDROM_SEND_PACKET:
		cdrom_send_packet_sanitise(rec);
		break;
	case DVD_AUTH:
		cdrom_dvd_auth_sanitise(rec);
		break;
	case CDROMAUDIOBUFSIZ:
		rec->a3 = rand();
		break;
	case CDROM_SELECT_SPEED:
		rec->a3 = rand() % 56;
		break;
	case CDROM_SELECT_DISC:
		rec->a3 = rand() % 16;
		break;
	default:
		break;
	}
}

static const struct ioctl_group cdrom_grp = {
	.devtype = DEV_BLOCK,
	.devs = cdrom_devs,
	.devs_cnt = ARRAY_SIZE(cdrom_devs),
	.sanitise = cdrom_sanitise,
	.ioctls = cdrom_ioctls,
	.ioctls_cnt = ARRAY_SIZE(cdrom_ioctls),
};

REG_IOCTL_GROUP(cdrom_grp)
