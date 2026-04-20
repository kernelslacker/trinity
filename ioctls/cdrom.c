#include <limits.h>
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
	IOCTL(CDROM_TIMED_MEDIA_CHANGE),
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

	cgc = (struct cdrom_generic_command *) get_writable_struct(sizeof(*cgc));
	if (!cgc)
		return;

	cgc->cmd[0] = cdrom_scsi_opcodes[rand() % ARRAY_SIZE(cdrom_scsi_opcodes)];
	for (i = 1; i < CDROM_PACKET_SIZE; i++)
		cgc->cmd[i] = (unsigned char) rand();

	{
		static const unsigned int buflens[] = {
			0, 1, 4096, 4097, 65535, (unsigned int) INT_MAX,
		};
		cgc->buflen = buflens[rand() % ARRAY_SIZE(buflens)];
		cgc->buffer = (unsigned char *) get_writable_struct(65536);
	}
	cgc->sense = (struct request_sense *) get_writable_struct(sizeof(struct request_sense));

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

	dai = (dvd_authinfo *) get_writable_struct(sizeof(*dai));
	if (!dai)
		return;
	memset(dai, 0, sizeof(*dai));
	dai->type = auth_types[rand() % ARRAY_SIZE(auth_types)];

	rec->a3 = (unsigned long) dai;
}

static void sanitise_cdrom_playmsf(struct syscallrecord *rec)
{
	struct cdrom_msf *msf;

	msf = (struct cdrom_msf *) get_writable_struct(sizeof(*msf));
	if (!msf)
		return;
	msf->cdmsf_min0   = rand() % 80;
	msf->cdmsf_sec0   = rand() % 60;
	msf->cdmsf_frame0 = rand() % 75;
	msf->cdmsf_min1   = rand() % 80;
	msf->cdmsf_sec1   = rand() % 60;
	msf->cdmsf_frame1 = rand() % 75;
	rec->a3 = (unsigned long) msf;
}

static void sanitise_cdrom_playtrkind(struct syscallrecord *rec)
{
	struct cdrom_ti *ti;

	ti = (struct cdrom_ti *) get_writable_struct(sizeof(*ti));
	if (!ti)
		return;
	ti->cdti_trk0 = 1 + rand() % 99;
	ti->cdti_ind0 = 1 + rand() % 99;
	ti->cdti_trk1 = 1 + rand() % 99;
	ti->cdti_ind1 = 1 + rand() % 99;
	rec->a3 = (unsigned long) ti;
}

static void sanitise_cdrom_readtochdr(struct syscallrecord *rec)
{
	struct cdrom_tochdr *hdr;

	hdr = (struct cdrom_tochdr *) get_writable_struct(sizeof(*hdr));
	if (!hdr)
		return;
	memset(hdr, 0, sizeof(*hdr));
	rec->a3 = (unsigned long) hdr;
}

static void sanitise_cdrom_readtocentry(struct syscallrecord *rec)
{
	struct cdrom_tocentry *te;

	te = (struct cdrom_tocentry *) get_writable_struct(sizeof(*te));
	if (!te)
		return;
	memset(te, 0, sizeof(*te));
	te->cdte_track  = RAND_BOOL() ? CDROM_LEADOUT : (1 + rand() % 99);
	te->cdte_format = RAND_BOOL() ? CDROM_MSF : CDROM_LBA;
	rec->a3 = (unsigned long) te;
}

static void sanitise_cdrom_volctrl(struct syscallrecord *rec)
{
	struct cdrom_volctrl *vc;

	vc = (struct cdrom_volctrl *) get_writable_struct(sizeof(*vc));
	if (!vc)
		return;
	vc->channel0 = rand() % 256;
	vc->channel1 = rand() % 256;
	vc->channel2 = rand() % 256;
	vc->channel3 = rand() % 256;
	rec->a3 = (unsigned long) vc;
}

static void sanitise_cdrom_volread(struct syscallrecord *rec)
{
	struct cdrom_volctrl *vc;

	vc = (struct cdrom_volctrl *) get_writable_struct(sizeof(*vc));
	if (!vc)
		return;
	memset(vc, 0, sizeof(*vc));
	rec->a3 = (unsigned long) vc;
}

static void sanitise_cdrom_subchnl(struct syscallrecord *rec)
{
	struct cdrom_subchnl *sc;

	sc = (struct cdrom_subchnl *) get_writable_struct(sizeof(*sc));
	if (!sc)
		return;
	memset(sc, 0, sizeof(*sc));
	sc->cdsc_format = RAND_BOOL() ? CDROM_MSF : CDROM_LBA;
	rec->a3 = (unsigned long) sc;
}

static void sanitise_cdrom_read(struct syscallrecord *rec, int bufsz)
{
	struct cdrom_read *cr;

	cr = (struct cdrom_read *) get_writable_struct(sizeof(*cr));
	if (!cr)
		return;
	cr->cdread_lba     = rand();
	cr->cdread_bufaddr = (char *) get_writable_struct(bufsz);
	cr->cdread_buflen  = bufsz;
	rec->a3 = (unsigned long) cr;
}

static void sanitise_cdrom_readaudio(struct syscallrecord *rec)
{
	struct cdrom_read_audio *ra;

	ra = (struct cdrom_read_audio *) get_writable_struct(sizeof(*ra));
	if (!ra)
		return;
	memset(ra, 0, sizeof(*ra));
	ra->addr_format = RAND_BOOL() ? CDROM_MSF : CDROM_LBA;
	if (ra->addr_format == CDROM_MSF) {
		ra->addr.msf.minute = rand() % 80;
		ra->addr.msf.second = rand() % 60;
		ra->addr.msf.frame  = rand() % 75;
	} else {
		ra->addr.lba = rand();
	}
	ra->nframes = 1 + rand() % 8;
	ra->buf = (unsigned char *) get_writable_struct(ra->nframes * 2352);
	rec->a3 = (unsigned long) ra;
}

static void sanitise_cdrom_seek(struct syscallrecord *rec)
{
	struct cdrom_msf *msf;

	msf = (struct cdrom_msf *) get_writable_struct(sizeof(*msf));
	if (!msf)
		return;
	msf->cdmsf_min0   = rand() % 80;
	msf->cdmsf_sec0   = rand() % 60;
	msf->cdmsf_frame0 = rand() % 75;
	msf->cdmsf_min1   = 0;
	msf->cdmsf_sec1   = 0;
	msf->cdmsf_frame1 = 0;
	rec->a3 = (unsigned long) msf;
}

static void sanitise_cdrom_playblk(struct syscallrecord *rec)
{
	struct cdrom_blk *blk;

	blk = (struct cdrom_blk *) get_writable_struct(sizeof(*blk));
	if (!blk)
		return;
	blk->from = rand();
	blk->len  = rand() % 64;
	rec->a3 = (unsigned long) blk;
}

static void sanitise_cdrom_multisession(struct syscallrecord *rec)
{
	struct cdrom_multisession *ms;

	ms = (struct cdrom_multisession *) get_writable_struct(sizeof(*ms));
	if (!ms)
		return;
	memset(ms, 0, sizeof(*ms));
	ms->addr_format = RAND_BOOL() ? CDROM_MSF : CDROM_LBA;
	rec->a3 = (unsigned long) ms;
}

static void sanitise_cdrom_get_mcn(struct syscallrecord *rec)
{
	struct cdrom_mcn *mcn;

	mcn = (struct cdrom_mcn *) get_writable_struct(sizeof(*mcn));
	if (!mcn)
		return;
	memset(mcn, 0, sizeof(*mcn));
	rec->a3 = (unsigned long) mcn;
}

static void sanitise_dvd_struct(struct syscallrecord *rec)
{
	static const __u8 dvd_types[] = {
		DVD_STRUCT_PHYSICAL,
		DVD_STRUCT_COPYRIGHT,
		DVD_STRUCT_DISCKEY,
		DVD_STRUCT_BCA,
		DVD_STRUCT_MANUFACT,
	};
	dvd_struct *ds;

	ds = (dvd_struct *) get_writable_struct(sizeof(*ds));
	if (!ds)
		return;
	memset(ds, 0, sizeof(*ds));
	ds->type = dvd_types[rand() % ARRAY_SIZE(dvd_types)];
	rec->a3 = (unsigned long) ds;
}

static void sanitise_cdrom_timed_media_change(struct syscallrecord *rec)
{
	struct cdrom_timed_media_change_info *info;

	info = (struct cdrom_timed_media_change_info *) get_writable_struct(sizeof(*info));
	if (!info)
		return;
	memset(info, 0, sizeof(*info));
	rec->a3 = (unsigned long) info;
}

static void sanitise_cdrom_long_out(struct syscallrecord *rec)
{
	long *val;

	val = (long *) get_writable_struct(sizeof(*val));
	if (!val)
		return;
	*val = 0;
	rec->a3 = (unsigned long) val;
}

static void cdrom_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case CDROMPLAYMSF:
		sanitise_cdrom_playmsf(rec);
		break;
	case CDROMPLAYTRKIND:
		sanitise_cdrom_playtrkind(rec);
		break;
	case CDROMREADTOCHDR:
		sanitise_cdrom_readtochdr(rec);
		break;
	case CDROMREADTOCENTRY:
		sanitise_cdrom_readtocentry(rec);
		break;
	case CDROMVOLCTRL:
		sanitise_cdrom_volctrl(rec);
		break;
	case CDROMVOLREAD:
		sanitise_cdrom_volread(rec);
		break;
	case CDROMSUBCHNL:
		sanitise_cdrom_subchnl(rec);
		break;
	case CDROMREADMODE1:
	case CDROMREADCOOKED:
		sanitise_cdrom_read(rec, 2048);
		break;
	case CDROMREADMODE2:
		sanitise_cdrom_read(rec, 2336);
		break;
	case CDROMREADRAW:
		sanitise_cdrom_read(rec, 2352);
		break;
	case CDROMREADALL:
		sanitise_cdrom_read(rec, 2646);
		break;
	case CDROMREADAUDIO:
		sanitise_cdrom_readaudio(rec);
		break;
	case CDROMSEEK:
		sanitise_cdrom_seek(rec);
		break;
	case CDROMPLAYBLK:
		sanitise_cdrom_playblk(rec);
		break;
	case CDROMMULTISESSION:
		sanitise_cdrom_multisession(rec);
		break;
	case CDROM_GET_MCN:
		sanitise_cdrom_get_mcn(rec);
		break;
	case DVD_READ_STRUCT:
	case DVD_WRITE_STRUCT:
		sanitise_dvd_struct(rec);
		break;
	case CDROM_TIMED_MEDIA_CHANGE:
		sanitise_cdrom_timed_media_change(rec);
		break;
	case CDROM_NEXT_WRITABLE:
	case CDROM_LAST_WRITTEN:
		sanitise_cdrom_long_out(rec);
		break;
	case CDROMGETSPINDOWN:
		rec->a3 = (unsigned long) get_writable_struct(4);
		break;
	case CDROMSETSPINDOWN:
		rec->a3 = rand() % 4;
		break;
	case CDROMEJECT_SW:
	case CDROM_LOCKDOOR:
	case CDROM_DEBUG:
		rec->a3 = rand() % 2;
		break;
	case CDROM_SET_OPTIONS:
	case CDROM_CLEAR_OPTIONS:
		rec->a3 = rand();
		break;
	case CDROM_MEDIA_CHANGED:
	case CDROM_DRIVE_STATUS:
		switch (rand() % 3) {
		case 0:  rec->a3 = CDSL_CURRENT; break;
		case 1:  rec->a3 = CDSL_NONE;    break;
		default: rec->a3 = rand() % 16;  break;
		}
		break;
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
		switch (rand() % 10) {
		case 0:  rec->a3 = CDSL_CURRENT; break;
		case 1:  rec->a3 = CDSL_NONE;    break;
		default: rec->a3 = rand() % 16;  break;
		}
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
