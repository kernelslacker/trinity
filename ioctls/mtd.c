#include <linux/ioctl.h>
#include <mtd/mtd-abi.h>

#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_erase_info_user(struct syscallrecord *rec)
{
	struct erase_info_user *eiu;

	eiu = (struct erase_info_user *) get_writable_struct(sizeof(*eiu));
	if (!eiu)
		return;
	eiu->start = rand32();
	eiu->length = rand32();
	rec->a3 = (unsigned long) eiu;
}

static void sanitise_erase_info_user64(struct syscallrecord *rec)
{
	struct erase_info_user64 *eiu;

	eiu = (struct erase_info_user64 *) get_writable_struct(sizeof(*eiu));
	if (!eiu)
		return;
	eiu->start = rand64();
	eiu->length = rand64();
	rec->a3 = (unsigned long) eiu;
}

static void sanitise_mtd_oob_buf(struct syscallrecord *rec)
{
	struct mtd_oob_buf *oob;

	oob = (struct mtd_oob_buf *) get_writable_struct(sizeof(*oob));
	if (!oob)
		return;
	oob->start = rand32();
	oob->length = rand() % 64;
	oob->ptr = (unsigned char *) get_writable_struct(oob->length + 1);
	rec->a3 = (unsigned long) oob;
}

static void sanitise_mtd_oob_buf64(struct syscallrecord *rec)
{
	struct mtd_oob_buf64 *oob;

	oob = (struct mtd_oob_buf64 *) get_writable_struct(sizeof(*oob));
	if (!oob)
		return;
	oob->start = rand64();
	oob->length = rand() % 64;
	oob->usr_ptr = (unsigned long) get_writable_struct(oob->length + 1);
	rec->a3 = (unsigned long) oob;
}

static void sanitise_region_info_user(struct syscallrecord *rec)
{
	struct region_info_user *riu;

	riu = (struct region_info_user *) get_writable_struct(sizeof(*riu));
	if (!riu)
		return;
	riu->regionindex = rand() % 16;
	rec->a3 = (unsigned long) riu;
}

static void sanitise_otp_info(struct syscallrecord *rec)
{
	struct otp_info *oi;

	oi = (struct otp_info *) get_writable_struct(sizeof(*oi));
	if (!oi)
		return;
	oi->start = rand32();
	oi->length = rand() % 4096;
	oi->locked = RAND_BOOL();
	rec->a3 = (unsigned long) oi;
}

static void sanitise_mtd_write_req(struct syscallrecord *rec)
{
	struct mtd_write_req *req;

	req = (struct mtd_write_req *) get_writable_struct(sizeof(*req));
	if (!req)
		return;
	req->start = rand64();
	req->len = rand() % 4096;
	req->ooblen = rand() % 128;
	req->mode = rand() % 3;
	req->usr_data = (unsigned long) get_writable_struct(req->len + 1);
	if (RAND_BOOL())
		req->usr_oob = (unsigned long) get_writable_struct(req->ooblen + 1);
	rec->a3 = (unsigned long) req;
}

#ifdef MEMREAD
static void sanitise_mtd_read_req(struct syscallrecord *rec)
{
	struct mtd_read_req *req;

	req = (struct mtd_read_req *) get_writable_struct(sizeof(*req));
	if (!req)
		return;
	req->start = rand64();
	req->len = rand() % 4096;
	req->ooblen = rand() % 128;
	req->mode = rand() % 3;
	req->usr_data = (unsigned long) get_writable_struct(req->len + 1);
	if (RAND_BOOL())
		req->usr_oob = (unsigned long) get_writable_struct(req->ooblen + 1);
	rec->a3 = (unsigned long) req;
}
#endif

static void mtd_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case MEMERASE:
	case MEMLOCK:
	case MEMUNLOCK:
#ifdef MEMISLOCKED
	case MEMISLOCKED:
#endif
		sanitise_erase_info_user(rec);
		break;

	case MEMERASE64:
		sanitise_erase_info_user64(rec);
		break;

	case MEMWRITEOOB:
	case MEMREADOOB:
		sanitise_mtd_oob_buf(rec);
		break;

	case MEMWRITEOOB64:
	case MEMREADOOB64:
		sanitise_mtd_oob_buf64(rec);
		break;

	case MEMGETREGIONINFO:
		sanitise_region_info_user(rec);
		break;

	case OTPGETREGIONINFO:
	case OTPLOCK:
		sanitise_otp_info(rec);
		break;

#ifdef MEMWRITE
	case MEMWRITE:
		sanitise_mtd_write_req(rec);
		break;
#endif

#ifdef OTPERASE
	case OTPERASE:
		sanitise_otp_info(rec);
		break;
#endif

#ifdef MEMREAD
	case MEMREAD:
		sanitise_mtd_read_req(rec);
		break;
#endif

	case MEMGETINFO: {
		struct mtd_info_user *info = get_writable_struct(sizeof(*info));
		if (info)
			rec->a3 = (unsigned long) info;
		break;
	}

	case MEMGETOOBSEL: {
		struct nand_oobinfo *oobsel = get_writable_struct(sizeof(*oobsel));
		if (oobsel)
			rec->a3 = (unsigned long) oobsel;
		break;
	}

	case ECCGETLAYOUT: {
		struct nand_ecclayout_user *layout = get_writable_struct(sizeof(*layout));
		if (layout)
			rec->a3 = (unsigned long) layout;
		break;
	}

	case ECCGETSTATS: {
		struct mtd_ecc_stats *stats = get_writable_struct(sizeof(*stats));
		if (stats)
			rec->a3 = (unsigned long) stats;
		break;
	}

	case MEMGETREGIONCOUNT:
	case OTPSELECT:
	case OTPGETREGIONCOUNT: {
		int *p = (int *) get_writable_struct(sizeof(int));
		if (p)
			rec->a3 = (unsigned long) p;
		break;
	}

	case MEMGETBADBLOCK:
	case MEMSETBADBLOCK: {
		__u64 *off = (__u64 *) get_writable_struct(sizeof(__u64));
		if (off) {
			*off = rand64();
			rec->a3 = (unsigned long) off;
		}
		break;
	}

	case MTDFILEMODE:
		/* arg is a mode value, not a pointer */
		rec->a3 = rand() % 4;
		break;

	default:
		break;
	}
}

static const struct ioctl mtd_ioctls[] = {
	IOCTL(MEMGETINFO),
	IOCTL(MEMERASE),
	IOCTL(MEMWRITEOOB),
	IOCTL(MEMREADOOB),
	IOCTL(MEMLOCK),
	IOCTL(MEMUNLOCK),
	IOCTL(MEMGETREGIONCOUNT),
	IOCTL(MEMGETREGIONINFO),
	/* IOCTL(MEMSETOOBSEL), */
	IOCTL(MEMGETOOBSEL),
	IOCTL(MEMGETBADBLOCK),
	IOCTL(MEMSETBADBLOCK),
	IOCTL(OTPSELECT),
	IOCTL(OTPGETREGIONCOUNT),
	IOCTL(OTPGETREGIONINFO),
	IOCTL(OTPLOCK),
	IOCTL(ECCGETLAYOUT),
	IOCTL(ECCGETSTATS),
	IOCTL(MTDFILEMODE),
	IOCTL(MEMERASE64),
	IOCTL(MEMWRITEOOB64),
	IOCTL(MEMREADOOB64),
#ifdef MEMISLOCKED
	IOCTL(MEMISLOCKED),
#endif
#ifdef MEMWRITE
	IOCTL(MEMWRITE),
#endif
#ifdef OTPERASE
	IOCTL(OTPERASE),
#endif
#ifdef MEMREAD
	IOCTL(MEMREAD),
#endif
};

static const char *const mtd_devs[] = {
	"mtd",
};

static const struct ioctl_group mtd_grp = {
	.devtype = DEV_MISC,
	.devs = mtd_devs,
	.devs_cnt = ARRAY_SIZE(mtd_devs),
	.sanitise = mtd_sanitise,
	.ioctls = mtd_ioctls,
	.ioctls_cnt = ARRAY_SIZE(mtd_ioctls),
};

REG_IOCTL_GROUP(mtd_grp)
