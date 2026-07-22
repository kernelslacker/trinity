#include <linux/ioctl.h>
#include <mtd/mtd-abi.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

/*
 * Compile-time: every size-carrying MTD ioctl command the sanitisers
 * below fill must have sizeof(arg) matching the _IOC_SIZE encoded in
 * its request bits.  A mismatch means the kernel mtd-abi.h moved
 * under us and the sanitiser is stamping into a buffer the kernel
 * copies less of than we prepared (under-encoded) or reads past
 * (over-encoded).  Commands sharing a struct (MEMERASE, MEMLOCK,
 * MEMUNLOCK, MEMISLOCKED all take erase_info_user; MEMWRITEOOB and
 * MEMREADOOB both take mtd_oob_buf; MEMWRITEOOB64 and MEMREADOOB64
 * both take mtd_oob_buf64; OTPGETREGIONINFO, OTPLOCK, OTPERASE all
 * take otp_info) get one assert each -- the two sides can drift
 * independently in a header refactor.  The scalar-carrying commands
 * (MEMGETREGIONCOUNT, OTPSELECT, OTPGETREGIONCOUNT each take a bare
 * int; MEMGETBADBLOCK and MEMSETBADBLOCK each take a __kernel_loff_t,
 * which is long long and matches __u64 in width) are asserted too.
 * MTDFILEMODE is _IO() with no size and is intentionally absent.
 */
IOCTL_SIZE_ASSERT(MEMGETINFO, struct mtd_info_user);
IOCTL_SIZE_ASSERT(MEMERASE, struct erase_info_user);
IOCTL_SIZE_ASSERT(MEMWRITEOOB, struct mtd_oob_buf);
IOCTL_SIZE_ASSERT(MEMREADOOB, struct mtd_oob_buf);
IOCTL_SIZE_ASSERT(MEMLOCK, struct erase_info_user);
IOCTL_SIZE_ASSERT(MEMUNLOCK, struct erase_info_user);
IOCTL_SIZE_ASSERT(MEMGETREGIONCOUNT, int);
IOCTL_SIZE_ASSERT(MEMGETREGIONINFO, struct region_info_user);
IOCTL_SIZE_ASSERT(MEMGETOOBSEL, struct nand_oobinfo);
IOCTL_SIZE_ASSERT(MEMGETBADBLOCK, __u64);
IOCTL_SIZE_ASSERT(MEMSETBADBLOCK, __u64);
IOCTL_SIZE_ASSERT(OTPSELECT, int);
IOCTL_SIZE_ASSERT(OTPGETREGIONCOUNT, int);
IOCTL_SIZE_ASSERT(OTPGETREGIONINFO, struct otp_info);
IOCTL_SIZE_ASSERT(OTPLOCK, struct otp_info);
IOCTL_SIZE_ASSERT(ECCGETLAYOUT, struct nand_ecclayout_user);
IOCTL_SIZE_ASSERT(ECCGETSTATS, struct mtd_ecc_stats);
IOCTL_SIZE_ASSERT(MEMERASE64, struct erase_info_user64);
IOCTL_SIZE_ASSERT(MEMWRITEOOB64, struct mtd_oob_buf64);
IOCTL_SIZE_ASSERT(MEMREADOOB64, struct mtd_oob_buf64);
#ifdef MEMISLOCKED
IOCTL_SIZE_ASSERT(MEMISLOCKED, struct erase_info_user);
#endif
#ifdef MEMWRITE
IOCTL_SIZE_ASSERT(MEMWRITE, struct mtd_write_req);
#endif
#ifdef OTPERASE
IOCTL_SIZE_ASSERT(OTPERASE, struct otp_info);
#endif
#ifdef MEMREAD
IOCTL_SIZE_ASSERT(MEMREAD, struct mtd_read_req);
#endif

static void sanitise_erase_info_user(struct syscallrecord *rec)
{
	struct erase_info_user *eiu;

	eiu = (struct erase_info_user *) get_writable_struct(sizeof(*eiu));
	if (!eiu)
		return;
	memset(eiu, 0, sizeof(*eiu));
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
	memset(eiu, 0, sizeof(*eiu));
	eiu->start = rand64();
	eiu->length = rand64();
	rec->a3 = (unsigned long) eiu;
}

static void sanitise_mtd_oob_buf(struct syscallrecord *rec)
{
	struct mtd_oob_buf *oob;
	unsigned char *ptr;
	__u32 length;

	oob = (struct mtd_oob_buf *) get_writable_struct(sizeof(*oob));
	if (!oob)
		return;
	memset(oob, 0, sizeof(*oob));
	length = rnd_modulo_u32(64);
	ptr = get_writable_struct(length + 1);
	if (!ptr)
		return;
	generate_rand_bytes(ptr, length + 1);
	oob->start = rand32();
	oob->length = length;
	oob->ptr = ptr;
	rec->a3 = (unsigned long) oob;
}

static void sanitise_mtd_oob_buf64(struct syscallrecord *rec)
{
	struct mtd_oob_buf64 *oob;
	void *usr_ptr;
	__u32 length;

	oob = (struct mtd_oob_buf64 *) get_writable_struct(sizeof(*oob));
	if (!oob)
		return;
	memset(oob, 0, sizeof(*oob));
	length = rnd_modulo_u32(64);
	usr_ptr = get_writable_struct(length + 1);
	if (!usr_ptr)
		return;
	generate_rand_bytes(usr_ptr, length + 1);
	oob->start = rand64();
	oob->length = length;
	oob->usr_ptr = (unsigned long) usr_ptr;
	rec->a3 = (unsigned long) oob;
}

static void sanitise_region_info_user(struct syscallrecord *rec)
{
	struct region_info_user *riu;

	riu = (struct region_info_user *) get_writable_struct(sizeof(*riu));
	if (!riu)
		return;
	memset(riu, 0, sizeof(*riu));
	riu->regionindex = rnd_modulo_u32(16);
	rec->a3 = (unsigned long) riu;
}

static void sanitise_otp_info(struct syscallrecord *rec)
{
	struct otp_info *oi;

	oi = (struct otp_info *) get_writable_struct(sizeof(*oi));
	if (!oi)
		return;
	memset(oi, 0, sizeof(*oi));
	oi->start = rand32();
	oi->length = rnd_modulo_u32(4096);
	oi->locked = RAND_BOOL();
	rec->a3 = (unsigned long) oi;
}

static void sanitise_mtd_write_req(struct syscallrecord *rec)
{
	struct mtd_write_req *req;
	void *usr_data;
	__u32 len, ooblen;

	req = (struct mtd_write_req *) get_writable_struct(sizeof(*req));
	if (!req)
		return;
	memset(req, 0, sizeof(*req));
	len = rnd_modulo_u32(4096);
	ooblen = rnd_modulo_u32(128);
	usr_data = get_writable_struct(len + 1);
	if (!usr_data)
		return;
	req->start = rand64();
	req->len = len;
	req->ooblen = ooblen;
	req->mode = rnd_modulo_u32(3);
	req->usr_data = (unsigned long) usr_data;
	if (RAND_BOOL()) {
		void *usr_oob = get_writable_struct(ooblen + 1);
		if (usr_oob)
			req->usr_oob = (unsigned long) usr_oob;
		else
			req->usr_oob = 0;
	} else {
		req->usr_oob = 0;
	}
	rec->a3 = (unsigned long) req;
}

#ifdef MEMREAD
static void sanitise_mtd_read_req(struct syscallrecord *rec)
{
	struct mtd_read_req *req;
	void *usr_data;
	__u32 len, ooblen;

	req = (struct mtd_read_req *) get_writable_struct(sizeof(*req));
	if (!req)
		return;
	memset(req, 0, sizeof(*req));
	len = rnd_modulo_u32(4096);
	ooblen = rnd_modulo_u32(128);
	usr_data = get_writable_struct(len + 1);
	if (!usr_data)
		return;
	req->start = rand64();
	req->len = len;
	req->ooblen = ooblen;
	req->mode = rnd_modulo_u32(3);
	req->usr_data = (unsigned long) usr_data;
	if (RAND_BOOL()) {
		void *usr_oob = get_writable_struct(ooblen + 1);
		if (usr_oob)
			req->usr_oob = (unsigned long) usr_oob;
		else
			req->usr_oob = 0;
	} else {
		req->usr_oob = 0;
	}
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
		if (info) {
			memset(info, 0, sizeof(*info));
			rec->a3 = (unsigned long) info;
		}
		break;
	}

	case MEMGETOOBSEL: {
		struct nand_oobinfo *oobsel = get_writable_struct(sizeof(*oobsel));
		if (oobsel) {
			memset(oobsel, 0, sizeof(*oobsel));
			rec->a3 = (unsigned long) oobsel;
		}
		break;
	}

	case ECCGETLAYOUT: {
		struct nand_ecclayout_user *layout = get_writable_struct(sizeof(*layout));
		if (layout) {
			memset(layout, 0, sizeof(*layout));
			rec->a3 = (unsigned long) layout;
		}
		break;
	}

	case ECCGETSTATS: {
		struct mtd_ecc_stats *stats = get_writable_struct(sizeof(*stats));
		if (stats) {
			memset(stats, 0, sizeof(*stats));
			rec->a3 = (unsigned long) stats;
		}
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
		rec->a3 = rnd_modulo_u32(4);
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
