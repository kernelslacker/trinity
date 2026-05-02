/* /dev/mei[N] Intel Management Engine Interface chrdev ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/mei.h>
#include <string.h>

#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

/*
 * The mei driver (drivers/misc/mei/main.c) registers its own char-major
 * via alloc_chrdev_region() with the literal name "mei", so /proc/devices
 * shows it under "Character devices:" and the standard DEV_CHAR + devs[]
 * match path applies.  Per-device nodes are /dev/mei0, /dev/mei1, ...
 *
 * Per-fd state machine: a fresh open() leaves the fd at MEI_FILE_INITIALIZING.
 * Only IOCTL_MEI_CONNECT_CLIENT[_VTAG] is meaningfully callable at this point;
 * NOTIFY_SET/GET return -ENODEV until a successful connect.  Exactly one
 * successful CONNECT is allowed per fd lifetime -- subsequent CONNECTs
 * return -EBUSY.  close() is the only reset.
 *
 * Without a UUID known to the firmware client list, CONNECT returns -ENOTTY
 * immediately (mei_me_cl_by_uuid() lookup miss).  Random 16-byte UUIDs hit
 * a real client at probability 1/2^128, so raw fuzzing is degenerate.  The
 * static table below is the well-known UUID set hardcoded in
 * drivers/misc/mei/bus-fixup.c plus the AMTHI host-interface UUID; biasing
 * CONNECT toward these unlocks the actual mei_cl_connect() path including
 * the HBM round-trip, vtag-support check, and per-client notification
 * subscribe path.  The trailing NULL UUID gives -ENOTTY negative-test cover.
 *
 * Brick risk: the four ioctls in scope cannot perturb FW state.  No
 * firmware-update or host-interface-disable commands exist on this surface
 * (igsc uses a separate mei_lb path).  In-kernel consumers (mei-wdt,
 * mei-hdcp) are protected by -EBUSY when their FW client is already held,
 * so trinity grabbing the WD or HDCP UUID just bounces back.  Server SKUs
 * (devservers, prod fleet) do not load mei.ko at all.
 *
 * IOCTL_MEI_CONNECT_CLIENT_VTAG arrived in 2021; #ifdef-wrap it so the
 * group still builds against pre-vtag uapi headers.
 */

struct mei_uuid_entry {
	__u8 b[16];
};

#define MEI_UUID(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)		\
	{ { (a) & 0xff, ((a) >> 8) & 0xff,				\
	    ((a) >> 16) & 0xff, ((a) >> 24) & 0xff,			\
	    (b) & 0xff, ((b) >> 8) & 0xff,				\
	    (c) & 0xff, ((c) >> 8) & 0xff,				\
	    (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) } }

static const struct mei_uuid_entry mei_known_uuids[] = {
	/* MKHIF fix client -- near-universal on shipping ME firmware */
	MEI_UUID(0x55213584, 0x9a29, 0x4916,
		 0xbd, 0xf8, 0x2b, 0xb3, 0x7e, 0x6d, 0x76, 0xe0),
	/* HDCP client (mei-hdcp) */
	MEI_UUID(0xb638ab7e, 0x94e2, 0x4ea2,
		 0xa5, 0x52, 0xd1, 0xc5, 0x4b, 0x62, 0x7f, 0x04),
	/* PAVP client */
	MEI_UUID(0xfbf6fcf1, 0x96cf, 0x4e2e,
		 0xa6, 0xa6, 0x1b, 0xab, 0x8c, 0xbe, 0x36, 0xb1),
	/* NFC info */
	MEI_UUID(0xd2de1625, 0x382d, 0x417d,
		 0x48, 0xa4, 0xef, 0xab, 0xbe, 0x54, 0x40, 0x0a),
	/* iAMT watchdog (mei-wdt) */
	MEI_UUID(0x05b79a6f, 0x4628, 0x4d7f,
		 0x89, 0x9d, 0xa9, 0x15, 0x14, 0xcb, 0x32, 0xab),
	/* iGSC MKHI -- integrated graphics security */
	MEI_UUID(0xe2c2afa2, 0x3817, 0x4d19,
		 0x9d, 0x95, 0x06, 0x53, 0xbc, 0xaa, 0x5a, 0x92),
	/* AMTHI -- Intel AMT host interface */
	MEI_UUID(0x12f80028, 0xb4b7, 0x4b2d,
		 0xac, 0xa8, 0x46, 0xe0, 0xff, 0x65, 0x81, 0x4c),
	/* NULL UUID -- always -ENOTTY, negative-test cover */
	MEI_UUID(0x00000000, 0x0000, 0x0000,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
};

static void fill_mei_uuid(uuid_le *u)
{
	unsigned int i;

	/* 80% well-known, 20% fully random for -ENOTTY lookup-fail cover. */
	if ((rand() % 5) != 0) {
		const struct mei_uuid_entry *e =
			&mei_known_uuids[rand() % ARRAY_SIZE(mei_known_uuids)];
		memcpy(u->b, e->b, sizeof(u->b));
		return;
	}

	for (i = 0; i < sizeof(u->b); i++)
		u->b[i] = rand() & 0xff;
}

static void sanitise_connect_client(struct syscallrecord *rec)
{
	struct mei_connect_client_data *d;

	d = (struct mei_connect_client_data *)
		get_writable_struct(sizeof(*d));
	if (!d)
		return;
	memset(d, 0, sizeof(*d));
	fill_mei_uuid(&d->in_client_uuid);
	rec->a3 = (unsigned long) d;
}

#ifdef IOCTL_MEI_CONNECT_CLIENT_VTAG
static void sanitise_connect_client_vtag(struct syscallrecord *rec)
{
	struct mei_connect_client_data_vtag *d;

	d = (struct mei_connect_client_data_vtag *)
		get_writable_struct(sizeof(*d));
	if (!d)
		return;
	memset(d, 0, sizeof(*d));
	fill_mei_uuid(&d->connect.in_client_uuid);

	/* vtag must be nonzero for valid tagged-channel connect; OR-with-1
	 * stays in [1, 255] most of the time.  Occasionally let through a
	 * zero vtag to exercise the -EINVAL branch. */
	if ((rand() % 8) == 0)
		d->connect.vtag = 0;
	else
		d->connect.vtag = (rand() & 0xff) | 1;

	rec->a3 = (unsigned long) d;
}
#endif

static void sanitise_notify_set(struct syscallrecord *rec)
{
	__u32 *v;

	v = (__u32 *) get_writable_struct(sizeof(*v));
	if (!v)
		return;

	/* Mostly 0/1 (the only values the dispatcher accepts), occasionally
	 * a random u32 to hit the -EINVAL branch in the validator. */
	if ((rand() % 8) == 0)
		*v = (__u32) rand();
	else
		*v = RAND_BOOL();

	rec->a3 = (unsigned long) v;
}

static void sanitise_notify_get(struct syscallrecord *rec)
{
	__u32 *v;

	v = (__u32 *) get_writable_struct(sizeof(*v));
	if (!v)
		return;
	*v = 0;
	rec->a3 = (unsigned long) v;
}

static void mei_sanitise(const struct ioctl_group *grp,
			 struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case IOCTL_MEI_CONNECT_CLIENT:
		sanitise_connect_client(rec);
		break;

#ifdef IOCTL_MEI_CONNECT_CLIENT_VTAG
	case IOCTL_MEI_CONNECT_CLIENT_VTAG:
		sanitise_connect_client_vtag(rec);
		break;
#endif

	case IOCTL_MEI_NOTIFY_SET:
		sanitise_notify_set(rec);
		break;

	case IOCTL_MEI_NOTIFY_GET:
		sanitise_notify_get(rec);
		break;

	default:
		break;
	}
}

static const struct ioctl mei_ioctls[] = {
	IOCTL(IOCTL_MEI_CONNECT_CLIENT),
	IOCTL(IOCTL_MEI_NOTIFY_SET),
	IOCTL(IOCTL_MEI_NOTIFY_GET),
#ifdef IOCTL_MEI_CONNECT_CLIENT_VTAG
	IOCTL(IOCTL_MEI_CONNECT_CLIENT_VTAG),
#endif
};

static const char *const mei_devs[] = {
	"mei",
};

static const struct ioctl_group mei_grp = {
	.name = "mei",
	.devtype = DEV_CHAR,
	.devs = mei_devs,
	.devs_cnt = ARRAY_SIZE(mei_devs),
	.sanitise = mei_sanitise,
	.ioctls = mei_ioctls,
	.ioctls_cnt = ARRAY_SIZE(mei_ioctls),
};

REG_IOCTL_GROUP(mei_grp)
