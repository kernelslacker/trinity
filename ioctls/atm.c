/* ATM ioctl group. */

#include <linux/atmdev.h>
#include <linux/atm.h>
#include <linux/sonet.h>
#include <linux/atmbr2684.h>
#include <sys/socket.h>

#include "ioctls.h"
#include "net.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

/*
 * Compile-time: every fixed-shape ATM/SONET/BR2684 ioctl the sanitisers
 * below fill must have sizeof(struct) matching the _IOC_SIZE encoded in
 * its request bits.  A mismatch means one of <linux/atmdev.h>,
 * <linux/sonet.h> or <linux/atmbr2684.h> moved under us and the
 * sanitiser is memset()ing / stamping into a buffer the kernel copies
 * less of than we prepared (under-encoded) or reads past (over-encoded).
 * ATM_SETSC (int), ATM_SETBACKEND / ATM_NEWBACKENDIF (atm_backend_t),
 * SONET_SETDIAG / SONET_CLRDIAG / SONET_GETDIAG / SONET_SETFRAMING /
 * SONET_GETFRAMING (int) and SONET_GETFRSENSE (unsigned char[6] raw byte
 * buffer) take bare scalars or a fixed byte array and are intentionally
 * absent -- asserting sizeof(struct) against a scalar would not be
 * meaningful.
 */
IOCTL_SIZE_ASSERT(ATM_GETLINKRATE, struct atmif_sioc);
IOCTL_SIZE_ASSERT(ATM_GETNAMES, struct atm_iobuf);
IOCTL_SIZE_ASSERT(ATM_GETTYPE, struct atmif_sioc);
IOCTL_SIZE_ASSERT(ATM_GETESI, struct atmif_sioc);
IOCTL_SIZE_ASSERT(ATM_GETCIRANGE, struct atmif_sioc);
IOCTL_SIZE_ASSERT(ATM_SETCIRANGE, struct atmif_sioc);
IOCTL_SIZE_ASSERT(ATM_SETESI, struct atmif_sioc);
IOCTL_SIZE_ASSERT(ATM_SETESIF, struct atmif_sioc);
IOCTL_SIZE_ASSERT(ATM_GETSTAT, struct atmif_sioc);
IOCTL_SIZE_ASSERT(ATM_GETSTATZ, struct atmif_sioc);
IOCTL_SIZE_ASSERT(ATM_GETLOOP, struct atmif_sioc);
IOCTL_SIZE_ASSERT(ATM_SETLOOP, struct atmif_sioc);
IOCTL_SIZE_ASSERT(ATM_QUERYLOOP, struct atmif_sioc);
IOCTL_SIZE_ASSERT(BR2684_SETFILT, struct br2684_filter_set);
IOCTL_SIZE_ASSERT(SONET_GETSTAT, struct sonet_stats);
IOCTL_SIZE_ASSERT(SONET_GETSTATZ, struct sonet_stats);

static int atm_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SOCKET);

	for_each_obj(head, obj, idx) {
		struct socketinfo *si = &obj->sockinfo;

		if (si->fd == fd && si->triplet.family == PF_ATMPVC)
			return 0;
	}

	return -1;
}

/*
 * Most ATM device ioctls pass a struct atmif_sioc where number selects the
 * interface and arg points to ioctl-specific data.  Allocate a generic blob
 * large enough for the common cases (stats, addresses, ci-range, etc.).
 */
static void sanitise_atmif_sioc(struct syscallrecord *rec)
{
	struct atmif_sioc *sioc;
	void *arg;

	sioc = (struct atmif_sioc *) get_writable_struct(sizeof(*sioc));
	if (!sioc)
		return;
	memset(sioc, 0, sizeof(*sioc));
	sioc->number = rnd_modulo_u32(16);
	arg = get_writable_struct(64);
	if (arg) {
		sioc->arg = arg;
		sioc->length = 64;
	} else {
		sioc->arg = NULL;
		sioc->length = 0;
	}
	rec->a3 = (unsigned long) sioc;
}

static void sanitise_atm_cirange(struct syscallrecord *rec)
{
	struct atmif_sioc *sioc;
	struct atm_cirange *cir;

	sioc = (struct atmif_sioc *) get_writable_struct(sizeof(*sioc));
	if (!sioc)
		return;
	memset(sioc, 0, sizeof(*sioc));
	cir = (struct atm_cirange *) get_writable_struct(sizeof(*cir));
	if (!cir)
		return;
	memset(cir, 0, sizeof(*cir));
	/* ATM_CI_MAX (-1) means use hardware maximum; otherwise 1..8 for vpi, 1..16 for vci */
	cir->vpi_bits = RAND_BOOL() ? ATM_CI_MAX : (rnd_modulo_u32(8) + 1);
	cir->vci_bits = RAND_BOOL() ? ATM_CI_MAX : (rnd_modulo_u32(16) + 1);
	sioc->number = rnd_modulo_u32(16);
	sioc->length = sizeof(*cir);
	sioc->arg = cir;
	rec->a3 = (unsigned long) sioc;
}

static void sanitise_atm_iobuf(struct syscallrecord *rec)
{
	struct atm_iobuf *iobuf;
	void *buf;
	int len;

	iobuf = (struct atm_iobuf *) get_writable_struct(sizeof(*iobuf));
	if (!iobuf)
		return;
	memset(iobuf, 0, sizeof(*iobuf));
	len = rnd_modulo_u32(256) + 4;
	buf = get_writable_struct(len);
	if (buf) {
		iobuf->buffer = buf;
		iobuf->length = len;
	} else {
		iobuf->buffer = NULL;
		iobuf->length = 0;
	}
	rec->a3 = (unsigned long) iobuf;
}

static void sanitise_br2684_filter_set(struct syscallrecord *rec)
{
	struct br2684_filter_set *fs;

	fs = (struct br2684_filter_set *) get_writable_struct(sizeof(*fs));
	if (!fs)
		return;
	memset(fs, 0, sizeof(*fs));
	fs->ifspec.method = rnd_modulo_u32(3);	/* BR2684_FIND_BYNOTHING/BYNUM/BYIFNAME */
	if (fs->ifspec.method == BR2684_FIND_BYNUM)
		fs->ifspec.spec.devnum = rnd_modulo_u32(16);
	/* netmask 0 disables the filter; use a non-zero mask most of the time */
	fs->filter.netmask = RAND_BOOL() ? 0 : 0xffffff00u;
	fs->filter.prefix = rnd_u32();
	rec->a3 = (unsigned long) fs;
}

static void atm_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	/* ioctls that take struct atmif_sioc with a generic payload */
	case ATM_GETLINKRATE:
	case ATM_GETTYPE:
	case ATM_GETESI:
	case ATM_GETCIRANGE:
	case ATM_SETESI:
	case ATM_SETESIF:
	case ATM_GETSTAT:
	case ATM_GETSTATZ:
	case ATM_GETLOOP:
	case ATM_SETLOOP:
	case ATM_QUERYLOOP:
		sanitise_atmif_sioc(rec);
		break;

	case ATM_SETCIRANGE:
		sanitise_atm_cirange(rec);
		break;

	case ATM_GETNAMES:
	case ATM_ADDPARTY:
		sanitise_atm_iobuf(rec);
		break;

	case ATM_SETSC: {
		/* int bitmask: ATM_SC_RX=1024, ATM_SC_TX=2048 */
		int *sc = (int *) get_writable_struct(sizeof(int));
		if (sc) {
			static const int sc_flags[] = { 0, 1024, 2048, 3072 };
			*sc = sc_flags[rnd_modulo_u32(ARRAY_SIZE(sc_flags))];
			rec->a3 = (unsigned long) sc;
		}
		break;
	}

	case ATM_SETBACKEND:
	case ATM_NEWBACKENDIF: {
		/* atm_backend_t (unsigned short): raw=0, ppp=1, br2684=2 */
		atm_backend_t *be = (atm_backend_t *) get_writable_struct(sizeof(*be));
		if (be) {
			*be = rnd_modulo_u32(3);
			rec->a3 = (unsigned long) be;
		}
		break;
	}

	case ATM_DROPPARTY: {
		/* int: party endpoint ID (1..127 for N-UNI) */
		int *pid = (int *) get_writable_struct(sizeof(int));
		if (pid) {
			*pid = rnd_modulo_u32(127) + 1;
			rec->a3 = (unsigned long) pid;
		}
		break;
	}

	case BR2684_SETFILT:
		sanitise_br2684_filter_set(rec);
		break;

	case SONET_GETSTAT:
	case SONET_GETSTATZ: {
		/* output: struct sonet_stats */
		struct sonet_stats *stats = get_writable_struct(sizeof(*stats));
		if (stats) {
			memset(stats, 0, sizeof(*stats));
			rec->a3 = (unsigned long) stats;
		}
		break;
	}

	case SONET_SETDIAG:
	case SONET_CLRDIAG: {
		/* IOWR(int): set/clear error-insertion bits */
		int *diag = (int *) get_writable_struct(sizeof(int));
		if (diag) {
			*diag = rnd_u32() & 0xFF;	/* SONET_INS_* flags, bits 0-7 */
			rec->a3 = (unsigned long) diag;
		}
		break;
	}

	case SONET_GETDIAG:
	case SONET_GETFRAMING: {
		/* output: int */
		int *p = (int *) get_writable_struct(sizeof(int));
		if (p)
			rec->a3 = (unsigned long) p;
		break;
	}

	case SONET_SETFRAMING: {
		/* _IOW(int): 0=SONET, 1=SDH */
		int *framing = (int *) get_writable_struct(sizeof(int));
		if (framing) {
			*framing = rnd_modulo_u32(2);
			rec->a3 = (unsigned long) framing;
		}
		break;
	}

	case SONET_GETFRSENSE: {
		/* output: unsigned char[SONET_FRSENSE_SIZE] (6 bytes) */
		unsigned char *sense = (unsigned char *) get_writable_struct(SONET_FRSENSE_SIZE);
		if (sense) {
			memset(sense, 0, SONET_FRSENSE_SIZE);
			rec->a3 = (unsigned long) sense;
		}
		break;
	}

	default:
		break;
	}
}

static const struct ioctl atm_ioctls[] = {
	IOCTL(ATM_GETLINKRATE),
	IOCTL(ATM_GETNAMES),
	IOCTL(ATM_GETTYPE),
	IOCTL(ATM_GETESI),
	IOCTL(ATM_GETCIRANGE),
	IOCTL(ATM_SETCIRANGE),
	IOCTL(ATM_SETESI),
	IOCTL(ATM_SETESIF),
	IOCTL(ATM_GETSTAT),
	IOCTL(ATM_GETSTATZ),
	IOCTL(ATM_GETLOOP),
	IOCTL(ATM_SETLOOP),
	IOCTL(ATM_QUERYLOOP),
	IOCTL(ATM_SETSC),
	IOCTL(ATM_SETBACKEND),
	IOCTL(ATM_NEWBACKENDIF),
	IOCTL(ATM_ADDPARTY),
	IOCTL(ATM_DROPPARTY),
	/* BR2684 bridged RFC2684 backend filter */
	IOCTL(BR2684_SETFILT),
	IOCTL(SONET_GETSTAT),
	IOCTL(SONET_GETSTATZ),
	IOCTL(SONET_SETDIAG),
	IOCTL(SONET_CLRDIAG),
	IOCTL(SONET_GETDIAG),
	IOCTL(SONET_SETFRAMING),
	IOCTL(SONET_GETFRAMING),
	IOCTL(SONET_GETFRSENSE),
};

static const struct ioctl_group atm_grp = {
	.name = "atm",
	.fd_test = atm_fd_test,
	.sanitise = atm_sanitise,
	.ioctls = atm_ioctls,
	.ioctls_cnt = ARRAY_SIZE(atm_ioctls),
};

REG_IOCTL_GROUP(atm_grp)
