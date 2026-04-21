/* ATM ioctl group. */

#include <linux/atmdev.h>
#include <linux/atm.h>
#include <linux/sonet.h>
#include <linux/atm_eni.h>
#include <linux/atm_he.h>
#include <linux/atm_nicstar.h>
#include <linux/atm_zatm.h>
#include <linux/atm_idt77105.h>
#include <sys/socket.h>

#include "ioctls.h"
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

static int atm_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct list_head *globallist, *node;

	globallist = shm->global_objects[OBJ_FD_SOCKET].list;

	list_for_each(node, globallist) {
		struct object *obj;
		struct socketinfo *si;

		obj = (struct object *) node;
		si = &obj->sockinfo;

		if (si->fd == fd &&
		    (si->triplet.family == PF_ATMPVC ||
		     si->triplet.family == PF_ATMSVC))
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

	sioc = (struct atmif_sioc *) get_writable_struct(sizeof(*sioc));
	if (!sioc)
		return;
	sioc->number = rand() % 16;
	sioc->length = 64;
	sioc->arg = get_writable_struct(64);
	rec->a3 = (unsigned long) sioc;
}

static void sanitise_atm_cirange(struct syscallrecord *rec)
{
	struct atmif_sioc *sioc;
	struct atm_cirange *cir;

	sioc = (struct atmif_sioc *) get_writable_struct(sizeof(*sioc));
	if (!sioc)
		return;
	cir = (struct atm_cirange *) get_writable_struct(sizeof(*cir));
	if (!cir)
		return;
	/* ATM_CI_MAX (-1) means use hardware maximum; otherwise 1..8 for vpi, 1..16 for vci */
	cir->vpi_bits = RAND_BOOL() ? ATM_CI_MAX : (rand() % 8 + 1);
	cir->vci_bits = RAND_BOOL() ? ATM_CI_MAX : (rand() % 16 + 1);
	sioc->number = rand() % 16;
	sioc->length = sizeof(*cir);
	sioc->arg = cir;
	rec->a3 = (unsigned long) sioc;
}

static void sanitise_atm_iobuf(struct syscallrecord *rec)
{
	struct atm_iobuf *iobuf;
	int len;

	iobuf = (struct atm_iobuf *) get_writable_struct(sizeof(*iobuf));
	if (!iobuf)
		return;
	len = rand() % 256 + 4;
	iobuf->length = len;
	iobuf->buffer = get_writable_struct(len);
	rec->a3 = (unsigned long) iobuf;
}

static void atm_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	/* ioctls that take struct atmif_sioc with a generic payload */
	case ATM_GETLINKRATE:
	case ATM_GETTYPE:
	case ATM_GETESI:
	case ATM_GETADDR:
	case ATM_RSTADDR:
	case ATM_ADDADDR:
	case ATM_DELADDR:
	case ATM_GETCIRANGE:
	case ATM_SETESI:
	case ATM_SETESIF:
	case ATM_ADDLECSADDR:
	case ATM_DELLECSADDR:
	case ATM_GETLECSADDR:
	case ATM_GETSTAT:
	case ATM_GETSTATZ:
	case ATM_GETLOOP:
	case ATM_SETLOOP:
	case ATM_QUERYLOOP:
	/* vendor PHY-private ioctls (IDT77105) */
	case IDT77105_GETSTAT:
	case IDT77105_GETSTATZ:
	/* vendor SAR-private ioctls; ENI_MEMDUMP == HE_GET_REG numerically */
	case ENI_MEMDUMP:
	case ENI_SETMULT:
	case NS_GETPSTAT:
	case ZATM_GETPOOL:
	/* ZATM_GETPOOLZ == NS_SETBUFLEV numerically; one label covers both */
	case ZATM_GETPOOLZ:
	case ZATM_SETPOOL:
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
			*sc = sc_flags[rand() % ARRAY_SIZE(sc_flags)];
			rec->a3 = (unsigned long) sc;
		}
		break;
	}

	case ATM_SETBACKEND:
	case ATM_NEWBACKENDIF: {
		/* atm_backend_t (unsigned short): raw=0, ppp=1, br2684=2 */
		atm_backend_t *be = (atm_backend_t *) get_writable_struct(sizeof(*be));
		if (be) {
			*be = rand() % 3;
			rec->a3 = (unsigned long) be;
		}
		break;
	}

	case ATM_DROPPARTY: {
		/* int: party endpoint ID (1..127 for N-UNI) */
		int *pid = (int *) get_writable_struct(sizeof(int));
		if (pid) {
			*pid = rand() % 127 + 1;
			rec->a3 = (unsigned long) pid;
		}
		break;
	}

	case SONET_GETSTAT:
	case SONET_GETSTATZ: {
		/* output: struct sonet_stats */
		struct sonet_stats *stats = get_writable_struct(sizeof(*stats));
		if (stats)
			rec->a3 = (unsigned long) stats;
		break;
	}

	case SONET_SETDIAG:
	case SONET_CLRDIAG: {
		/* IOWR(int): set/clear error-insertion bits */
		int *diag = (int *) get_writable_struct(sizeof(int));
		if (diag) {
			*diag = rand() & 0xFF;	/* SONET_INS_* flags, bits 0-7 */
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
			*framing = rand() % 2;
			rec->a3 = (unsigned long) framing;
		}
		break;
	}

	case SONET_GETFRSENSE: {
		/* output: unsigned char[SONET_FRSENSE_SIZE] (6 bytes) */
		unsigned char *sense = (unsigned char *) get_writable_struct(SONET_FRSENSE_SIZE);
		if (sense)
			rec->a3 = (unsigned long) sense;
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
	IOCTL(ATM_GETADDR),
	IOCTL(ATM_RSTADDR),
	IOCTL(ATM_ADDADDR),
	IOCTL(ATM_DELADDR),
	IOCTL(ATM_GETCIRANGE),
	IOCTL(ATM_SETCIRANGE),
	IOCTL(ATM_SETESI),
	IOCTL(ATM_SETESIF),
	IOCTL(ATM_ADDLECSADDR),
	IOCTL(ATM_DELLECSADDR),
	IOCTL(ATM_GETLECSADDR),
	IOCTL(ATM_GETSTAT),
	IOCTL(ATM_GETSTATZ),
	IOCTL(ATM_GETLOOP),
	IOCTL(ATM_SETLOOP),
	IOCTL(ATM_QUERYLOOP),
	IOCTL(ATM_SETSC),
	IOCTL(ATM_SETBACKEND),
	IOCTL(ATM_NEWBACKENDIF),
	/* vendor PHY-private driver ioctls */
	IOCTL(IDT77105_GETSTAT),
	IOCTL(IDT77105_GETSTATZ),
	/* vendor SAR-private driver ioctls */
	IOCTL(ENI_MEMDUMP),
	IOCTL(ENI_SETMULT),
	IOCTL(HE_GET_REG),
	IOCTL(NS_GETPSTAT),
	IOCTL(NS_SETBUFLEV),
	IOCTL(NS_ADJBUFLEV),
	IOCTL(ZATM_GETPOOL),
	IOCTL(ZATM_GETPOOLZ),
	IOCTL(ZATM_SETPOOL),
	IOCTL(ATM_ADDPARTY),
	IOCTL(ATM_DROPPARTY),
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
