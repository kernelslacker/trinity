/* /dev/cec[N] HDMI CEC adapter chrdev ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/cec.h>
#include <string.h>

#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

/*
 * The CEC core (drivers/media/cec/core/cec-core.c) registers its own
 * char-major via alloc_chrdev_region() with the literal name "cec".
 * That string appears in /proc/devices for any host with CONFIG_CEC_CORE
 * built in and a CEC adapter present (HDMI capture cards, SoC HDMI
 * outputs, USB CEC dongles like Pulse-Eight).  Hosts with no adapter
 * never allocate the region and find_ioctl_group() finds no match -- the
 * group simply sees no fds, no fd_test gating required.
 *
 * Brick risk: CEC_TRANSMIT puts an arbitrary CEC message onto the
 * physical HDMI bus.  With msg.msg[] left random, the fuzzer would
 * trivially generate Standby, Routing Change, Set Stream Path, OSD
 * String overwrite, or vendor commands aimed at any logical address on
 * the bus -- on a host with a real HDMI cable to a TV/AVR this would
 * power down displays, switch inputs, or wedge bus arbitration.  Not a
 * kernel bug, but a real-world side effect this fuzzer must not cause.
 *
 * The cec_msg sanitiser below contains TRANSMIT in three layers of
 * defence: the initiator is forced to CEC_LOG_ADDR_UNREGISTERED so the
 * kernel rejects the message during cec_validate_msg() before it ever
 * reaches the wire on a normally-configured adapter; the destination
 * is restricted to logical addresses very unlikely to be claimed by a
 * real device; and the opcode is drawn from a whitelist of read-style
 * queries (Give Physical Addr, Give Vendor ID, Get CEC Version, Abort,
 * etc.) that cannot perturb HDMI routing or display power even if the
 * first two layers fail.  CEC_RECEIVE shares struct cec_msg and uses
 * the same builder for symmetry.
 *
 * The CEC_ADAP_G_CONNECTOR_INFO ioctl (and the CEC_CAP_REPLY_VENDOR_ID
 * cap) are relatively recent additions; #ifdef-wrap them so older
 * libc-headers-supplied <linux/cec.h> still builds.
 */

static const __u8 cec_safe_opcodes[] = {
#ifdef CEC_MSG_GIVE_PHYSICAL_ADDR
	CEC_MSG_GIVE_PHYSICAL_ADDR,
#endif
#ifdef CEC_MSG_GIVE_DEVICE_VENDOR_ID
	CEC_MSG_GIVE_DEVICE_VENDOR_ID,
#endif
#ifdef CEC_MSG_GIVE_OSD_NAME
	CEC_MSG_GIVE_OSD_NAME,
#endif
#ifdef CEC_MSG_GET_CEC_VERSION
	CEC_MSG_GET_CEC_VERSION,
#endif
#ifdef CEC_MSG_GIVE_DEVICE_POWER_STATUS
	CEC_MSG_GIVE_DEVICE_POWER_STATUS,
#endif
#ifdef CEC_MSG_GIVE_FEATURES
	CEC_MSG_GIVE_FEATURES,
#endif
#ifdef CEC_MSG_ABORT
	CEC_MSG_ABORT,
#endif
};

static const __u8 cec_safe_destinations[] = {
	CEC_LOG_ADDR_TUNER_2,
	CEC_LOG_ADDR_TUNER_3,
	CEC_LOG_ADDR_TUNER_4,
	CEC_LOG_ADDR_SPECIFIC,
};

static void sanitise_cec_msg(struct syscallrecord *rec)
{
	struct cec_msg *m;
	__u8 initiator, destination, opcode;

	m = (struct cec_msg *) get_writable_struct(sizeof(*m));
	if (!m)
		return;
	memset(m, 0, sizeof(*m));

	/*
	 * Force initiator to UNREGISTERED so cec_validate_msg() rejects
	 * the transmit on any adapter that has claimed a real logical
	 * address (i.e. all in-service adapters).  See comment above for
	 * the rest of the safety chain.
	 */
	initiator = CEC_LOG_ADDR_UNREGISTERED;
	destination = cec_safe_destinations[rand() %
					    ARRAY_SIZE(cec_safe_destinations)];
	m->msg[0] = (initiator << 4) | (destination & 0xf);

	if (ARRAY_SIZE(cec_safe_opcodes) > 0) {
		opcode = cec_safe_opcodes[rand() % ARRAY_SIZE(cec_safe_opcodes)];
		m->msg[1] = opcode;
		m->len = 2;
	} else {
		m->len = 1;
	}

	/* Short timeout so a stuck wait can't park a child for long. */
	m->timeout = 100;
	m->reply = 0;
	m->flags = 0;

	rec->a3 = (unsigned long) m;
}

static void sanitise_cec_caps(struct syscallrecord *rec)
{
	struct cec_caps *c;

	c = (struct cec_caps *) get_writable_struct(sizeof(*c));
	if (!c)
		return;
	memset(c, 0, sizeof(*c));
	rec->a3 = (unsigned long) c;
}

static void sanitise_cec_phys_addr(struct syscallrecord *rec)
{
	__u16 *p;

	p = (__u16 *) get_writable_struct(sizeof(*p));
	if (!p)
		return;
	*p = (__u16) rand();
	rec->a3 = (unsigned long) p;
}

static void sanitise_cec_log_addrs(struct syscallrecord *rec)
{
	struct cec_log_addrs *la;
	unsigned int i;

	la = (struct cec_log_addrs *) get_writable_struct(sizeof(*la));
	if (!la)
		return;
	memset(la, 0, sizeof(*la));

	la->cec_version = RAND_BOOL() ? 0x04 : 0x05;	/* 1.4 or 2.0 */
	la->num_log_addrs = rand() % (CEC_MAX_LOG_ADDRS + 1);
	la->vendor_id = RAND_BOOL() ? CEC_VENDOR_ID_NONE : (rand() & 0xffffff);
	la->flags = rand() & 0x7;	/* known flag bits */

	for (i = 0; i < CEC_MAX_LOG_ADDRS; i++) {
		la->log_addr_type[i] = rand() % (CEC_LOG_ADDR_TYPE_UNREGISTERED + 1);
		la->primary_device_type[i] = rand() % 8;
		la->all_device_types[i] = rand() & 0xff;
	}

	rec->a3 = (unsigned long) la;
}

static void sanitise_cec_event(struct syscallrecord *rec)
{
	struct cec_event *e;

	e = (struct cec_event *) get_writable_struct(sizeof(*e));
	if (!e)
		return;
	memset(e, 0, sizeof(*e));
	rec->a3 = (unsigned long) e;
}

static void sanitise_cec_mode(struct syscallrecord *rec)
{
	__u32 *m;

	m = (__u32 *) get_writable_struct(sizeof(*m));
	if (!m)
		return;
	*m = (rand() & CEC_MODE_INITIATOR_MSK) |
	     (rand() & CEC_MODE_FOLLOWER_MSK);
	rec->a3 = (unsigned long) m;
}

#ifdef CEC_ADAP_G_CONNECTOR_INFO
static void sanitise_cec_connector_info(struct syscallrecord *rec)
{
	struct cec_connector_info *ci;

	ci = (struct cec_connector_info *) get_writable_struct(sizeof(*ci));
	if (!ci)
		return;
	memset(ci, 0, sizeof(*ci));
	rec->a3 = (unsigned long) ci;
}
#endif

static void cec_sanitise(const struct ioctl_group *grp,
			 struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
#ifdef CEC_ADAP_G_CAPS
	case CEC_ADAP_G_CAPS:
		sanitise_cec_caps(rec);
		break;
#endif

#ifdef CEC_ADAP_G_PHYS_ADDR
	case CEC_ADAP_G_PHYS_ADDR:
#endif
#ifdef CEC_ADAP_S_PHYS_ADDR
	case CEC_ADAP_S_PHYS_ADDR:
#endif
#if defined(CEC_ADAP_G_PHYS_ADDR) || defined(CEC_ADAP_S_PHYS_ADDR)
		sanitise_cec_phys_addr(rec);
		break;
#endif

#ifdef CEC_ADAP_G_LOG_ADDRS
	case CEC_ADAP_G_LOG_ADDRS:
#endif
#ifdef CEC_ADAP_S_LOG_ADDRS
	case CEC_ADAP_S_LOG_ADDRS:
#endif
#if defined(CEC_ADAP_G_LOG_ADDRS) || defined(CEC_ADAP_S_LOG_ADDRS)
		sanitise_cec_log_addrs(rec);
		break;
#endif

#ifdef CEC_TRANSMIT
	case CEC_TRANSMIT:
#endif
#ifdef CEC_RECEIVE
	case CEC_RECEIVE:
#endif
#if defined(CEC_TRANSMIT) || defined(CEC_RECEIVE)
		sanitise_cec_msg(rec);
		break;
#endif

#ifdef CEC_DQEVENT
	case CEC_DQEVENT:
		sanitise_cec_event(rec);
		break;
#endif

#ifdef CEC_G_MODE
	case CEC_G_MODE:
#endif
#ifdef CEC_S_MODE
	case CEC_S_MODE:
#endif
#if defined(CEC_G_MODE) || defined(CEC_S_MODE)
		sanitise_cec_mode(rec);
		break;
#endif

#ifdef CEC_ADAP_G_CONNECTOR_INFO
	case CEC_ADAP_G_CONNECTOR_INFO:
		sanitise_cec_connector_info(rec);
		break;
#endif

	default:
		break;
	}
}

static const struct ioctl cec_ioctls[] = {
#ifdef CEC_ADAP_G_CAPS
	IOCTL(CEC_ADAP_G_CAPS),
#endif
#ifdef CEC_ADAP_G_PHYS_ADDR
	IOCTL(CEC_ADAP_G_PHYS_ADDR),
#endif
#ifdef CEC_ADAP_S_PHYS_ADDR
	IOCTL(CEC_ADAP_S_PHYS_ADDR),
#endif
#ifdef CEC_ADAP_G_LOG_ADDRS
	IOCTL(CEC_ADAP_G_LOG_ADDRS),
#endif
#ifdef CEC_ADAP_S_LOG_ADDRS
	IOCTL(CEC_ADAP_S_LOG_ADDRS),
#endif
#ifdef CEC_TRANSMIT
	IOCTL(CEC_TRANSMIT),
#endif
#ifdef CEC_RECEIVE
	IOCTL(CEC_RECEIVE),
#endif
#ifdef CEC_DQEVENT
	IOCTL(CEC_DQEVENT),
#endif
#ifdef CEC_G_MODE
	IOCTL(CEC_G_MODE),
#endif
#ifdef CEC_S_MODE
	IOCTL(CEC_S_MODE),
#endif
#ifdef CEC_ADAP_G_CONNECTOR_INFO
	IOCTL(CEC_ADAP_G_CONNECTOR_INFO),
#endif
};

static const char *const cec_devs[] = {
	"cec",
};

static const struct ioctl_group cec_grp = {
	.name = "cec",
	.devtype = DEV_CHAR,
	.devs = cec_devs,
	.devs_cnt = ARRAY_SIZE(cec_devs),
	.sanitise = cec_sanitise,
	.ioctls = cec_ioctls,
	.ioctls_cnt = ARRAY_SIZE(cec_ioctls),
};

REG_IOCTL_GROUP(cec_grp)
