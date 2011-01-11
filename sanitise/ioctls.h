#include <linux/ioctl.h>
#include <linux/major.h>

#include <linux/agpgart.h>
#include <linux/atmioc.h>
#include <linux/cciss_ioctl.h>
#include <linux/cm4000_cs.h>
#include <linux/dm-ioctl.h>
#include <linux/dn.h>
#include <linux/gigaset_dev.h>
#include <linux/i2o-dev.h>
#include <linux/ipmi.h>
#include <linux/kvm.h>
#include <linux/mmtimer.h>
#include <linux/phantom.h>
#include <linux/pktcdvd.h>
#include <linux/ppdev.h>
#include <linux/rfkill.h>
#include <linux/spi/spidev.h>
#include <linux/sonet.h>
#include <linux/suspend_ioctls.h>
#include <linux/synclink.h>
#include <linux/usb/tmc.h>
#include <linux/uinput.h>
#include <linux/vhost.h>
#include <linux/videodev2.h>
#include <linux/watchdog.h>
#include <mtd/ubi-user.h>
#include <rdma/ib_user_mad.h>

// msm_mdp.h not exported to glibc yet.
#define MSMFB_IOCTL_MAGIC 'm'

struct ioctl {
	char *name;
	unsigned int request;
	void (*sanitise)(
		unsigned long *, unsigned long *, unsigned long *,
		unsigned long *, unsigned long *, unsigned long *);
};

struct ioctl ioctllist[] = {
#include "ioctls/scsi-generic.h"
/*
#include "ioctls/framebuffer.h"
#include "ioctls/console.h"
#include "ioctls/cdrom.h"
#include "ioctls/scsi.h"
#include "ioctls/tty.h"
#include "ioctls/vt.h"
#include "ioctls/socket.h"
#include "ioctls/snd.h"
#include "ioctls/mem.h"
#include "ioctls/sisfb.h"
*/
};

#define NR_IOCTLS sizeof(ioctllist)/sizeof(struct ioctl)
