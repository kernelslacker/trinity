/* ATM ioctl group. */

#include <linux/atmdev.h>
#include <linux/atm.h>
#include <linux/sonet.h>
#include <sys/socket.h>

#include "ioctls.h"
#include "net.h"
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
	IOCTL(ATM_ADDPARTY),
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
	.sanitise = pick_random_ioctl,
	.ioctls = atm_ioctls,
	.ioctls_cnt = ARRAY_SIZE(atm_ioctls),
};

REG_IOCTL_GROUP(atm_grp)
