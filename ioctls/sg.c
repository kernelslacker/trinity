/* SCSI generic (/dev/sg*) ioctl fuzzing */

#include <linux/ioctl.h>
#include <scsi/sg.h>

#include <limits.h>
#include <stdlib.h>

#include "arch.h"		// page_size
#include "ioctls.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "utils.h"

/*
 * /dev/sg* are real character device nodes.  The sg driver registers
 * its own char-major (typically 21) and shows up in /proc/devices as
 * "sg", so the devtype/devs[] match path is reliable -- no fd_test
 * needed.
 *
 * Note: the existing ioctls/scsi.c group dispatches the same SG_*
 * cmds but only against /dev/sd* and /dev/sr* (DEV_BLOCK).  Issuing
 * them through an actual sg char fd exercises the dedicated
 * drivers/scsi/sg.c entry points (sg_ioctl, sg_new_write, sg_read,
 * the per-fd Sg_fd state machine) that the block-layer pass-through
 * never touches.
 *
 * SG_GET_ACCESS_COUNT (0x2289) is documented in the kernel sg driver
 * but absent from older glibc <scsi/sg.h>; defined locally to keep
 * the build green on stale build hosts.
 *
 * SG_SCSI_RESET is intentionally omitted: with a fuzzed arg it can
 * trivially issue SG_SCSI_RESET_BUS or SG_SCSI_RESET_HOST and brick
 * the test target's SCSI controller.
 */

#ifndef SG_GET_ACCESS_COUNT
#define SG_GET_ACCESS_COUNT 0x2289
#endif

static const struct ioctl sg_ioctls[] = {
#ifdef SG_SET_TIMEOUT
	IOCTL(SG_SET_TIMEOUT),
#endif
#ifdef SG_GET_TIMEOUT
	IOCTL(SG_GET_TIMEOUT),
#endif
#ifdef SG_EMULATED_HOST
	IOCTL(SG_EMULATED_HOST),
#endif
#ifdef SG_SET_TRANSFORM
	IOCTL(SG_SET_TRANSFORM),
#endif
#ifdef SG_GET_TRANSFORM
	IOCTL(SG_GET_TRANSFORM),
#endif
#ifdef SG_GET_COMMAND_Q
	IOCTL(SG_GET_COMMAND_Q),
#endif
#ifdef SG_SET_COMMAND_Q
	IOCTL(SG_SET_COMMAND_Q),
#endif
#ifdef SG_SET_RESERVED_SIZE
	IOCTL(SG_SET_RESERVED_SIZE),
#endif
#ifdef SG_GET_RESERVED_SIZE
	IOCTL(SG_GET_RESERVED_SIZE),
#endif
#ifdef SG_GET_SCSI_ID
	IOCTL(SG_GET_SCSI_ID),
#endif
#ifdef SG_SET_FORCE_LOW_DMA
	IOCTL(SG_SET_FORCE_LOW_DMA),
#endif
#ifdef SG_GET_LOW_DMA
	IOCTL(SG_GET_LOW_DMA),
#endif
#ifdef SG_SET_FORCE_PACK_ID
	IOCTL(SG_SET_FORCE_PACK_ID),
#endif
#ifdef SG_GET_PACK_ID
	IOCTL(SG_GET_PACK_ID),
#endif
#ifdef SG_GET_NUM_WAITING
	IOCTL(SG_GET_NUM_WAITING),
#endif
#ifdef SG_SET_DEBUG
	IOCTL(SG_SET_DEBUG),
#endif
#ifdef SG_GET_SG_TABLESIZE
	IOCTL(SG_GET_SG_TABLESIZE),
#endif
#ifdef SG_GET_VERSION_NUM
	IOCTL(SG_GET_VERSION_NUM),
#endif
#ifdef SG_NEXT_CMD_LEN
	IOCTL(SG_NEXT_CMD_LEN),
#endif
#ifdef SG_IO
	IOCTL(SG_IO),
#endif
#ifdef SG_GET_REQUEST_TABLE
	IOCTL(SG_GET_REQUEST_TABLE),
#endif
#ifdef SG_SET_KEEP_ORPHAN
	IOCTL(SG_SET_KEEP_ORPHAN),
#endif
#ifdef SG_GET_KEEP_ORPHAN
	IOCTL(SG_GET_KEEP_ORPHAN),
#endif
	IOCTL(SG_GET_ACCESS_COUNT),
};

static const char *const sg_devs[] = {
	"sg",
};

/*
 * SG_IO carries a struct sg_io_hdr.  A page of random bytes fails
 * the kernel's first check (interface_id != 'S') before any of the
 * interesting dispatch logic runs, so build a real header that
 * passes that gate and then varies the dxfer direction, length and
 * flags.  Mirrors the SG_IO sanitiser in ioctls/scsi.c so the same
 * code path is exercised regardless of which fd we land on.
 */
struct sg_io_buf {
	sg_io_hdr_t ioh;
	unsigned char data[512];
	unsigned char cmd[12];
	unsigned char sense[252];
};

static void sg_io_sanitise(struct syscallrecord *rec)
{
	struct sg_io_buf *sgio;

	sgio = (struct sg_io_buf *) get_address();

	/* INQUIRY (0x12) with a small allocation length keeps the cmd
	 * structurally valid without depending on target state. */
	sgio->cmd[0] = 0x12;
	sgio->cmd[3] = 0x2;

	sgio->ioh.interface_id = 'S';

	switch (rand() % 4) {
	case 0: sgio->ioh.dxfer_direction = SG_DXFER_NONE;		break;
	case 1: sgio->ioh.dxfer_direction = SG_DXFER_TO_DEV;		break;
	case 2: sgio->ioh.dxfer_direction = SG_DXFER_FROM_DEV;		break;
	case 3: sgio->ioh.dxfer_direction = SG_DXFER_TO_FROM_DEV;	break;
	default: break;
	}

	sgio->ioh.dxferp = sgio->data;

	switch (rand() % 3) {
	case 0: sgio->ioh.dxfer_len = rand() % page_size;		break;
	case 1: sgio->ioh.dxfer_len = (unsigned int) rand32();		break;
	case 2: sgio->ioh.dxfer_len = rand() % 512;			break;
	default: break;
	}

	sgio->ioh.cmdp = sgio->cmd;
	sgio->ioh.cmd_len = 6;
	sgio->ioh.mx_sb_len = sizeof(sgio->sense);
	sgio->ioh.sbp = sgio->sense;
	sgio->ioh.timeout = UINT_MAX;
	sgio->ioh.usr_ptr = NULL;
	sgio->ioh.flags |= SG_FLAG_DIRECT_IO;

	rec->a3 = (unsigned long) sgio;
}

static void sg_sanitise(const struct ioctl_group *grp,
			struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
#ifdef SG_IO
	case SG_IO:
		sg_io_sanitise(rec);
		break;
#endif
	default:
		break;
	}
}

static const struct ioctl_group sg_grp = {
	.name = "sg",
	.devtype = DEV_CHAR,
	.devs = sg_devs,
	.devs_cnt = ARRAY_SIZE(sg_devs),
	.sanitise = sg_sanitise,
	.ioctls = sg_ioctls,
	.ioctls_cnt = ARRAY_SIZE(sg_ioctls),
};

REG_IOCTL_GROUP(sg_grp)
