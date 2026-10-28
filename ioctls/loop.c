/* /dev/loopN block device and /dev/loop-control ioctl fuzzing */

#include <linux/ioctl.h>
#include <linux/loop.h>
#include <linux/major.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "scratch_block.h"
#include "shm.h"
#include "utils.h"

#include "kernel/memfd.h"
/*
 * Cached memfd used as a backing file for LOOP_CONFIGURE.  Opened
 * lazily on first use per child; the kernel takes its own reference
 * once the loop device is configured, so leaking this fd at child
 * exit is harmless.  Returns -1 if memfd_create() is unavailable
 * (e.g. CONFIG_MEMFD_CREATE=n or sandboxed), in which case the
 * caller leaves rec->a3 untouched and falls back to fuzzed bytes.
 */
static int loop_backing_fd(void)
{
	static int fd = -1;

	if (fd >= 0)
		return fd;

	fd = memfd_create("trinity-loop-backing", MFD_CLOEXEC);
	if (fd < 0)
		return -1;

	/* Give it some size so the loop device has something to map. */
	if (ftruncate(fd, 1UL << 20) < 0) {
		close(fd);
		fd = -1;
		return -1;
	}
	return fd;
}

/*
 * /dev/loopN block devices live on LOOP_MAJOR (7).  Match block fds by
 * major rather than by devname so we don't fire LOOP_* ioctls at other
 * block drivers that happen to share a name prefix.  /dev/loop-control
 * is a separate misc char device and gets its own group below.
 */

static const struct ioctl loop_dev_ioctls[] = {
#ifdef LOOP_SET_FD
	IOCTL(LOOP_SET_FD),
#endif
#ifdef LOOP_CLR_FD
	IOCTL(LOOP_CLR_FD),
#endif
#ifdef LOOP_SET_STATUS
	IOCTL(LOOP_SET_STATUS),
#endif
#ifdef LOOP_GET_STATUS
	IOCTL(LOOP_GET_STATUS),
#endif
#ifdef LOOP_SET_STATUS64
	IOCTL(LOOP_SET_STATUS64),
#endif
#ifdef LOOP_GET_STATUS64
	IOCTL(LOOP_GET_STATUS64),
#endif
#ifdef LOOP_SET_CAPACITY
	IOCTL(LOOP_SET_CAPACITY),
#endif
#ifdef LOOP_SET_DIRECT_IO
	IOCTL(LOOP_SET_DIRECT_IO),
#endif
#ifdef LOOP_SET_BLOCK_SIZE
	IOCTL(LOOP_SET_BLOCK_SIZE),
#endif
#ifdef LOOP_CONFIGURE
	IOCTL(LOOP_CONFIGURE),
#endif
};

#ifdef LOOP_CONFIGURE
static void sanitise_loop_configure(struct syscallrecord *rec)
{
	static const __u32 block_sizes[] = { 512, 1024, 2048, 4096 };
	struct loop_config *cfg;
	int backing;

	backing = loop_backing_fd();
	if (backing < 0)
		return;

	cfg = (struct loop_config *) get_writable_struct(sizeof(*cfg));
	if (!cfg)
		return;
	memset(cfg, 0, sizeof(*cfg));
	cfg->fd = backing;
	cfg->block_size = block_sizes[rnd_modulo_u32(ARRAY_SIZE(block_sizes))];
	cfg->info.lo_flags = rand32() & LOOP_CONFIGURE_SETTABLE_FLAGS;
	cfg->info.lo_offset = RAND_BOOL() ? 0 : rand32();
	cfg->info.lo_sizelimit = RAND_BOOL() ? 0 : rand32();
	rec->a3 = (unsigned long) cfg;
}
#endif

#ifdef LOOP_SET_STATUS64
/*
 * True when @fd is a handle on one of the scratch pool's loop devices.
 * Matched on the device node's inode rather than the fd number: the
 * inherited fd, a dup of it and a fresh open of the node all reach the
 * same device.
 */
static bool is_scratch_loop(int fd)
{
	struct stat st, node;
	unsigned int i;

	if (fstat(fd, &st) < 0)
		return false;

	/* A slot that holds no loop reads loop_num -1 (create_shm(), the
	 * tmpfs entry, teardown), so the array can be walked in full. */
	for (i = 0; i < SCRATCH_BLOCK_MAX; i++) {
		const struct scratch_block_entry *e =
			&shm->isolation.scratch_block[i];

		if (e->loop_num >= 0 && stat(e->dev_path, &node) == 0 &&
		    node.st_dev == st.st_dev && node.st_ino == st.st_ino)
			return true;
	}
	return false;
}

/*
 * @scratch: the write is aimed at a scratch loop.  loop_set_status()
 * replaces the device's LO_FLAGS_AUTOCLEAR with the bit in this struct,
 * and fds/scratch_block.c relies on the flag to have the kernel unbind
 * the loop on its last close when SIGKILL keeps the parent from tearing
 * it down.  Every child holds a writable fd on those loops, so the bit
 * stays set.
 */
static void sanitise_loop_set_status64(struct syscallrecord *rec, bool scratch)
{
	struct loop_info64 *info;

	info = (struct loop_info64 *) get_writable_struct(sizeof(*info));
	if (!info)
		return;
	memset(info, 0, sizeof(*info));
	info->lo_flags = rand32() & LOOP_SET_STATUS_SETTABLE_FLAGS;
	if (scratch)
		info->lo_flags |= LO_FLAGS_AUTOCLEAR;
	info->lo_offset = RAND_BOOL() ? 0 : rand32();
	info->lo_sizelimit = RAND_BOOL() ? 0 : rand32();
	rec->a3 = (unsigned long) info;
}
#endif

static void loop_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
#ifdef LOOP_CONFIGURE
	case LOOP_CONFIGURE:
		sanitise_loop_configure(rec);
		break;
#endif
#ifdef LOOP_SET_STATUS64
	case LOOP_SET_STATUS64:
		sanitise_loop_set_status64(rec, is_scratch_loop((int) rec->a1));
		break;
#ifdef LOOP_SET_STATUS
	case LOOP_SET_STATUS:
		/*
		 * The struct loop_info it takes is not built here, and the
		 * same write is a LOOP_SET_STATUS64 away: send it that way
		 * when it would reach a scratch loop.
		 */
		if (is_scratch_loop((int) rec->a1)) {
			rec->a2 = LOOP_SET_STATUS64;
			sanitise_loop_set_status64(rec, true);
		}
		break;
#endif
#endif
	default:
		break;
	}
}

static const struct ioctl loop_ctrl_ioctls[] = {
#ifdef LOOP_CTL_ADD
	IOCTL(LOOP_CTL_ADD),
#endif
#ifdef LOOP_CTL_REMOVE
	IOCTL(LOOP_CTL_REMOVE),
#endif
#ifdef LOOP_CTL_GET_FREE
	IOCTL(LOOP_CTL_GET_FREE),
#endif
};

static const char *const loop_ctrl_devs[] = {
	"loop-control",
};

static const struct ioctl_group loop_ctrl_grp = {
	.name = "loop-control",
	.devtype = DEV_MISC,
	.devs = loop_ctrl_devs,
	.devs_cnt = ARRAY_SIZE(loop_ctrl_devs),
	.sanitise = pick_random_ioctl,
	.ioctls = loop_ctrl_ioctls,
	.ioctls_cnt = ARRAY_SIZE(loop_ctrl_ioctls),
};

REG_IOCTL_GROUP(loop_ctrl_grp)

static int loop_fd_test(int fd __attribute__((unused)),
			const struct stat *st)
{
	if (!S_ISBLK(st->st_mode))
		return -1;
	if (major(st->st_rdev) != LOOP_MAJOR)
		return -1;
	return 0;
}

static const char *const loop_devs[] = {
	"loop",
};

static const struct ioctl_group loop_grp = {
	.name = "loop",
	.devtype = DEV_BLOCK,
	.devs = loop_devs,
	.devs_cnt = ARRAY_SIZE(loop_devs),
	.fd_test = loop_fd_test,
	.sanitise = loop_sanitise,
	.cmd_held = true,
	.ioctls = loop_dev_ioctls,
	.ioctls_cnt = ARRAY_SIZE(loop_dev_ioctls),
};

REG_IOCTL_GROUP(loop_grp)
