/*
 * hfs_mount_fuzz - crafted-image mount fuzzer for a legacy on-disk
 * filesystem (HFS).  The mount path for less-audited on-disk formats
 * is a coverage-dense surface: hfs_mdb_get() parses a master
 * directory block whose fields (block sizes, extent offsets, catalog
 * / extents btree pointers) are trusted after a single signature
 * check, and hfs_mdb_commit() writes them back on unmount / sync.
 * Neither path is reachable from generic syscall fuzzing.
 *
 * Per invocation:
 *   1. Craft a minimal HFS master directory block (MDB) into a memfd:
 *      valid drSigWord ("BD") plus randomised block sizes / btree
 *      extent records / clump sizes / volume-attribute bits.  A
 *      per-invocation chance also emits a truncated backing (short
 *      write) so hfs_mdb_get sees a partial MDB.
 *   2. Draw a parent-vetted /dev/loop$N from the scratch_block pool
 *      (fds/scratch_block.c) and fork a userns_run_in_ns(CLONE_NEWNS)
 *      grandchild so the mount attempts run under CAP_SYS_ADMIN
 *      scoped to an owned user namespace inside a private mount
 *      namespace -- the persistent fuzz child's credentials and mount
 *      tree are unchanged.
 *   3. Inside the grandchild: try LOOP_SET_FD with the memfd (the
 *      pool's parent-held binding usually EBUSYs the swap and is
 *      counted; the mount attempt still exercises hfs_mdb_get against
 *      whatever bytes the loop already exposes).  Attempt
 *      mount("/dev/loop$N", target, "hfs", flags, options) with a
 *      churned option string ("uid=", "gid=", "umask=", "session=",
 *      "part=", "type=", "creator=", "quiet") drawn from hfs's
 *      parse_options() vocabulary.  On mount success, run a handful
 *      of ops that drive hfs_mdb_commit -- readdir, create, rename,
 *      setattr, sync -- then umount2(MNT_DETACH).
 *
 * Latch policy:
 *   - CHILDOP_LATCH_NS_UNSUPPORTED: userns_run_in_ns returns -EPERM
 *     (kernel refused CLONE_NEWUSER: user.max_user_namespaces=0 or
 *     kernel.unprivileged_userns_clone=0).  Persistent for the child's
 *     lifetime.
 *   - CHILDOP_LATCH_UNSUPPORTED: mount() returned ENODEV inside the
 *     grandchild -- CONFIG_HFS_FS not built into this kernel.  Also
 *     persistent per child; further attempts would burn syscalls.
 *   - CHILDOP_LATCH_RESOURCE_EXHAUSTED: scratch_block loop pool
 *     empty (non-root, --no-startup-isolation, /dev/loop-control
 *     absent, exhausted allocation).  Persistent for the child's
 *     lifetime; the pool is a fork-time singleton.
 *
 * DORMANT in dormant_op_disabled[].  Dave smoke-tests before fleet
 * enable.  On the denylist for the alt_op_rotation[] (image-mount
 * lifecycle over a shared scratch loop; not safe for steady
 * rotation).
 */

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "child.h"
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "scratch_block.h"
#include "shm.h"
#include "syscall-gate.h"
#include "trinity.h"
#include "userns-bootstrap.h"

#if __has_include(<linux/loop.h>)

#include <linux/loop.h>

#include "kernel/fcntl.h"
#include "kernel/memfd.h"
#include "kernel/mount.h"
/* MDB lives at byte offset 1024 (block 2 in 512-byte units) on an HFS
 * volume.  Full struct hfs_mdb is 162 bytes; we round the crafted
 * backing to a small power-of-two so the loop-device size math stays
 * clean. */
#define HFS_MDB_OFFSET		1024U
#define HFS_MDB_SIZE		162U
#define HFS_SUPER_MAGIC		0x4244U		/* "BD" big-endian */

/* Backing-image size band.  512 KiB - 4 MiB is enough to cover MDB
 * + a bit of btree scratch without inflating the memfd. */
#define HFS_IMAGE_MIN		(512U << 10)
#define HFS_IMAGE_MAX		(4U   << 20)

/* Latched per-child: kernel refused CLONE_NEWUSER (helper -EPERM). */
static bool ns_unsupported;
/* Latched per-child: mount("hfs") returned ENODEV -- CONFIG_HFS_FS
 * absent.  Non-latching mount errors (EINVAL, EIO, EBUSY, ...) leave
 * this false so the next invocation retries. */
static bool hfs_unsupported;
/* Latched per-child: scratch_block loop pool empty. */
static bool loop_unsupported;

/* Per-child invocation counter: keeps grandchild-side path names unique. */
static unsigned int hfs_mount_seq;

static void be16_put(unsigned char *p, uint16_t v)
{
	p[0] = (unsigned char)(v >> 8);
	p[1] = (unsigned char)(v & 0xff);
}

static void be32_put(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)((v >> 16) & 0xff);
	p[2] = (unsigned char)((v >> 8) & 0xff);
	p[3] = (unsigned char)(v & 0xff);
}

/*
 * Fill @mdb (HFS_MDB_SIZE bytes) with a churned-but-signature-valid
 * master directory block.  drSigWord is always "BD" so hfs_mdb_get()
 * clears its first check and continues into the field-trust code
 * path we actually want to exercise; every other field is randomised
 * within HFS's declared type width so the trust math (alloc-block
 * size validation, btree extent decode, name-length reads) sees a
 * wide input distribution across invocations.
 */
static void build_hfs_mdb(unsigned char *mdb)
{
	unsigned int i;

	memset(mdb, 0, HFS_MDB_SIZE);

	be16_put(mdb + 0x00, HFS_SUPER_MAGIC);		/* drSigWord */
	be32_put(mdb + 0x02, rand32());			/* drCrDate */
	be32_put(mdb + 0x06, rand32());			/* drLsMod */
	be16_put(mdb + 0x0a, (uint16_t)rand32());	/* drAtrb */
	be16_put(mdb + 0x0c, (uint16_t)rand32());	/* drNmFls */
	be16_put(mdb + 0x0e, (uint16_t)rand32());	/* drVBMSt */
	be16_put(mdb + 0x10, (uint16_t)rand32());	/* drAllocPtr */
	be16_put(mdb + 0x12, (uint16_t)rand32());	/* drNmAlBlks */
	be32_put(mdb + 0x14, rand32());			/* drAlBlkSiz */
	be32_put(mdb + 0x18, rand32());			/* drClpSiz */
	be16_put(mdb + 0x1c, (uint16_t)rand32());	/* drAlBlSt */
	be32_put(mdb + 0x1e, rand32());			/* drNxtCNID */
	be16_put(mdb + 0x22, (uint16_t)rand32());	/* drFreeBks */

	/* drVN Pascal string: length byte + up to 27 name bytes. */
	mdb[0x24] = (unsigned char)rnd_modulo_u32(28U);
	for (i = 0; i < 27U; i++)
		mdb[0x25 + i] = (unsigned char)('A' + (rand32() % 26U));

	be32_put(mdb + 0x40, rand32());			/* drVolBkUp */
	be16_put(mdb + 0x44, (uint16_t)rand32());	/* drVSeqNum */
	be32_put(mdb + 0x46, rand32());			/* drWrCnt */
	be32_put(mdb + 0x4a, rand32());			/* drXTClpSiz */
	be32_put(mdb + 0x4e, rand32());			/* drCTClpSiz */
	be16_put(mdb + 0x52, (uint16_t)rand32());	/* drNmRtDirs */
	be32_put(mdb + 0x54, rand32());			/* drFilCnt */
	be32_put(mdb + 0x58, rand32());			/* drDirCnt */
	for (i = 0; i < 32U; i++)			/* drFndrInfo */
		mdb[0x5c + i] = (unsigned char)rand32();
	be16_put(mdb + 0x7c, (uint16_t)rand32());	/* drEmbedSigWord */
	be32_put(mdb + 0x7e, rand32());			/* drEmbedExtent */
	be32_put(mdb + 0x82, rand32());			/* drXTFlSize */
	for (i = 0; i < 12U; i++)			/* drXTExtRec */
		mdb[0x86 + i] = (unsigned char)rand32();
	be32_put(mdb + 0x92, rand32());			/* drCTFlSize */
	for (i = 0; i < 12U; i++)			/* drCTExtRec */
		mdb[0x96 + i] = (unsigned char)rand32();
}

/*
 * Create a memfd, size it into the HFS_IMAGE_MIN..MAX band, and write
 * the crafted MDB at offset HFS_MDB_OFFSET.  1-in-8 emits a truncated
 * backing (ftruncate to a size that cuts the MDB in half) so
 * hfs_mdb_get sees a short read -- exercises the length-guard path.
 * Returns the memfd on success, -1 on failure; caller closes.
 */
static int hfs_build_image_memfd(void)
{
	unsigned char mdb[HFS_MDB_SIZE];
	unsigned int span = HFS_IMAGE_MAX - HFS_IMAGE_MIN + 1U;
	off_t sz = (off_t)(HFS_IMAGE_MIN + (rand32() % span));
	int fd;

	fd = (int)trinity_raw_syscall(__NR_memfd_create,
				      "trinity-hfs", MFD_CLOEXEC);
	if (fd < 0)
		return -1;

	if (rnd_modulo_u32(8U) == 0U)
		sz = HFS_MDB_OFFSET + (off_t)(HFS_MDB_SIZE / 2U);

	if (ftruncate(fd, sz) < 0) {
		close(fd);
		return -1;
	}

	build_hfs_mdb(mdb);
	{
		ssize_t w __unused__;
		size_t write_len = sizeof(mdb);

		if ((off_t)HFS_MDB_OFFSET + (off_t)write_len > sz)
			write_len = (size_t)(sz - (off_t)HFS_MDB_OFFSET);
		w = pwrite(fd, mdb, write_len, (off_t)HFS_MDB_OFFSET);
	}

	return fd;
}

enum hfs_opt_kind {
	HFS_OPT_INT,		/* single %u / %d integer operand */
	HFS_OPT_OCTAL,		/* %o operand */
	HFS_OPT_FOURCHAR,	/* four ASCII chars */
	HFS_OPT_FLAG,		/* bare keyword, no operand */
};

struct hfs_opt {
	const char       *fmt;
	enum hfs_opt_kind kind;
};

static const struct hfs_opt hfs_opts[] = {
	{ "uid=%u",         HFS_OPT_INT      },
	{ "gid=%u",         HFS_OPT_INT      },
	{ "umask=%o",       HFS_OPT_OCTAL    },
	{ "file_umask=%o",  HFS_OPT_OCTAL    },
	{ "dir_umask=%o",   HFS_OPT_OCTAL    },
	{ "session=%d",     HFS_OPT_INT      },
	{ "part=%d",        HFS_OPT_INT      },
	{ "type=%c%c%c%c",  HFS_OPT_FOURCHAR },
	{ "creator=%c%c%c%c", HFS_OPT_FOURCHAR },
	{ "quiet",          HFS_OPT_FLAG     },
};

/*
 * Build a mount-options string from the hfs parse_options() vocabulary.
 * Emits a comma-separated subset with fuzzed numeric operands so both
 * the token-lookup path (match_token) and the per-token operand
 * decoders (match_int, match_octal, match_fourchar) get exercised.
 * @buf must be at least 128 bytes; result is NUL-terminated.
 */
static void build_hfs_options(char *buf, size_t bufsz)
{
	unsigned int i;
	size_t off = 0;
	int n;

	buf[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(hfs_opts); i++) {
		const struct hfs_opt *o = &hfs_opts[i];

		if (!RAND_BOOL())
			continue;
		if (off && off + 1 < bufsz)
			buf[off++] = ',';

		switch (o->kind) {
		case HFS_OPT_INT:
		case HFS_OPT_OCTAL:
			n = snprintf(buf + off, bufsz - off, o->fmt, rand32());
			break;
		case HFS_OPT_FOURCHAR:
			n = snprintf(buf + off, bufsz - off, o->fmt,
				     'a' + (rand32() % 26U),
				     'a' + (rand32() % 26U),
				     'a' + (rand32() % 26U),
				     'a' + (rand32() % 26U));
			break;
		case HFS_OPT_FLAG:
		default:
			n = snprintf(buf + off, bufsz - off, "%s", o->fmt);
			break;
		}
		if (n <= 0 || (size_t)n >= bufsz - off)
			break;
		off += (size_t)n;
	}
	buf[off] = '\0';
}

/*
 * Drive the mounted HFS volume through operations that push through
 * hfs_mdb_commit on the way back to disk: create a file, setattr,
 * rename, sync, readdir, unlink.  Any per-op failure is silently
 * ignored -- a mount that happened to accept our crafted MDB may
 * still reject writes.
 */
static void hfs_churn_ops(const char *base)
{
	char path_a[PATH_MAX + 128], path_b[PATH_MAX + 128];
	char rdbuf[512];
	ssize_t rc __unused__;
	int fd, dfd;

	dfd = open(base, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd >= 0) {
		rc = syscall(__NR_getdents64, dfd, rdbuf, sizeof(rdbuf));
		close(dfd);
	}

	snprintf(path_a, sizeof(path_a), "%s/a", base);
	snprintf(path_b, sizeof(path_b), "%s/b", base);

	fd = open(path_a, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (fd >= 0) {
		rc = write(fd, "hfs", 3);
		(void)fchmod(fd, 0600);
		(void)fsync(fd);
		close(fd);
	}
	(void)rename(path_a, path_b);
	(void)sync();
	(void)unlink(path_b);
	(void)unlink(path_a);
}

struct hfs_mount_ctx {
	struct childdata *child;
	int loop_num;
	int image_fd;
	bool hit_enodev;
};

/*
 * Grandchild body: run inside (CLONE_NEWUSER | CLONE_NEWNS).  Tries
 * to swap the loop device's backing to our crafted memfd (best-effort
 * -- the parent's binding usually wins the EBUSY race), then attempts
 * mount("hfs") against the loop and drives churn ops on success.
 * Sets ctx->hit_enodev when the kernel reports the fstype is absent
 * so the outer path can latch.  Return value is ignored by
 * userns_run_in_ns().
 */
static int hfs_mount_in_ns(void *arg)
{
	struct hfs_mount_ctx *ctx = (struct hfs_mount_ctx *)arg;
	char loop_path[32];
	char target[PATH_MAX + 64];
	char options[192];
	unsigned int seq = ++hfs_mount_seq;
	int loop_fd;
	bool set_ok = false;
	unsigned long flags = MS_NOSUID | MS_NODEV;

	(void)mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);

	snprintf(loop_path, sizeof(loop_path),
		 "/dev/loop%d", ctx->loop_num);
	loop_fd = open(loop_path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (loop_fd >= 0) {
		set_ok = (ioctl(loop_fd, LOOP_SET_FD,
				(unsigned long)ctx->image_fd) == 0);
		if (set_ok)
			__atomic_add_fetch(&shm->stats.hfs_mount_fuzz.set_fd_ok,
					   1, __ATOMIC_RELAXED);
		else if (errno == EBUSY || errno == ENXIO || errno == EPERM)
			__atomic_add_fetch(&shm->stats.hfs_mount_fuzz.set_fd_busy,
					   1, __ATOMIC_RELAXED);
		close(loop_fd);
	}

	snprintf(target, sizeof(target),
		 "%s/trinity-hfsmount-%d-%u",
		 trinity_tmpdir_abs(), (int)mypid(), seq);
	if (mkdir(target, 0755) != 0)
		return 0;

	if (RAND_BOOL())
		flags |= MS_RDONLY;
	if (RAND_BOOL())
		flags |= MS_NOATIME;
	if (RAND_BOOL())
		flags |= MS_SYNCHRONOUS;

	build_hfs_options(options, sizeof(options));

	if (mount(loop_path, target, "hfs", flags,
		  options[0] ? options : NULL) == 0) {
		__atomic_add_fetch(&shm->stats.hfs_mount_fuzz.mount_ok,
				   1, __ATOMIC_RELAXED);
		hfs_churn_ops(target);
		(void)umount2(target, MNT_DETACH);
	} else {
		if (errno == ENODEV)
			ctx->hit_enodev = true;
		__atomic_add_fetch(&shm->stats.hfs_mount_fuzz.mount_failed,
				   1, __ATOMIC_RELAXED);
	}

	(void)rmdir(target);

	if (set_ok) {
		loop_fd = open(loop_path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
		if (loop_fd >= 0) {
			(void)ioctl(loop_fd, LOOP_CLR_FD);
			close(loop_fd);
		}
	}
	return 0;
}

bool hfs_mount_fuzz(struct childdata *child)
{
	struct hfs_mount_ctx ctx;
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	int rc;

	__atomic_add_fetch(&shm->stats.hfs_mount_fuzz.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported || hfs_unsupported || loop_unsupported)
		return true;

	ctx.child = child;
	ctx.loop_num = scratch_block_random_loop_num();
	ctx.hit_enodev = false;
	if (ctx.loop_num < 0) {
		loop_unsupported = true;
		__atomic_add_fetch(&shm->stats.hfs_mount_fuzz.setup_failed,
				   1, __ATOMIC_RELAXED);
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_RESOURCE_EXHAUSTED,
					 __ATOMIC_RELAXED);
		return true;
	}

	ctx.image_fd = hfs_build_image_memfd();
	if (ctx.image_fd < 0) {
		__atomic_add_fetch(&shm->stats.hfs_mount_fuzz.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	rc = userns_run_in_ns(CLONE_NEWNS, hfs_mount_in_ns, &ctx);
	close(ctx.image_fd);

	if (rc == -EPERM) {
		ns_unsupported = true;
		__atomic_add_fetch(&shm->stats.hfs_mount_fuzz.ns_unsupported,
				   1, __ATOMIC_RELAXED);
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return true;
	}
	if (rc < 0)
		return true;

	if (ctx.hit_enodev) {
		hfs_unsupported = true;
		__atomic_add_fetch(&shm->stats.hfs_mount_fuzz.hfs_unsupported,
				   1, __ATOMIC_RELAXED);
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		return true;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	return true;
}

#else  /* !__has_include(<linux/loop.h>) */

bool hfs_mount_fuzz(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.hfs_mount_fuzz.runs, 1,
			   __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.hfs_mount_fuzz.setup_failed, 1,
			   __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/loop.h>) */
