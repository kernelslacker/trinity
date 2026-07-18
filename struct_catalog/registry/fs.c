/*
 * Filesystem / VFS struct-catalog registrations.
 *
 * Covers file / dir / mount / xattr / quota / poll / io syscalls,
 * the landlock ruleset + rule attrs, the fcntl / landlock_add_rule /
 * quotactl / quotactl_fd discriminator-aware rows and their pools,
 * the iovec fanout (readv, writev, preadv[2], pwritev[2], vmsplice,
 * process_madvise) and the sigset_t rows on signalfd, signalfd4,
 * ppoll, epoll_pwait, epoll_pwait2.
 *
 * Timeout-shaped timespec rows on ppoll, pselect6, io_getevents,
 * io_pgetevents and epoll_pwait2 come along here because the owning
 * syscall's primary subsystem is VFS.
 *
 * The struct_catalog/registry.c composition root wires the array
 * declared here into syscall_struct_arg_groups[].
 */

#include <stddef.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/quota.h>
#include <linux/dqblk_xfs.h>
#include <linux/landlock.h>

#include "config.h"

#ifdef USE_XATTR_ARGS
#include <linux/xattr.h>
#endif

#include "struct_catalog.h"
#include "trinity.h"

#include "kernel/fcntl.h"

/*
 * fcntl arg3 cmd discriminator pools.  Sibling arg a2 (cmd) selects
 * which struct backs the a3 pointer; the discriminator-aware lookup
 * resolves these lists against rec->a2 to pick the right descriptor.
 *
 * fcntl_flock_cmds: every cmd where the kernel reads a struct flock
 * at a3 -- POSIX (F_GETLK / F_SETLK / F_SETLKW), OFD (F_OFD_*) and
 * F_CANCELLK.  The LK64 variants are folded in via the
 * F_GETLK64 != F_GETLK preprocessor gate so 64-bit-clean toolchains
 * (where the LK64 cmd values collapse onto their non-LK64 siblings)
 * don't waste a duplicate-match slot.
 *
 * fcntl_f_owner_ex_cmds: the two cmds where a3 is a struct
 * f_owner_ex pointer.
 */
static const unsigned long fcntl_flock_cmds[] = {
	F_GETLK, F_SETLK, F_SETLKW,
	F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW,
	F_CANCELLK,
#if F_GETLK64 != F_GETLK
	F_GETLK64, F_SETLK64, F_SETLKW64,
#endif
};

static const unsigned long fcntl_f_owner_ex_cmds[] = {
	F_GETOWN_EX, F_SETOWN_EX,
};

/*
 * landlock_add_rule arg3 rule_type discriminator pools.  Sibling arg
 * a2 (rule_type) selects which struct backs the a3 pointer; the
 * discriminator-aware lookup resolves these lists against rec->a2 to
 * pick the right descriptor.
 *
 * landlock_add_rule_path_beneath_rule_types: just
 * LANDLOCK_RULE_PATH_BENEATH (a3 is a struct landlock_path_beneath_attr).
 *
 * landlock_add_rule_net_port_rule_types: just LANDLOCK_RULE_NET_PORT
 * (a3 is a struct landlock_net_port_attr).
 *
 * One-element pools so the registration shape matches the fcntl
 * cmd-discriminator above; new landlock rule_types will land here as
 * additional entries with their own descriptor + pool.
 */
static const unsigned long landlock_add_rule_path_beneath_rule_types[] = {
	LANDLOCK_RULE_PATH_BENEATH,
};

static const unsigned long landlock_add_rule_net_port_rule_types[] = {
	LANDLOCK_RULE_NET_PORT,
};

/*
 * quotactl / quotactl_fd cmd discriminator pools.  Both syscalls pack
 * the cmd into a single arg as QCMD(subcmd, type) (subcmd in the high
 * bits, USRQUOTA / GRPQUOTA / PRJQUOTA / ... type in the low byte),
 * so the discriminator-aware lookup unpacks via the (shift, mask)
 * extension: discrim_shift = SUBCMDSHIFT strips the type byte and
 * leaves the raw subcmd that the kernel switches on, which is what
 * Q_SETQUOTA / Q_SETINFO actually equal.
 *
 * quotactl_if_dqblk_subcmds: just Q_SETQUOTA (a4 / a3 is a struct
 * if_dqblk pointer the kernel reads on dispatch).  Q_GETQUOTA /
 * Q_GETNEXTQUOTA also use if_dqblk at the same slot but they're
 * output-only -- registering them would attribute CMP-learned
 * constants against bytes the kernel wrote rather than bytes we
 * stamped.
 */
static const unsigned long quotactl_if_dqblk_subcmds[] = {
	Q_SETQUOTA,
};

/*
 * quotactl_if_dqinfo_subcmds: just Q_SETINFO (a4 / a3 is a struct
 * if_dqinfo pointer the kernel reads on dispatch).  Q_GETINFO also
 * uses if_dqinfo at the same slot but is output-only -- registering
 * it would attribute CMP-learned constants against bytes the kernel
 * wrote rather than bytes we stamped.
 */
static const unsigned long quotactl_if_dqinfo_subcmds[] = {
	Q_SETINFO,
};

/*
 * quotactl_fs_disk_quota_subcmds: just Q_XSETQLIM (a4 is a struct
 * fs_disk_quota pointer the kernel reads on dispatch under the XFS
 * quota set-limit command).  Q_XGETQUOTA / Q_XGETNEXTQUOTA also use
 * fs_disk_quota at the same slot but they're output-only -- registering
 * them would attribute CMP-learned constants against bytes the kernel
 * wrote rather than bytes we stamped.
 */
static const unsigned long quotactl_fs_disk_quota_subcmds[] = {
	Q_XSETQLIM,
};

const struct syscall_struct_arg struct_catalog_registry_fs[] = {
	/* epoll_ctl(int, int, int, struct epoll_event *) */
	{ "epoll_ctl",		4, &struct_catalog[SC_EPOLL_EVENT] },
	/* landlock_create_ruleset(const struct landlock_ruleset_attr *, size_t, u32) */
	{ "landlock_create_ruleset",	1, &struct_catalog[SC_LANDLOCK_RULESET_ATTR] },
	/* statmount(const struct mnt_id_req *, struct statmount *, size_t, u32) */
	{ "statmount",		1, &struct_catalog[SC_MNT_ID_REQ] },
	/* listmount(const struct mnt_id_req *, u64 *, size_t, u32) */
	{ "listmount",		1, &struct_catalog[SC_MNT_ID_REQ] },
	/*
	 * utimensat(int, const char *, struct timespec[2], int)
	 * utimensat's `utimes` arg is a 2-element timespec array -- the
	 * mapping table has no array semantics, so the entry below names
	 * the single-struct desc and the existing sanitise_utimensat
	 * callback continues to own the 2-element layout.
	 */
	{ "utimensat",		3, &struct_catalog[SC_TIMESPEC] },
	/*
	 * ppoll(struct pollfd *, nfds_t, struct timespec *tsp, const sigset_t *, size_t)
	 * a3 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_ppoll / ppoll_post_state in syscalls/poll.c continues to
	 * own the live fill; this row only lets schema-aware CMP attribution
	 * name the tv_sec / tv_nsec fields.  ppoll's a1 (pollfd array) is
	 * mapped to SC_POLLFD below and is unaffected.
	 */
	{ "ppoll",		3, &struct_catalog[SC_TIMESPEC] },
	/*
	 * pselect6(int n, fd_set *inp, fd_set *outp, fd_set *exp,
	 *          struct timespec *tsp, void *sig)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_pselect6 (allocs the timespec via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a6 (sig, a
	 * packed { sigset_t *, size_t } pointer) is not a timespec and is
	 * intentionally unregistered here.
	 */
	{ "pselect6",		5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * io_getevents(aio_context_t ctx_id, long min_nr, long nr,
	 *              struct io_event *events, struct timespec *timeout)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_io_getevents (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "io_getevents",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
	 *              struct timespec *timeout, const sigset_t *sigmask,
	 *              size_t sigsetsize)
	 * a4 is the INPUT timeout timespec (epoll_pwait2 takes a timespec*
	 * where epoll_pwait took an int ms).  Attribution-only: the bespoke
	 * sanitise_epoll_pwait2 / pick_timespec (stamps the slot via
	 * get_writable_struct) continues to own the live fill; this row only
	 * lets schema-aware CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "epoll_pwait2",	4, &struct_catalog[SC_TIMESPEC] },
	/*
	 * io_pgetevents(aio_context_t ctx_id, long min_nr, long nr,
	 *               struct io_event *events, struct timespec *timeout,
	 *               const struct __aio_sigset *usig)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_io_pgetevents (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "io_pgetevents",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * cachestat(unsigned int fd, struct cachestat_range *cstat_range,
	 *           struct cachestat *cstat, unsigned int flags)
	 * Maps the INPUT cstat_range arg only; cstat is the kernel-written
	 * output and is intentionally not registered.  Attribution-only:
	 * sanitise_cachestat / pick_range continues to own the live fill.
	 */
	{ "cachestat",		2, &struct_catalog[SC_CACHESTAT_RANGE] },
	/*
	 * mount_setattr(int dfd, const char *path, unsigned int flags,
	 *               struct mount_attr *uattr, size_t usize)
	 * open_tree_attr(int dfd, const char *filename, unsigned int flags,
	 *                struct mount_attr *uattr, size_t usize)
	 * Both a4 slots are ARG_STRUCT_PTR_IN, but the bespoke sanitisers
	 * (build_mount_attr / sanitise_mount_setattr) overwrite rec->a4
	 * after the schema-aware fill -- attribution-only registration so
	 * struct_field_for_cmp can steer CMP-learned constants at the
	 * named fields.  The curated bespoke fill stays live.
	 */
	{ "mount_setattr",	4, &struct_catalog[SC_MOUNT_ATTR] },
	{ "open_tree_attr",	4, &struct_catalog[SC_MOUNT_ATTR] },
	/*
	 * pollfd is an array slot on ARG_ADDRESS at a1 of both poll and
	 * ppoll; the per-element type is named here so future schema
	 * consumers and struct_field_for_cmp can resolve it.  The bespoke
	 * alloc_pollfds() owns the live (nfds, fd, events) layout.
	 */
	{ "poll",		1, &struct_catalog[SC_POLLFD] },
	{ "ppoll",		1, &struct_catalog[SC_POLLFD] },
	/*
	 * openat2(int dfd, const char *filename, struct open_how *how,
	 *         size_t usize)
	 * a3 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_openat2 / build_csfu_struct path keeps owning the
	 * live (flags, mode, resolve) layout and the usize bucket
	 * distribution.  Attribution-only registration lets
	 * struct_field_for_cmp steer CMP-learned constants at the named
	 * flags / resolve slot.
	 */
	{ "openat2",		3, &struct_catalog[SC_OPEN_HOW] },
	/*
	 * open_by_handle_at(int mountdirfd, struct file_handle *handle, int flags)
	 * a2 (1-indexed) is the file_handle.  Schema-fill produces a coherent
	 * (handle_bytes, handle_type) pair and exercises the kernel's
	 * handle_bytes bounds check when fuzzed past the sized buffer.
	 */
	{ "open_by_handle_at",	2, &struct_catalog[SC_FILE_HANDLE] },
	/*
	 * utime(const char *filename, const struct utimbuf __user *times)
	 * a2 is the INPUT struct utimbuf pointer.  utime has no bespoke
	 * .sanitise -- the slot previously fell through ARG_ADDRESS with no
	 * schema-aware fill.  argtype[1] is now ARG_STRUCT_PTR_IN so the
	 * times buffer lands on a dedicated sized buffer; the catalog entry
	 * also lets struct_field_for_cmp steer CMP-learned constants at the
	 * named actime / modtime slots rather than at a coincidentally-
	 * same-width slot.
	 */
	{ "utime",		2, &struct_catalog[SC_UTIMBUF] },
	/*
	 * fcntl(int fd, int cmd, ... arg): a3 is cmd-discriminated between
	 * struct flock (fcntl_flock_cmds pool) and struct f_owner_ex
	 * (fcntl_f_owner_ex_cmds pool).  Both attribution-only; bespoke
	 * sanitise_fcntl() owns the live fill.  Unlisted cmds resolve NULL.
	 * See Documentation/struct_catalog.md.
	 */
	{
		"fcntl", 3, &struct_catalog[SC_FLOCK],
		.discrim_arg_idx	= 2,
		.discrim_values		= fcntl_flock_cmds,
		.num_discrim_values	= ARRAY_SIZE(fcntl_flock_cmds),
	},
	{
		"fcntl", 3, &struct_catalog[SC_F_OWNER_EX],
		.discrim_arg_idx	= 2,
		.discrim_values		= fcntl_f_owner_ex_cmds,
		.num_discrim_values	= ARRAY_SIZE(fcntl_f_owner_ex_cmds),
	},
	/*
	 * timeval slots on select a5 (INOUT remaining-time), futimesat a3
	 * (INPUT timeval[2], first-elem only), utimes a2 (INPUT
	 * timeval[2], first-elem only).  All attribution-only; bespoke
	 * sanitisers own the live fill.  See Documentation/struct_catalog.md.
	 */
	{ "select",		5, &struct_catalog[SC_TIMEVAL] },
	{ "futimesat",		3, &struct_catalog[SC_TIMEVAL] },
	{ "utimes",		2, &struct_catalog[SC_TIMEVAL] },
	/*
	 * listns(const struct ns_id_req __user *req, u64 __user *ns_ids,
	 *        size_t nr_ns_ids, unsigned int flags)
	 * a1 is the INPUT struct ns_id_req pointer.  sanitise_listns()
	 * keeps owning the live fill via build_csfu_struct(&desc_listns)
	 * -- the csfu path stamps the versioned size word and the
	 * subsequent ns_type / ns_id / user_ns_id pickers populate the
	 * remaining slots.  Attribution-only registration lets
	 * struct_field_for_cmp steer CMP-learned constants at the named
	 * size / ns_type / ns_id / user_ns_id slots, with ns_type masked
	 * to the eight defined CLONE_NEW* selector bits.
	 */
	{ "listns",		1, &struct_catalog[SC_NS_ID_REQ] },
#ifdef USE_XATTR_ARGS
	/*
	 * setxattrat(int dfd, const char __user *pathname,
	 *            unsigned int at_flags, const char __user *name,
	 *            const struct xattr_args __user *uargs, size_t usize)
	 * getxattrat(int dfd, const char __user *pathname,
	 *            unsigned int at_flags, const char __user *name,
	 *            struct xattr_args __user *uargs, size_t usize)
	 * a5 is the INPUT struct xattr_args pointer in both cases (the
	 * kernel reads value / size / flags before any sub-buffer access
	 * even for getxattrat).  sanitise_{set,get}xattrat() keep owning
	 * the live fill via build_csfu_struct(&desc_{set,get}xattrat) and
	 * the in-line value/size/flags picker; attribution-only
	 * registration lets struct_field_for_cmp steer CMP-learned
	 * constants at the named value / size / flags slots, with flags
	 * masked to XATTR_CREATE | XATTR_REPLACE.
	 */
	{ "setxattrat",		5, &struct_catalog[SC_XATTR_ARGS] },
	{ "getxattrat",		5, &struct_catalog[SC_XATTR_ARGS] },
#endif
	/*
	 * file_setattr(int dfd, const char __user *filename,
	 *              struct file_attr __user *ufattr, size_t usize,
	 *              unsigned int at_flags)
	 * a3 is the INPUT struct file_attr pointer.  The bespoke
	 * sanitise_file_setattr() keeps owning the live fill via
	 * build_csfu_struct(&desc_file_setattr) and the curated
	 * FS_XFLAG_* pool picker; this registration is attribution-only
	 * so struct_field_for_cmp can steer CMP-learned constants at
	 * the named fa_xflags / fa_extsize / fa_nextents / fa_projid /
	 * fa_cowextsize slots rather than at a coincidentally-same-
	 * width slot.
	 *
	 * Not mapped here on purpose: file_getattr's a2 buffer is a
	 * kernel-written OUTPUT and has no input fill to attribute
	 * against.
	 */
	{ "file_setattr",	3, &struct_catalog[SC_FILE_ATTR] },
	/*
	 * landlock_add_rule a3: rule_type-discriminated between
	 * struct landlock_path_beneath_attr (LANDLOCK_RULE_PATH_BENEATH)
	 * and struct landlock_net_port_attr (LANDLOCK_RULE_NET_PORT).
	 * Both attribution-only; bespoke sanitise_landlock_add_rule()
	 * owns the live fill.  Unlisted rule_types resolve NULL.
	 * See Documentation/struct_catalog.md.
	 */
	{
		"landlock_add_rule", 3,
		&struct_catalog[SC_LANDLOCK_PATH_BENEATH_ATTR],
		.discrim_arg_idx	= 2,
		.discrim_values		= landlock_add_rule_path_beneath_rule_types,
		.num_discrim_values	= ARRAY_SIZE(landlock_add_rule_path_beneath_rule_types),
	},
	{
		"landlock_add_rule", 3,
		&struct_catalog[SC_LANDLOCK_NET_PORT_ATTR],
		.discrim_arg_idx	= 2,
		.discrim_values		= landlock_add_rule_net_port_rule_types,
		.num_discrim_values	= ARRAY_SIZE(landlock_add_rule_net_port_rule_types),
	},
	/*
	 * quotactl / quotactl_fd a4 (addr): struct if_dqblk under
	 * Q_SETQUOTA.  Packed cmd: rec->a1 (quotactl) / rec->a2
	 * (quotactl_fd) is QCMD(subcmd, type); discrim_shift =
	 * SUBCMDSHIFT strips the type byte before the match.
	 * Attribution-only; bespoke sanitisers own the live fill.
	 * Q_GET* not mapped (output-only).  Unlisted subcmds resolve
	 * NULL.  See Documentation/struct_catalog.md.
	 */
	{
		"quotactl", 4, &struct_catalog[SC_IF_DQBLK],
		.discrim_arg_idx	= 1,
		.discrim_values		= quotactl_if_dqblk_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqblk_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	{
		"quotactl_fd", 4, &struct_catalog[SC_IF_DQBLK],
		.discrim_arg_idx	= 2,
		.discrim_values		= quotactl_if_dqblk_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqblk_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	/*
	 * if_dqinfo sibling of the if_dqblk registration above: the same
	 * addr slot (quotactl a4 / quotactl_fd a4) is a struct if_dqinfo
	 * pointer under Q_SETINFO.  Same packed-discriminator extraction
	 * (discrim_shift = SUBCMDSHIFT) and same attribution-only shape
	 * as the if_dqblk pair -- the bespoke sanitisers own the live
	 * dqi_bgrace / dqi_igrace fill; this entry only steers
	 * struct_field_for_cmp().  Q_GETINFO uses if_dqinfo at the same
	 * slot but is output-only, so the pool stays at just Q_SETINFO.
	 */
	{
		"quotactl", 4, &struct_catalog[SC_IF_DQINFO],
		.discrim_arg_idx	= 1,
		.discrim_values		= quotactl_if_dqinfo_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqinfo_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	{
		"quotactl_fd", 4, &struct_catalog[SC_IF_DQINFO],
		.discrim_arg_idx	= 2,
		.discrim_values		= quotactl_if_dqinfo_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqinfo_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	/*
	 * fs_disk_quota sibling of the if_dqblk / if_dqinfo registrations
	 * above: the same addr slot (quotactl a4 / quotactl_fd a4) is a
	 * struct fs_disk_quota pointer under Q_XSETQLIM (the XFS quota
	 * set-limit command).  Same packed-discriminator extraction
	 * (discrim_shift = SUBCMDSHIFT) and same attribution-only shape
	 * as the if_dqblk / if_dqinfo pairs -- the bespoke sanitisers
	 * own the live fill; this entry only steers
	 * struct_field_for_cmp().  Q_XGETQUOTA / Q_XGETNEXTQUOTA use
	 * fs_disk_quota at the same slot but are output-only, so the
	 * pool stays at just Q_XSETQLIM.
	 */
	{
		"quotactl", 4, &struct_catalog[SC_FS_DISK_QUOTA],
		.discrim_arg_idx	= 1,
		.discrim_values		= quotactl_fs_disk_quota_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_fs_disk_quota_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	{
		"quotactl_fd", 4, &struct_catalog[SC_FS_DISK_QUOTA],
		.discrim_arg_idx	= 2,
		.discrim_values		= quotactl_fs_disk_quota_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_fs_disk_quota_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	/*
	 * io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,
	 *           struct io_event __user *result)
	 * a2 is the INPUT struct iocb pointer.  sanitise_io_cancel() owns
	 * the live fill (memset, opcode = IOCB_CMD_PREAD, fd from
	 * get_random_fd(), aio_buf via get_writable_address, optional pool
	 * pin from OBJ_AIO_IOCB) and overwrites rec->a2 wholesale.
	 * Attribution-only registration lets struct_field_for_cmp steer
	 * KCOV-CMP learned constants at the named opcode / flags / fd
	 * slots rather than at a coincidentally-same-width slot.
	 *
	 * Not registered here on purpose: io_submit's a3 is
	 * `struct iocb __user * __user *` -- an array-of-pointers, the
	 * wrong indirection for a flat single-struct descriptor.  The
	 * io_cancel a2 slot is the real `struct iocb *`.
	 */
	{ "io_cancel",		2, &struct_catalog[SC_IOCB] },
	/*
	 * iovec is an array slot on ARG_IOVEC / ARG_IOVEC_IN at the
	 * vec / iov argument of every iovec-shaped syscall; the per-
	 * element type is named here so future schema consumers and
	 * struct_field_for_cmp() can resolve it.  The bespoke
	 * alloc_iovec() generator owns the live (iov_base, iov_len)
	 * layout, so all rows below are attribution-only.
	 *
	 * readv(int fd, const struct iovec *vec, int vlen)
	 * writev(int fd, const struct iovec *vec, int vlen)
	 * preadv(unsigned long fd, const struct iovec *vec,
	 *        unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
	 * preadv2(..., int flags)
	 * pwritev(unsigned long fd, const struct iovec *vec,
	 *         unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
	 * pwritev2(..., int flags)
	 * vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs,
	 *          unsigned int flags)
	 * process_madvise(int pidfd, const struct iovec *vec, size_t vlen,
	 *                 int behavior, unsigned int flags)
	 */
	{ "readv",		2, &struct_catalog[SC_IOVEC] },
	{ "writev",		2, &struct_catalog[SC_IOVEC] },
	{ "preadv",		2, &struct_catalog[SC_IOVEC] },
	{ "preadv2",		2, &struct_catalog[SC_IOVEC] },
	{ "pwritev",		2, &struct_catalog[SC_IOVEC] },
	{ "pwritev2",		2, &struct_catalog[SC_IOVEC] },
	{ "vmsplice",		2, &struct_catalog[SC_IOVEC] },
	{ "process_madvise",	2, &struct_catalog[SC_IOVEC] },
	/*
	 * signalfd(int ufd, const sigset_t __user *user_mask, size_t sizemask)
	 * signalfd4(int ufd, const sigset_t __user *user_mask, size_t sizemask,
	 *           int flags)
	 * a2 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_signalfd() / sanitise_signalfd4() keep owning the live
	 * fill: a four-way bucketed sigset_t (empty / single RT signal /
	 * classic standard-signal mix / sigfillset minus SIGKILL+SIGSTOP).
	 * Attribution-only registration lets struct_field_for_cmp() steer
	 * CMP-learned constants at the named __val slot rather than at a
	 * coincidentally-same-width neighbour.  SC_SIGSET_T is shared infra
	 * future sigset_t-taking syscalls (e.g. rt_sigsuspend) can reuse.
	 */
	{ "signalfd",		2, &struct_catalog[SC_SIGSET_T] },
	{ "signalfd4",		2, &struct_catalog[SC_SIGSET_T] },
	{ "ppoll",		4, &struct_catalog[SC_SIGSET_T] },
	{ "epoll_pwait",	5, &struct_catalog[SC_SIGSET_T] },
	/*
	 * epoll_pwait2(int epfd, struct epoll_event __user *events,
	 *              int maxevents, const struct timespec __user *timeout,
	 *              const sigset_t __user *sigmask, size_t sigsetsize)
	 * a5 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_epoll_pwait2() keeps owning the live fill via
	 * pick_sigmask().  Attribution-only registration lets
	 * struct_field_for_cmp() steer CMP-learned constants at the named
	 * sigset_t __val slot rather than at a coincidentally-same-width
	 * neighbour.  a4 (timeout) is mapped to SC_TIMESPEC above and is
	 * unaffected.
	 */
	{ "epoll_pwait2",	5, &struct_catalog[SC_SIGSET_T] },
	/* sentinel */
	{ NULL, 0, NULL },
};
