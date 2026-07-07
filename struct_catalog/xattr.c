/*
 * struct_catalog/xattr.c -- xattr_args / file_attr struct field tables.
 *
 * Field tables are `const` (not `static const`) so the spine's
 * .fields=/.variants= references resolve via struct_catalog-internal.h.
 * struct_catalog.h and arch.h are included unconditionally so this TU
 * is never empty when USE_XATTR_ARGS is off.
 *
 * struct file_attr comes from <linux/fs.h> when the system uapi
 * headers are recent enough; include/kernel/fs.h carries a layout-identical
 * fallback under #ifndef FILE_ATTR_SIZE_VER0 plus a fallback
 * FS_XFLAG_HASATTR macro, so both TUs land on the same shape
 * regardless of the build host's vintage.
 */

#include <stddef.h>
#include <linux/fs.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

#ifdef USE_XATTR_ARGS
#include <linux/xattr.h>

#include "kernel/fs.h"
/* ------------------------------------------------------------------ */
/* struct xattr_args (setxattrat, getxattrat)                          */
/* ------------------------------------------------------------------ */

/*
 * struct xattr_args from include/uapi/linux/xattr.h.  Gated on
 * USE_XATTR_ARGS because the build host's uapi headers may predate
 * the addition; mirror the syscalls/{set,get}xattrat.c guard so the
 * translation unit still builds on older headers.  The bespoke
 * sanitisers in those syscall files own the live fill --
 * build_csfu_struct(&desc_{set,get}xattrat) stamps the size word
 * envelope and the in-line picker populates value / size / flags
 * plus the value sub-buffer; this registration layers per-field
 * CMP attribution on top.
 *
 * value is an embedded __aligned_u64 carrying a userspace pointer --
 * FT_ADDRESS mirrors the rseq_cs / robust_list_head treatment so
 * KCOV-CMP learned address constants attribute against it.  size is
 * a free __u32 the kernel reads as the value-buffer bound (FT_RAW).
 * flags carries the XATTR_CREATE / XATTR_REPLACE vocabulary --
 * anything outside the mask is rejected by the VFS before any
 * sub-buffer read, so the mask is the entire useful CMP vocabulary.
 */
const struct struct_field xattr_args_fields[XATTR_ARGS_FIELDS_N] = {
	FIELDX(struct xattr_args, value, FT_ADDRESS,
	       .mutate_weight = 100),
	FIELD(struct xattr_args, size),
	FIELDX(struct xattr_args, flags, FT_FLAGS,
	       .u.flags.mask = (XATTR_CREATE | XATTR_REPLACE),
	       .mutate_weight = 80),
};
#endif

/* ------------------------------------------------------------------ */
/* struct file_attr (file_setattr)                                     */
/* ------------------------------------------------------------------ */

/*
 * struct file_attr from <linux/fs.h> (shimmed in include/kernel/fs.h when
 * the system uapi headers predate the file_getattr/file_setattr
 * addition).  The bespoke sanitise_file_setattr() owns the live fill --
 * build_csfu_struct(&desc_file_setattr) stamps the size word envelope
 * and the in-line xflag picker draws fa_xflags from a curated
 * FS_XFLAG_* pool with an occasional outside-mask leg; this
 * registration layers per-field CMP attribution on top.
 *
 * fa_xflags carries the FS_XFLAG_* vocabulary -- anything outside the
 * mask is bounced by vfs_fileattr_set() on -EINVAL before the kernel
 * reaches the real setattr arms, so the mask is the entire useful CMP
 * vocabulary.  fa_extsize / fa_nextents / fa_projid / fa_cowextsize are
 * free u32 slots the kernel reads as raw values.  Mirrors the
 * attribution-only treatment of timer_create's sigevent, rseq, and
 * xattr_args entries.
 */
#define FILE_ATTR_XFLAGS_MASK						\
	(FS_XFLAG_REALTIME    | FS_XFLAG_PREALLOC    | FS_XFLAG_IMMUTABLE | \
	 FS_XFLAG_APPEND      | FS_XFLAG_SYNC        | FS_XFLAG_NOATIME  | \
	 FS_XFLAG_NODUMP      | FS_XFLAG_RTINHERIT   | FS_XFLAG_PROJINHERIT | \
	 FS_XFLAG_NOSYMLINKS  | FS_XFLAG_EXTSIZE     | FS_XFLAG_EXTSZINHERIT | \
	 FS_XFLAG_NODEFRAG    | FS_XFLAG_FILESTREAM  | FS_XFLAG_DAX      | \
	 FS_XFLAG_COWEXTSIZE  | FS_XFLAG_HASATTR)

const struct struct_field file_attr_fields[FILE_ATTR_FIELDS_N] = {
	FIELDX(struct file_attr, fa_xflags, FT_FLAGS,
	       .u.flags.mask = FILE_ATTR_XFLAGS_MASK,
	       .mutate_weight = 80),
	FIELD(struct file_attr, fa_extsize),
	FIELD(struct file_attr, fa_nextents),
	FIELD(struct file_attr, fa_projid),
	FIELD(struct file_attr, fa_cowextsize),
};
