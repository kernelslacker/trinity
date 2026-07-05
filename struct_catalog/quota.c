/*
 * struct_catalog/quota.c -- quotactl / quotactl_fd per-subcmd struct
 * field tables.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` refs (if_dqblk_fields / if_dqinfo_fields /
 * fs_disk_quota_fields) resolve via the externs in struct_catalog-internal.h.
 * struct_catalog.h and arch.h are #included unconditionally so this TU is
 * never empty.
 */

#include <stddef.h>
#include <linux/quota.h>
#include <linux/dqblk_xfs.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct if_dqblk (quotactl Q_SETQUOTA, quotactl_fd Q_SETQUOTA)       */
/* ------------------------------------------------------------------ */

/*
 * quotactl(cmd, special, id, addr) and quotactl_fd(fd, cmd, id, addr)
 * pass a struct if_dqblk at the addr slot (quotactl a4 / quotactl_fd
 * a4) under Q_SETQUOTA -- the SET path is the input arm where the
 * bytes we stamp actually reach disk-quota code.  The bespoke
 * sanitise_quotactl() / sanitise_quotactl_fd() keep owning the live
 * fill (writable allocation, dqb_bhardlimit / dqb_bsoftlimit drawn
 * from rand32(), dqb_ihardlimit / dqb_isoftlimit bounded to 100000,
 * routed through avoid_shared_buffer_inout()); attribution-only
 * registration lets struct_field_for_cmp() steer CMP-learned
 * constants at the named limit / time / valid slots rather than at a
 * coincidentally-same-width slot.
 *
 * dqb_valid carries the QIF_* mask vocabulary; FT_FLAGS over QIF_ALL
 * keeps CMP attribution against the bits the kernel actually
 * switches on (the bespoke arm leaves the field zero today, so this
 * is purely about which slot a learned constant pegs).
 *
 * Q_GETQUOTA / Q_GETNEXTQUOTA also use if_dqblk at the same slot,
 * but they're output-only -- the bytes we stamp on dispatch don't
 * reach the kernel's quota lookup, only the kernel's write-back
 * touches them.  Register only the SET arm so CMP attribution
 * doesn't fire on output bytes that came from the kernel rather
 * than our fill.
 *
 * Resolution to this descriptor is gated on the Q_SETQUOTA subcmd
 * via the discriminator-aware syscall_struct_args[] entry below,
 * which uses the packed-discriminator (shift, mask) extension to
 * unpack QCMD(subcmd, type) -- rec->a<n> >> SUBCMDSHIFT yields the
 * raw subcmd that the kernel switches on, which is what Q_SETQUOTA
 * actually equals.
 */
const struct struct_field if_dqblk_fields[IF_DQBLK_FIELDS_N] = {
	FIELD(struct if_dqblk, dqb_bhardlimit),
	FIELD(struct if_dqblk, dqb_bsoftlimit),
	FIELD(struct if_dqblk, dqb_curspace),
	FIELD(struct if_dqblk, dqb_ihardlimit),
	FIELD(struct if_dqblk, dqb_isoftlimit),
	FIELD(struct if_dqblk, dqb_curinodes),
	FIELD(struct if_dqblk, dqb_btime),
	FIELD(struct if_dqblk, dqb_itime),
	FIELDX(struct if_dqblk, dqb_valid, FT_FLAGS,
	       .u.flags.mask = QIF_ALL,
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct if_dqinfo (quotactl Q_SETINFO, quotactl_fd Q_SETINFO)        */
/* ------------------------------------------------------------------ */

/*
 * Sibling to the if_dqblk registration above: under Q_SETINFO the
 * same addr slot (quotactl a4 / quotactl_fd a4) is a struct
 * if_dqinfo pointer instead.  The bespoke sanitisers keep owning
 * the live fill (writable allocation, dqi_bgrace / dqi_igrace
 * drawn from a deterministic hour-stride picker, routed through
 * avoid_shared_buffer_inout()); attribution-only registration lets
 * struct_field_for_cmp() steer CMP-learned constants at the named
 * grace / flags / valid slots rather than at a coincidentally-same-
 * width slot.
 *
 * dqi_flags carries the DQF_* vocabulary (DQF_ROOT_SQUASH /
 * DQF_SYS_FILE today); dqi_valid carries the IIF_* vocabulary
 * (IIF_BGRACE / IIF_IGRACE / IIF_FLAGS).  FT_FLAGS keeps CMP
 * attribution against the bits the kernel actually switches on.
 *
 * Q_GETINFO also uses if_dqinfo at the same slot but is output-only
 * (kernel writes the grace fields on dispatch); register only the
 * SET arm so CMP attribution doesn't fire on output bytes.
 *
 * Resolution is gated on the Q_SETINFO subcmd via the discriminator-
 * aware syscall_struct_args[] entry below, using the same packed-
 * discriminator (shift=SUBCMDSHIFT, mask=implicit-~0UL) extension
 * the if_dqblk registration uses.
 */
const struct struct_field if_dqinfo_fields[IF_DQINFO_FIELDS_N] = {
	FIELD(struct if_dqinfo, dqi_bgrace),
	FIELD(struct if_dqinfo, dqi_igrace),
	FIELDX(struct if_dqinfo, dqi_flags, FT_FLAGS,
	       .u.flags.mask = DQF_ROOT_SQUASH | DQF_SYS_FILE,
	       .mutate_weight = 60),
	FIELDX(struct if_dqinfo, dqi_valid, FT_FLAGS,
	       .u.flags.mask = IIF_ALL,
	       .mutate_weight = 60),
};

/* ------------------------------------------------------------------ */
/* struct fs_disk_quota (quotactl Q_XSETQLIM, quotactl_fd Q_XSETQLIM)  */
/* ------------------------------------------------------------------ */

/*
 * XFS-shaped sibling to the if_dqblk / if_dqinfo registrations above:
 * under Q_XSETQLIM the addr slot (quotactl a4 / quotactl_fd a4) is a
 * struct fs_disk_quota pointer instead.  The bespoke
 * sanitise_quotactl() / sanitise_quotactl_fd() keep owning the live
 * fill (writable allocation, limit / id pickers, routed through
 * avoid_shared_buffer_inout()); attribution-only registration lets
 * struct_field_for_cmp() steer CMP-learned constants at the named
 * d_blk_* / d_ino_* / d_rtb_* / d_*timer / d_*warns slots rather
 * than at a coincidentally-same-width slot.
 *
 * d_flags carries the FS_{USER,PROJ,GROUP}_QUOTA vocabulary;
 * d_fieldmask carries the FS_DQ_* mask the kernel switches on to
 * decide which sub-limits to apply.  FT_FLAGS on both keeps CMP
 * attribution against the bits the kernel actually tests.
 *
 * Q_XGETQUOTA / Q_XGETNEXTQUOTA also use fs_disk_quota at the same
 * slot but they're output-only -- the bytes we stamp on dispatch
 * don't reach the kernel's quota lookup, only the kernel's write-back
 * touches them.  Register only the Q_XSETQLIM arm so CMP attribution
 * doesn't fire on output bytes that came from the kernel rather than
 * our fill.
 *
 * Resolution is gated on the Q_XSETQLIM subcmd via the discriminator-
 * aware syscall_struct_args[] entry below, using the same packed-
 * discriminator (shift = SUBCMDSHIFT) extension the if_dqblk / if_dqinfo
 * registrations use.
 */
const struct struct_field fs_disk_quota_fields[FS_DISK_QUOTA_FIELDS_N] = {
	FIELD(struct fs_disk_quota, d_version),
	FIELDX(struct fs_disk_quota, d_flags, FT_FLAGS,
	       .u.flags.mask = FS_USER_QUOTA | FS_PROJ_QUOTA | FS_GROUP_QUOTA,
	       .mutate_weight = 60),
	FIELDX(struct fs_disk_quota, d_fieldmask, FT_FLAGS,
	       .u.flags.mask = FS_DQ_LIMIT_MASK | FS_DQ_TIMER_MASK |
			       FS_DQ_WARNS_MASK | FS_DQ_ACCT_MASK |
			       FS_DQ_BIGTIME,
	       .mutate_weight = 60),
	FIELD(struct fs_disk_quota, d_id),
	FIELD(struct fs_disk_quota, d_blk_hardlimit),
	FIELD(struct fs_disk_quota, d_blk_softlimit),
	FIELD(struct fs_disk_quota, d_ino_hardlimit),
	FIELD(struct fs_disk_quota, d_ino_softlimit),
	FIELD(struct fs_disk_quota, d_bcount),
	FIELD(struct fs_disk_quota, d_icount),
	FIELD(struct fs_disk_quota, d_itimer),
	FIELD(struct fs_disk_quota, d_btimer),
	FIELD(struct fs_disk_quota, d_iwarns),
	FIELD(struct fs_disk_quota, d_bwarns),
	FIELD(struct fs_disk_quota, d_itimer_hi),
	FIELD(struct fs_disk_quota, d_btimer_hi),
	FIELD(struct fs_disk_quota, d_rtbtimer_hi),
	FIELD(struct fs_disk_quota, d_rtb_hardlimit),
	FIELD(struct fs_disk_quota, d_rtb_softlimit),
	FIELD(struct fs_disk_quota, d_rtbcount),
	FIELD(struct fs_disk_quota, d_rtbtimer),
	FIELD(struct fs_disk_quota, d_rtbwarns),
};
