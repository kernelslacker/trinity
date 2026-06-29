/*
 * struct_catalog/fcntl.c -- fcntl-family struct field tables.
 *
 * Carved out of struct_catalog.c as the eleventh leaf TU of the file
 * split: the central spine (struct_catalog[], syscall_struct_args[])
 * and all logic stay in struct_catalog.c; this TU owns the fcntl
 * leaf data only -- struct flock (fcntl F_*LK / F_OFD_*LK /
 * F_CANCELLK), struct f_owner_ex (fcntl F_GETOWN_EX / F_SETOWN_EX),
 * struct open_how (openat2), and struct file_handle
 * (open_by_handle_at).  Symbols flip from static const to const so
 * the spine's .fields = flock_fields / f_owner_ex_fields /
 * open_how_fields / file_handle_fields references resolve via the
 * externs in struct_catalog-internal.h.
 *
 * struct_catalog.h and arch.h are included unconditionally so this
 * TU is never empty.
 */

#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/types.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct flock (fcntl)                                                */
/* ------------------------------------------------------------------ */

/*
 * fcntl's lock-pointer arg (F_GETLK / F_SETLK / F_SETLKW and the
 * F_OFD_* variants) carries a struct flock at a3.  The bespoke
 * sanitise_fcntl() keeps owning the live fill via build_flock(): it
 * picks an l_type / l_whence vocab member, a bounded l_start and
 * l_len, and zeroes l_pid (F_OFD_SETLK requires it).
 *
 * Attribution-only registration, mirroring the mq_notify / sigevent
 * pattern: struct_field_for_cmp() uses the FT_ENUM tags to steer
 * KCOV-CMP learned constants at l_type (a 3-valued vocab the kernel
 * branches on in posix_lock_inode) and l_whence (a 3-valued vocab the
 * kernel uses to resolve the start offset), and FT_RAW on l_start /
 * l_len / l_pid keeps attribution at the named range / pid slots
 * rather than at a coincidentally-same-width slot.  Without the
 * registration the slot fell through with no schema-aware attribution
 * even though the bespoke sanitiser already produced a plausible
 * payload, so per-field CMP steering at l_type / l_whence had nothing
 * to hang against.
 *
 * Resolution to this descriptor is now gated on the F_*LK / F_OFD_*LK
 * / F_CANCELLK cmds via the discriminator-aware syscall_struct_args[]
 * entry below; for non-lock cmds the kernel doesn't read a struct
 * flock at a3 (it reads an fd or an integer flag word that sanitise_
 * fcntl writes through rec->a3), so attribution at the flock fields
 * would be meaningless.
 */
const unsigned long flock_l_type_values[FLOCK_L_TYPE_VALUES_N] = {
	F_RDLCK, F_WRLCK, F_UNLCK,
};

const unsigned long flock_l_whence_values[FLOCK_L_WHENCE_VALUES_N] = {
	SEEK_SET, SEEK_CUR, SEEK_END,
};

const struct struct_field flock_fields[FLOCK_FIELDS_N] = {
	FIELDX(struct flock, l_type, FT_ENUM,
	       .u.enum_ = { flock_l_type_values,
			    ARRAY_SIZE(flock_l_type_values) },
	       .mutate_weight = 80),
	FIELDX(struct flock, l_whence, FT_ENUM,
	       .u.enum_ = { flock_l_whence_values,
			    ARRAY_SIZE(flock_l_whence_values) },
	       .mutate_weight = 80),
	FIELD(struct flock, l_start),
	FIELD(struct flock, l_len),
	FIELD(struct flock, l_pid),
};

/* ------------------------------------------------------------------ */
/* struct f_owner_ex (fcntl F_GETOWN_EX / F_SETOWN_EX)                 */
/* ------------------------------------------------------------------ */

/*
 * fcntl's a3 for F_GETOWN_EX / F_SETOWN_EX is a pointer to struct
 * f_owner_ex.  The bespoke sanitise_fcntl() keeps owning the live
 * fill: it allocates the buffer via get_writable_struct(), picks
 * type from {F_OWNER_TID, F_OWNER_PID, F_OWNER_PGRP}, and stamps
 * get_pid() into pid before overwriting rec->a3.
 *
 * Attribution-only registration, same shape as the struct flock
 * entry above: struct_field_for_cmp() uses the FT_ENUM tag on type
 * (a 3-valued vocab the kernel branches on in f_setown_ex) to steer
 * KCOV-CMP learned constants at the named slot rather than at a
 * coincidentally-same-width slot.  pid stays FT_RAW: the bespoke
 * sanitiser stamps a getpid()-shaped value and the kernel treats it
 * as an opaque process / thread id with no vocab to attribute
 * against.
 *
 * Resolution to this descriptor is gated on cmd ∈ {F_GETOWN_EX,
 * F_SETOWN_EX} via the discriminator-aware syscall_struct_args[]
 * entry below; this is the first proof of the new mechanism.  Same
 * (name, arg_idx) -> different desc by sibling-arg value -- the
 * existing single-desc table couldn't represent it.
 */
const unsigned long f_owner_ex_type_values[F_OWNER_EX_TYPE_VALUES_N] = {
	F_OWNER_TID, F_OWNER_PID, F_OWNER_PGRP,
};

const struct struct_field f_owner_ex_fields[F_OWNER_EX_FIELDS_N] = {
	FIELDX(struct f_owner_ex, type, FT_ENUM,
	       .u.enum_ = { f_owner_ex_type_values,
			    ARRAY_SIZE(f_owner_ex_type_values) },
	       .mutate_weight = 80),
	FIELD(struct f_owner_ex, pid),
};

/* ------------------------------------------------------------------ */
/* struct open_how (openat2)                                           */
/* ------------------------------------------------------------------ */

/*
 * struct open_how / RESOLVE_* may not be present in every host's
 * <linux/openat2.h>; mirror the trinity-local fallback already used
 * by syscalls/open.c so this TU compiles on toolchains that pre-date
 * the openat2 uapi.  The ifndef guard hands off to the host header
 * (or to whichever earlier-included TU has already pulled the symbols
 * in) when it is present.
 */
#ifndef RESOLVE_NO_XDEV
struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};
#define RESOLVE_NO_XDEV		0x01
#define RESOLVE_NO_MAGICLINKS	0x02
#define RESOLVE_NO_SYMLINKS	0x04
#define RESOLVE_BENEATH		0x08
#define RESOLVE_IN_ROOT		0x10
#define RESOLVE_CACHED		0x20
#endif

/*
 * openat2 passes struct open_how at a3 with a usize at a4
 * (copy_struct_from_user semantics).  The slot is ARG_ADDRESS rather
 * than ARG_STRUCT_PTR_*, so the schema-aware fill path never runs
 * against it -- the bespoke sanitise_openat2() in syscalls/open.c
 * continues to own the live (flags, mode, resolve) layout, including
 * the O_CREAT / __O_TMPFILE-gated mode write and the curated
 * openat2_resolve_combos[] table that walks the namei RESOLVE_*
 * paths the kernel actually branches on.
 *
 * Registration is attribution-only, mirroring pollfd / sembuf above:
 * struct_field_for_cmp() uses the FT_FLAGS tags to steer KCOV-CMP
 * learned constants at the flags or resolve slot rather than at a
 * coincidentally-same-width slot.  mode stays FT_RAW: the kernel
 * only honours it (masked to S_IALLUGO) when O_CREAT / __O_TMPFILE
 * is set, otherwise a non-zero mode trips the -EINVAL gate before
 * any per-bit CMP fires -- no single-field vocab maps cleanly.
 */
#define OPEN_HOW_FLAGS_MASK						\
	(O_ACCMODE | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_APPEND |	\
	 O_NONBLOCK | O_DSYNC | O_SYNC | O_ASYNC | O_DIRECTORY |	\
	 O_NOFOLLOW | O_CLOEXEC | O_DIRECT | O_NOATIME | O_PATH |	\
	 O_LARGEFILE | O_TMPFILE)

#define OPEN_HOW_RESOLVE_MASK						\
	(RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS |\
	 RESOLVE_BENEATH | RESOLVE_IN_ROOT | RESOLVE_CACHED)

const struct struct_field open_how_fields[OPEN_HOW_FIELDS_N] = {
	FIELDX(struct open_how, flags, FT_FLAGS,
	       .u.flags.mask = OPEN_HOW_FLAGS_MASK,
	       .mutate_weight = 100),
	FIELD(struct open_how, mode),
	FIELDX(struct open_how, resolve, FT_FLAGS,
	       .u.flags.mask = OPEN_HOW_RESOLVE_MASK,
	       .mutate_weight = 80),
};

/* ------------------------------------------------------------------ */
/* struct file_handle (open_by_handle_at)                              */
/* ------------------------------------------------------------------ */

/*
 * open_by_handle_at's a2 is a struct file_handle followed by a
 * variable-length opaque f_handle[] payload.  Catalog the two leading
 * scalar fields so the schema-aware fill produces coherent
 * (handle_bytes, handle_type) values and KCOV-CMP learned constants
 * land at the named slot rather than at a coincidentally-same-width
 * offset in the surrounding opaque buffer.  The flexible tail is
 * intentionally omitted: a fuzzed handle_bytes greater than the sized
 * buffer exercises the kernel's bounds check.
 */
const struct struct_field file_handle_fields[FILE_HANDLE_FIELDS_N] = {
	FIELD(struct file_handle, handle_bytes),
	FIELD(struct file_handle, handle_type),
};
