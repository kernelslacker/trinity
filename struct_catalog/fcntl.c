/*
 * struct_catalog/fcntl.c -- fcntl-family struct field tables.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` references resolve via the externs in struct_catalog-internal.h.
 * struct_catalog.h and arch.h are #included unconditionally so this TU is
 * never empty.
 */

#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

#include "kernel/fcntl.h"
/* ------------------------------------------------------------------ */
/* struct flock (fcntl)                                                */
/* ------------------------------------------------------------------ */

/*
 * fcntl's lock-pointer arg (F_GETLK / F_SETLK / F_SETLKW and the
 * F_OFD_* variants) carries a struct flock at a3.  The get cmds
 * (F_GETLK, F_OFD_GETLK) pass the generated buffer to the kernel; for
 * the set cmds sanitise_fcntl() builds its own via build_flock(): it
 * picks an l_type / l_whence vocab member, a bounded l_start and
 * l_len, and zeroes l_pid (F_OFD_SETLK requires it).  The FT_ENUM tags
 * draw l_type (a 3-valued vocab the kernel branches on in
 * posix_lock_inode) and l_whence (a 3-valued vocab the kernel uses to
 * resolve the start offset) from their legal sets.
 *
 * Resolution to this descriptor is gated on the F_*LK / F_OFD_*LK /
 * F_CANCELLK cmds via the discriminator-aware syscall_struct_args[]
 * entry; for non-lock cmds the kernel doesn't read a struct flock at
 * a3 (it reads an fd or an integer flag word that sanitise_fcntl
 * writes through rec->a3).
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
 * f_owner_ex.  F_GETOWN_EX writes it, so the generated buffer is only
 * a sized output slot; for F_SETOWN_EX sanitise_fcntl() allocates its
 * own via get_writable_struct(), picks type from {F_OWNER_TID,
 * F_OWNER_PID, F_OWNER_PGRP}, and stamps get_pid() into pid before
 * overwriting rec->a3.  The FT_ENUM tag draws type (a 3-valued vocab
 * the kernel branches on in f_setown_ex) from its legal set; pid
 * stays FT_RAW, an opaque process / thread id.
 *
 * Resolution to this descriptor is gated on cmd in {F_GETOWN_EX,
 * F_SETOWN_EX} via the discriminator-aware syscall_struct_args[]
 * entry: same (name, arg_idx) -> different desc by sibling-arg value,
 * which the single-desc table couldn't represent.
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
/* struct file_handle (open_by_handle_at)                              */
/* ------------------------------------------------------------------ */

/*
 * open_by_handle_at's a2 is a struct file_handle followed by a
 * variable-length opaque f_handle[] payload.  Catalog the two leading
 * scalar fields so the schema-aware fill produces coherent
 * (handle_bytes, handle_type) values.  The flexible tail is
 * intentionally omitted: a fuzzed handle_bytes greater than the sized
 * buffer exercises the kernel's bounds check.
 */
const struct struct_field file_handle_fields[FILE_HANDLE_FIELDS_N] = {
	FIELD(struct file_handle, handle_bytes),
	FIELD(struct file_handle, handle_type),
};
