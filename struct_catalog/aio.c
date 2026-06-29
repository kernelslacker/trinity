/*
 * struct_catalog/aio.c -- aio-shaped struct field tables.
 *
 * Carved out of struct_catalog.c as the tenth leaf TU of the file
 * split: the central spine (struct_catalog[], syscall_struct_args[])
 * and all logic stay in struct_catalog.c; this TU owns the aio leaf
 * data only -- struct iocb (io_cancel) with its IOCB_CMD_* opcode
 * vocab and IOCB_FLAG_* / RWF_* flag masks.  Symbols flip from static
 * const to const so the spine's .fields = iocb_fields reference
 * resolves via the externs in struct_catalog-internal.h.
 *
 * struct_catalog.h and arch.h are included unconditionally so this
 * TU is never empty.  <linux/aio_abi.h> brings struct iocb, the
 * IOCB_CMD_* opcodes, and the IOCB_FLAG_* bits; <linux/fs.h> brings
 * the RWF_* aio_rw_flags vocab.
 */

#include <stddef.h>
#include <linux/aio_abi.h>
#include <linux/fs.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct iocb (io_cancel)                                              */
/* ------------------------------------------------------------------ */

/*
 * IOCB_CMD_* opcode vocabulary for aio_lio_opcode.  The kernel rejects
 * anything outside this set up-front (aio_read_events_ring -> -EINVAL)
 * before any iocb body is consumed, so FT_RAW would burn most splats
 * on the reject path.
 */
const unsigned long iocb_opcode_values[IOCB_OPCODE_VALUES_N] = {
	IOCB_CMD_PREAD, IOCB_CMD_PWRITE, IOCB_CMD_FSYNC, IOCB_CMD_FDSYNC,
	IOCB_CMD_POLL,  IOCB_CMD_NOOP,   IOCB_CMD_PREADV, IOCB_CMD_PWRITEV,
};

#define IOCB_FLAGS_MASK \
	(IOCB_FLAG_RESFD | IOCB_FLAG_IOPRIO)

#define IOCB_RWF_MASK \
	(RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND | \
	 RWF_NOAPPEND | RWF_ATOMIC | RWF_DONTCACHE)

/*
 * io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,
 *           struct io_event __user *result)
 * a2 is the INPUT struct iocb pointer.  sanitise_io_cancel() owns the
 * live fill (memset, aio_lio_opcode = IOCB_CMD_PREAD, fd from
 * get_random_fd(), aio_buf via get_writable_address, optional pool
 * pin from OBJ_AIO_IOCB).  Attribution-only registration lets
 * struct_field_for_cmp steer KCOV-CMP learned constants at the named
 * opcode / flags / fd slots rather than at a coincidentally-same-width
 * slot.  Same shape as the timespec / siginfo_t entries above.
 *
 * Signed fields stay FT_RAW: FT_RANGE only carries an unsigned [lo, hi]
 * range, so aio_reqprio (__s16) and aio_offset (__s64) keep the
 * historical per-field random splat to preserve negative-value coverage.
 *
 * aio_key is documented as kernel-written ("the kernel sets aio_key to
 * the req #"), so FT_RAW avoids attributing CMP constants to bytes we
 * stamp but the kernel overwrites.
 */
const struct struct_field iocb_fields[IOCB_FIELDS_N] = {
	FIELD(struct iocb, aio_data),
	FIELD(struct iocb, aio_key),
	FIELDX(struct iocb, aio_rw_flags, FT_FLAGS,
	       .u.flags.mask = IOCB_RWF_MASK,
	       .mutate_weight = 80),
	FIELDX(struct iocb, aio_lio_opcode, FT_ENUM,
	       .u.enum_ = { iocb_opcode_values,
			    ARRAY_SIZE(iocb_opcode_values) },
	       .mutate_weight = 100),
	FIELD(struct iocb, aio_reqprio),
	FIELDX(struct iocb, aio_fildes, FT_FD,
	       .mutate_weight = 80),
	FIELD(struct iocb, aio_buf),
	FIELD(struct iocb, aio_nbytes),
	FIELD(struct iocb, aio_offset),
	FIELD(struct iocb, aio_reserved2),
	FIELDX(struct iocb, aio_flags, FT_FLAGS,
	       .u.flags.mask = IOCB_FLAGS_MASK,
	       .mutate_weight = 80),
	FIELDX(struct iocb, aio_resfd, FT_FD,
	       .mutate_weight = 60),
};
