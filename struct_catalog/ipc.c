/*
 * struct_catalog/ipc.c -- SysV / POSIX IPC struct field tables
 * (sembuf, mq_attr, msqid_ds, shmid_ds, msgbuf).
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` references resolve via the externs in struct_catalog-internal.h.
 * struct_catalog.h and arch.h are #included unconditionally so this TU is
 * never empty.
 */

#include <stddef.h>
#include <fcntl.h>
#include <mqueue.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/msg.h>
#include <sys/shm.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct sembuf (semop, semtimedop)                                   */
/* ------------------------------------------------------------------ */

/*
 * sem{,timed}op pass an ARRAY of sembuf at a2 (nsops in a3), not a
 * single struct, and the arg slot is ARG_ADDRESS rather than
 * ARG_STRUCT_PTR_*.  The bespoke fill_sembuf_array() helpers in
 * syscalls/semop.c and syscalls/semtimedop.c allocate the buffer,
 * pick a per-element (sem_num, sem_op, sem_flg) triple respecting
 * the kernel's nsems / IPC_NOWAIT / SEM_UNDO semantics, and overwrite
 * rec->a2 -- the schema-aware fill path never runs for this slot.
 *
 * Registration is attribution-only, mirroring cachestat_range /
 * mount_attr above: struct_field_for_cmp() uses the FT_RANGE /
 * FT_FLAGS tags to steer KCOV-CMP learned constants at sem_num or
 * sem_flg rather than at a coincidentally-same-width slot.  sem_op
 * stays FT_RAW: its kernel semantics are arithmetic
 * (sma->sem_base[].semval + sem_op) rather than a vocab CMP, so no
 * gate-tag lift would help attribution.  sem_num's range upper bound
 * mirrors syscalls/semop.c's pick_sem_num() worst-case
 * (SEMOP_FALLBACK_NSEMS + 63 = 95) so future schema consumers stay
 * inside the same in-range / out-of-range envelope the bespoke
 * sanitiser already explores.
 */
const struct struct_field sembuf_fields[SEMBUF_FIELDS_N] = {
	FIELDX(struct sembuf, sem_num, FT_RANGE,
	       .u.range = { 0, 95 },
	       .mutate_weight = 60),
	FIELD(struct sembuf, sem_op),
	FIELDX(struct sembuf, sem_flg, FT_FLAGS,
	       .u.flags.mask = IPC_NOWAIT | SEM_UNDO,
	       .mutate_weight = 80),
};

/* ------------------------------------------------------------------ */
/* struct mq_attr (mq_open, mq_getsetattr)                              */
/* ------------------------------------------------------------------ */

/*
 * mq_attr.mq_flags is the only settable bit in the struct on the
 * mq_setattr path and the kernel masks everything but O_NONBLOCK
 * away.  Constraining the random fill to that single bit lets
 * mq_getsetattr's IPC_SET path go through validation instead of
 * bouncing on -EINVAL.
 */
const struct struct_field mq_attr_fields[MQ_ATTR_FIELDS_N] = {
	FIELDX(struct mq_attr, mq_flags, FT_FLAGS,
	       .u.flags.mask = O_NONBLOCK),
	FIELD(struct mq_attr, mq_maxmsg),
	FIELD(struct mq_attr, mq_msgsize),
	FIELD(struct mq_attr, mq_curmsgs),
};

/* ------------------------------------------------------------------ */
/* struct msqid_ds (msgctl IPC_SET path)                                */
/* ------------------------------------------------------------------ */

const struct struct_field msqid_ds_fields[MSQID_DS_FIELDS_N] = {
	FIELD(struct msqid_ds, msg_perm.mode),
	FIELD(struct msqid_ds, msg_qbytes),
};

/* ------------------------------------------------------------------ */
/* struct shmid_ds (shmctl IPC_SET path)                                */
/* ------------------------------------------------------------------ */

const struct struct_field shmid_ds_fields[SHMID_DS_FIELDS_N] = {
	FIELD(struct shmid_ds, shm_perm.uid),
	FIELD(struct shmid_ds, shm_perm.gid),
	FIELD(struct shmid_ds, shm_perm.mode),
};

/* ------------------------------------------------------------------ */
/* struct msgbuf (msgsnd)                                              */
/* ------------------------------------------------------------------ */

/*
 * msgsnd(int msqid, const struct msgbuf __user *msgp, size_t msgsz,
 *        int msgflg) hands the kernel an mtype/mtext header at a2.
 * argtype[1] is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
 * sanitise_msgsnd() keeps owning the live fill: it zmalloc's a
 * sizeof(struct msgbuf) + msgsz buffer, draws msgsz from a bucketed
 * (empty / small / page-sized / near-MSGMAX / random-tail) distribution,
 * and stamps mtype in [1, 255] (the kernel rejects mtype <= 0).  The
 * variable mtext[] tail is owned by that sanitiser and intentionally
 * not modelled here: FT_RAW would need a per-call effective_size for
 * the trailing flexible array, and the bespoke fill already covers it.
 *
 * Registration is attribution-only, mirroring the in-tree timer_create /
 * utimbuf / flock entries: the bespoke sanitiser keeps owning the live
 * fill -- this only feeds the CMP-attribution path.  mtype is left
 * FT_RAW so the bespoke [1, 255] band is preserved verbatim; the win is
 * letting struct_field_for_cmp() steer KCOV CMP-learned constants at
 * the named mtype slot rather than at a coincidentally-same-width
 * neighbour.
 */
const struct struct_field msgbuf_fields[MSGBUF_FIELDS_N] = {
	FIELD(struct msgbuf, mtype),
};
