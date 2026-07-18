/*
 * Miscellaneous struct-catalog registrations.
 *
 * Catch-all for rows whose owning syscall doesn't fit a fs / net /
 * io_uring / sched / time / process / bpf bucket cleanly:
 *
 *   - POSIX mqueue: mq_open, mq_getsetattr, mq_notify, mq_timedsend,
 *     mq_timedreceive
 *   - SysV IPC: msgctl, shmctl, msgsnd, semop, semtimedop (both the
 *     sembuf array rows and the timespec timeout row)
 *   - LSM: lsm_set_self_attr
 *   - kexec: kexec_load
 *
 * The struct_catalog/registry.c composition root wires the array
 * declared here into syscall_struct_arg_groups[].
 */

#include <stddef.h>

#include "config.h"

#include "struct_catalog.h"
#include "trinity.h"

const struct syscall_struct_arg struct_catalog_registry_misc[] = {
	/* mq_open(const char *, int, mode_t, struct mq_attr *) */
	{ "mq_open",		4, &struct_catalog[SC_MQ_ATTR] },
	/* mq_getsetattr(mqd_t, const struct mq_attr *, struct mq_attr *) */
	{ "mq_getsetattr",	2, &struct_catalog[SC_MQ_ATTR] },
	{ "mq_getsetattr",	3, &struct_catalog[SC_MQ_ATTR] },
	/* msgctl(int msqid, int cmd, struct msqid_ds *buf) -- IPC_SET path */
	{ "msgctl",		3, &struct_catalog[SC_MSQID_DS] },
	/* shmctl(int shmid, int cmd, struct shmid_ds *buf) -- IPC_SET path */
	{ "shmctl",		3, &struct_catalog[SC_SHMID_DS] },
	/*
	 * semtimedop(int semid, struct sembuf *sops, unsigned nsops,
	 *            const struct timespec *timeout)
	 * a4 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_semtimedop (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a2 (sops, the
	 * sembuf array) is mapped to SC_SEMBUF below and is unaffected.
	 */
	{ "semtimedop",		4, &struct_catalog[SC_TIMESPEC] },
	/*
	 * mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
	 *              unsigned int msg_prio, const struct timespec *abs_timeout)
	 * a5 is the INPUT abs_timeout timespec.  Attribution-only: the bespoke
	 * sanitise_mq_timedsend (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "mq_timedsend",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len,
	 *                 unsigned int *msg_prio, const struct timespec *abs_timeout)
	 * a5 is the INPUT abs_timeout timespec.  Attribution-only: the bespoke
	 * sanitise_mq_timedreceive (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "mq_timedreceive",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * sembuf is an array slot on ARG_ADDRESS at a2 of both semop and
	 * semtimedop; the per-element type is named here so future schema
	 * consumers and struct_field_for_cmp can resolve it.  The bespoke
	 * fill_sembuf_array() owns the live (nsops, sem_*) layout.
	 */
	{ "semop",		2, &struct_catalog[SC_SEMBUF] },
	{ "semtimedop",		2, &struct_catalog[SC_SEMBUF] },
	/*
	 * mq_notify(mqd_t, const struct sigevent *)
	 * a2 carries the same struct sigevent that timer_create's a2
	 * carries; the bespoke sanitise_mq_notify() keeps owning the
	 * live fill (NULL-deregister half the time, otherwise SIGEV_NONE
	 * / SIGEV_SIGNAL / SIGEV_THREAD with sigev_signo populated).
	 * Attribution-only registration lets struct_field_for_cmp steer
	 * CMP-learned constants at sigev_notify / sigev_signo rather
	 * than at a coincidentally-same-width slot.
	 */
	{ "mq_notify",		2, &struct_catalog[SC_SIGEVENT] },
	/*
	 * msgsnd(int msqid, const struct msgbuf __user *msgp, size_t msgsz,
	 *        int msgflg)
	 * a2 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_msgsnd() keeps owning the live fill: a zmalloc'd
	 * sizeof(struct msgbuf) + msgsz buffer with mtype in [1, 255] and
	 * the variable mtext[] tail covered by the bespoke sizing.
	 * Attribution-only registration lets struct_field_for_cmp() steer
	 * CMP-learned constants at the named mtype slot rather than at a
	 * coincidentally-same-width slot.  msgrcv's a2 is a kernel-written
	 * output buffer and is intentionally not mapped.
	 */
	{ "msgsnd",		2, &struct_catalog[SC_MSGBUF] },
	/*
	 * lsm_set_self_attr(unsigned int attr, struct lsm_ctx __user *ctx,
	 *                   u32 size, u32 flags)
	 * a2 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_lsm_set_self_attr() keeps owning the live fill: a
	 * page_size+64 buffer with id drawn from {SELINUX, SMACK, APPARMOR,
	 * LANDLOCK} and size bucketed across the kernel's
	 * security_setselfattr() validation arms.  Attribution-only
	 * registration lets struct_field_for_cmp() steer CMP-learned
	 * constants at the named id / flags / len / ctx_len slots rather
	 * than at coincidentally-same-width neighbours; id is the prime
	 * dispatch target (the kernel selects a single LSM hook from it).
	 * lsm_get_self_attr's lsm_ctx a1 is a kernel-written output buffer
	 * and is intentionally not mapped.
	 */
	{ "lsm_set_self_attr",	2, &struct_catalog[SC_LSM_CTX] },
	/*
	 * kexec_load(unsigned long entry, unsigned long nr_segments,
	 *            struct kexec_segment __user *segments,
	 *            unsigned long flags)
	 * a3 is the segments array; argtype[2] is ARG_ADDRESS (not
	 * ARG_STRUCT_PTR_*), so sanitise_kexec_load() in
	 * syscalls/kexec_load.c keeps owning the live fill.  Attribution-
	 * only registration lets struct_field_for_cmp() steer CMP-learned
	 * constants at the named buf / bufsz / mem / memsz slots rather
	 * than at coincidentally-same-width neighbours.  See
	 * SC_KEXEC_SEGMENT above.
	 */
	{ "kexec_load",		3, &struct_catalog[SC_KEXEC_SEGMENT] },
	/* sentinel */
	{ NULL, 0, NULL },
};
