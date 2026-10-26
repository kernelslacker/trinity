/*
 * SYSCALL_DEFINE6(ipc, unsigned int, call, int, first, unsigned long, second,
		  unsigned long, third, void __user *, ptr, long, fifth)
 *
 * Old-style IPC multiplexer.  Maps to semop/semget/semctl/msgsnd/msgrcv/
 * msgget/msgctl/shmat/shmdt/shmget/shmctl via the 'call' argument.  A
 * SHMAT is held to the result slot the sanitiser builds and, with
 * SHM_REMAP, to the NULL shmaddr it draws, final slots included
 * (vet_final_ipc()).
 */
#include <limits.h>
#include <linux/ipc.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <string.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Forward-declare the userspace cleanup prototypes. The matching
 * <sys/{sem,msg,shm}.h> headers re-define struct {sem,msq,shm}id_ds and
 * collide with the <linux/...> versions used throughout this file, so
 * we declare just the entry points we need.
 */
extern int semctl(int semid, int semnum, int cmd, ...);
extern int msgctl(int msqid, int cmd, struct msqid_ds *buf);
extern int shmctl(int shmid, int cmd, struct shmid_ds *buf);

static unsigned long ipc_calls[] = {
	SEMOP, SEMGET, SEMCTL, SEMTIMEDOP,
	MSGSND, MSGRCV, MSGGET, MSGCTL,
	SHMAT, SHMDT, SHMGET, SHMCTL,
};

static int sem_cmds[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	GETVAL, GETALL, GETNCNT, GETZCNT, GETPID,
	SETVAL, SETALL, SEM_INFO, SEM_STAT, SEM_STAT_ANY,
};

static int msg_cmds[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	MSG_INFO, MSG_STAT, MSG_STAT_ANY,
};

static int shm_cmds[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	SHM_INFO, SHM_STAT, SHM_STAT_ANY, SHM_LOCK, SHM_UNLOCK,
};

static void sanitise_ipc_semop(struct syscallrecord *rec, unsigned long call)
{
	/*
	 * first=semid, second=nsops, ptr=struct sembuf[],
	 * fifth=timeout (SEMTIMEDOP only)
	 */
	struct sembuf *sops;
	unsigned int nsops, i;

	nsops = 1 + (rnd_modulo_u32(8));
	sops = (struct sembuf *) get_writable_struct(nsops * sizeof(*sops));
	if (!sops)
		return;
	for (i = 0; i < nsops; i++) {
		sops[i].sem_num = rnd_modulo_u32(32);
		sops[i].sem_op = (rnd_modulo_u32(5)) - 2;	/* -2..2 */
		sops[i].sem_flg = 0;
		if (RAND_BOOL())
			sops[i].sem_flg |= IPC_NOWAIT;
		if (RAND_BOOL())
			sops[i].sem_flg |= SEM_UNDO;
	}
	rec->a2 = ONE_IN(5) ? rnd_modulo_u32(1000) : (unsigned long) get_random_sysv_sem();
	rec->a3 = nsops;
	rec->a5 = (unsigned long) sops;

	if (call == SEMTIMEDOP) {
		struct timespec *ts;
		ts = (struct timespec *) get_writable_struct(sizeof(*ts));
		if (!ts)
			return;
		ts->tv_sec = 0;
		ts->tv_nsec = rnd_modulo_u32(1000000);	/* up to 1ms */
		rec->a6 = (unsigned long) ts;
	}
}

static void sanitise_ipc_semget(struct syscallrecord *rec)
{
	/* first=key, second=nsems, third=semflg */
	rec->a2 = RAND_BOOL() ? IPC_PRIVATE : rand32();
	rec->a3 = 1 + (rnd_modulo_u32(32));
	rec->a4 = 0666;
	if (RAND_BOOL())
		rec->a4 |= IPC_CREAT;
	if (RAND_BOOL())
		rec->a4 |= IPC_EXCL;
}

static void sanitise_semctl_cmd_stat(struct syscallrecord *rec)
{
	struct semid_ds *buf;
	buf = (struct semid_ds *) get_writable_struct(sizeof(*buf));
	if (!buf)
		return;
	memset(buf, 0, sizeof(*buf));
	rec->a5 = (unsigned long) buf;
	avoid_shared_buffer_inout(&rec->a5, sizeof(*buf));
}

static void sanitise_semctl_cmd_setval(struct syscallrecord *rec)
{
	unsigned long *slot;

	/*
	 * The ipc() multiplexer reads the union semun through ptr:
	 *   get_user(arg, (unsigned long __user *)ptr)
	 * so a5 must point at a writable slot holding the value,
	 * not carry the value itself.
	 */
	slot = (unsigned long *) get_writable_struct(sizeof(*slot));
	if (!slot)
		return;
	*slot = rnd_modulo_u32(32768);
	rec->a5 = (unsigned long) slot;
}

static void sanitise_semctl_cmd_getall(struct syscallrecord *rec)
{
	unsigned short *arr;
	unsigned int nsems = 1 + (rnd_modulo_u32(32));
	unsigned int j;
	arr = (unsigned short *) get_writable_struct(nsems * sizeof(*arr));
	if (!arr)
		return;
	for (j = 0; j < nsems; j++)
		arr[j] = rnd_modulo_u32(32768);
	rec->a5 = (unsigned long) arr;
	avoid_shared_buffer_inout(&rec->a5, nsems * sizeof(*arr));
}

static void sanitise_semctl_cmd_info(struct syscallrecord *rec)
{
	/* Kernel writes struct seminfo */
	void *buf;
	buf = get_writable_struct(256);
	if (!buf)
		return;
	memset(buf, 0, 256);
	rec->a5 = (unsigned long) buf;
	avoid_shared_buffer_inout(&rec->a5, 256);
}

static void sanitise_ipc_semctl(struct syscallrecord *rec)
{
	/*
	 * first=semid, second=semnum, third=cmd,
	 * ptr=union semun (for IPC_SET/GETALL/SETALL/SETVAL)
	 */
	int cmd;

	rec->a2 = ONE_IN(5) ? rnd_modulo_u32(1000) : (unsigned long) get_random_sysv_sem();
	rec->a3 = rnd_modulo_u32(32);		/* semnum */
	cmd = sem_cmds[rnd_modulo_u32(ARRAY_SIZE(sem_cmds))];
	rec->a4 = cmd;

	switch (cmd) {
	case IPC_STAT:
	case IPC_SET:
	case SEM_STAT:
		sanitise_semctl_cmd_stat(rec);
		break;
	case SETVAL:
		sanitise_semctl_cmd_setval(rec);
		break;
	case GETALL:
	case SETALL:
		sanitise_semctl_cmd_getall(rec);
		break;
	case IPC_INFO:
	case SEM_INFO:
		sanitise_semctl_cmd_info(rec);
		break;
	}
}

static void sanitise_ipc_msgsnd(struct syscallrecord *rec)
{
	/*
	 * first=msqid, ptr=msgbuf, second=msgsz, third=msgflg
	 */
	struct msgbuf *mb;
	size_t msgsz;

	msgsz = 1 + (rnd_modulo_u32(256));
	mb = (struct msgbuf *) get_writable_struct(sizeof(long) + msgsz);
	if (!mb)
		return;
	mb->mtype = 1 + (rnd_modulo_u32(100));
	memset(mb->mtext, 'A', msgsz);

	rec->a2 = ONE_IN(5) ? rnd_modulo_u32(1000) : (unsigned long) get_random_sysv_msg();
	rec->a3 = msgsz;
	rec->a4 = RAND_BOOL() ? IPC_NOWAIT : 0;
	rec->a5 = (unsigned long) mb;
}

static void sanitise_ipc_msgrcv(struct syscallrecord *rec)
{
	/*
	 * first=msqid, ptr=struct { msgbuf*, msgtyp },
	 * second=msgsz, third=msgflg
	 *
	 * The ipc() mux wraps msgrcv args in a tmp struct.
	 * Kernel extracts ptr->msgp and ptr->msgtyp from it.
	 */
	struct {
		struct msgbuf *msgp;
		long msgtyp;
	} *tmp;
	struct msgbuf *mb;
	unsigned long mb_addr;

	mb = (struct msgbuf *) get_writable_struct(sizeof(long) + 256);
	if (!mb)
		return;
	memset(mb, 0, sizeof(long) + 256);

	/* Redirect mb away from the shared/heap arenas before we
	 * publish it through tmp->msgp -- the kernel writes the
	 * received message into *tmp->msgp. */
	mb_addr = (unsigned long) mb;
	avoid_shared_buffer_out(&mb_addr, sizeof(long) + 256);
	mb = (struct msgbuf *) mb_addr;

	tmp = (void *) get_writable_struct(sizeof(*tmp));
	if (!tmp)
		return;
	tmp->msgp = mb;
	tmp->msgtyp = rnd_modulo_u32(10);	/* 0=any type */

	rec->a2 = ONE_IN(5) ? rnd_modulo_u32(1000) : (unsigned long) get_random_sysv_msg();
	rec->a3 = 256;			/* msgsz */
	rec->a4 = RAND_BOOL() ? IPC_NOWAIT : 0;
	rec->a5 = (unsigned long) tmp;
	avoid_shared_buffer_inout(&rec->a5, sizeof(*tmp));
}

static void sanitise_ipc_msgget(struct syscallrecord *rec)
{
	/* first=key, second=msgflg */
	rec->a2 = RAND_BOOL() ? IPC_PRIVATE : rand32();
	rec->a3 = 0666;
	if (RAND_BOOL())
		rec->a3 |= IPC_CREAT;
	if (RAND_BOOL())
		rec->a3 |= IPC_EXCL;
}

static void sanitise_ipc_msgctl(struct syscallrecord *rec)
{
	/* first=msqid, second=cmd, ptr=struct msqid_ds */
	int cmd;

	rec->a2 = ONE_IN(5) ? rnd_modulo_u32(1000) : (unsigned long) get_random_sysv_msg();
	cmd = msg_cmds[rnd_modulo_u32(ARRAY_SIZE(msg_cmds))];
	rec->a3 = cmd;

	switch (cmd) {
	case IPC_STAT:
	case IPC_SET:
	case MSG_STAT: {
		struct msqid_ds *buf;
		buf = (struct msqid_ds *) get_writable_struct(sizeof(*buf));
		if (!buf)
			break;
		memset(buf, 0, sizeof(*buf));
		rec->a5 = (unsigned long) buf;
		avoid_shared_buffer_inout(&rec->a5, sizeof(*buf));
		break;
	}
	case IPC_INFO:
	case MSG_INFO: {
		void *buf;
		buf = get_writable_struct(256);
		if (!buf)
			break;
		memset(buf, 0, 256);
		rec->a5 = (unsigned long) buf;
		avoid_shared_buffer_inout(&rec->a5, 256);
		break;
	}
	}
}

/*
 * The result slot the sanitiser builds for a SHMAT, for vet_final_ipc():
 * ksys_ipc() stores the attach address through third, and a rewrite of
 * third would have it store to memory nobody vetted.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a rewrite
 * of rec->aN cannot move what the call is held to.  Nothing reads it
 * after dispatch, and .cleanup releases it.
 */
#define IPC_POST_STATE_MAGIC	0x4950435F52414444UL	/* "IPC_RADD" */
struct ipc_post_state {
	unsigned long magic;
	unsigned long raddr;
};

static void sanitise_ipc_shmat(struct syscallrecord *rec)
{
	/* first=shmid, second=shmflg, third=&raddr, ptr=shmaddr */
	struct ipc_post_state *snap;
	unsigned long *raddr;
	unsigned long shmflg = 0;

	/*
	 * The ipc() SHMAT path does:
	 *   ret = do_shmat(...); if (ret) return ret;
	 *   return put_user(raddr, (unsigned long __user *)third);
	 * third must point at a writable slot; a bogus value lets the
	 * segment attach and then leaks it when put_user returns -EFAULT.
	 */
	raddr = (unsigned long *) get_writable_struct(sizeof(*raddr));
	if (!raddr)
		return;
	*raddr = 0;
	rec->a4 = (unsigned long) raddr;

	rec->a2 = ONE_IN(5) ? rnd_modulo_u32(1000) : (unsigned long) get_random_sysv_shm();
	if (RAND_BOOL())
		shmflg |= SHM_RDONLY;
	if (RAND_BOOL())
		shmflg |= SHM_RND;
	if (RAND_BOOL())
		shmflg |= SHM_REMAP;
	if (RAND_BOOL())
		shmflg |= SHM_EXEC;
	rec->a3 = shmflg;
	rec->a5 = 0;				/* shmaddr=NULL, kernel picks */

	/*
	 * A compat call's kernel stores through the low 32 bits of third
	 * (compat_ksys_ipc()), which truncate a pool slot above 4 GiB to an
	 * address nobody vetted.  A negative shmid has do_shmat() refuse the
	 * call before it attaches, so nothing is stored.
	 */
	if (rec->do32bit && rec->a4 > UINT_MAX)
		rec->a2 = (unsigned long) -1;

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = IPC_POST_STATE_MAGIC;
	snap->raddr = rec->a4;
	post_state_install(rec, snap);
}

static void sanitise_ipc_shmdt(struct syscallrecord *rec)
{
	/* ptr=shmaddr — use a valid writable page */
	void *addr = get_writable_struct(4096);

	if (addr)
		rec->a5 = (unsigned long) addr;
}

static void sanitise_ipc_shmget(struct syscallrecord *rec)
{
	/* first=key, second=size, third=shmflg */
	rec->a2 = RAND_BOOL() ? IPC_PRIVATE : rand32();
	rec->a3 = 4096 * (1 + (rnd_modulo_u32(16)));	/* 4K-64K */
	rec->a4 = 0666;
	if (RAND_BOOL())
		rec->a4 |= IPC_CREAT;
	if (RAND_BOOL())
		rec->a4 |= IPC_EXCL;
}

static void sanitise_ipc_shmctl(struct syscallrecord *rec)
{
	/* first=shmid, second=cmd, ptr=struct shmid_ds */
	int cmd;

	rec->a2 = ONE_IN(5) ? rnd_modulo_u32(1000) : (unsigned long) get_random_sysv_shm();
	cmd = shm_cmds[rnd_modulo_u32(ARRAY_SIZE(shm_cmds))];
	rec->a3 = cmd;

	switch (cmd) {
	case IPC_STAT:
	case IPC_SET:
	case SHM_STAT: {
		struct shmid_ds *buf;
		buf = (struct shmid_ds *) get_writable_struct(sizeof(*buf));
		if (!buf)
			break;
		memset(buf, 0, sizeof(*buf));
		rec->a5 = (unsigned long) buf;
		avoid_shared_buffer_inout(&rec->a5, sizeof(*buf));
		break;
	}
	case IPC_INFO:
	case SHM_INFO: {
		void *buf;
		buf = get_writable_struct(256);
		if (!buf)
			break;
		memset(buf, 0, 256);
		rec->a5 = (unsigned long) buf;
		avoid_shared_buffer_inout(&rec->a5, 256);
		break;
	}
	}
}

/*
 * A SHMAT that do_shmat() lets attach has ksys_ipc() store the attach
 * address through third, and one that carries SHM_REMAP replaces
 * whatever lies at shmaddr (do_shmat() maps the segment MAP_FIXED
 * there).  The sanitiser builds third as a writable pool slot and draws
 * no shmaddr, so a final SHMAT whose third is not that slot, or whose
 * SHM_REMAP comes with a shmaddr, is a rewrite: chain substitution of
 * call, second or third, which can turn another call's slots, a buffer
 * in ptr among them, into such a SHMAT, or a RedQueen pin of any slot,
 * ptr included.  The generator's slots, which the sanitiser leaves in
 * place when the writable pool cannot supply the result slot, are
 * refused the same way, as is any SHMAT with no snapshot of ours.
 * Refused rather than repaired.  A negative shmid attaches nothing,
 * do_shmat() refusing it first, and any other call's slots are its own.
 * Read as ksys_ipc() reads them: call's low 16 bits name the operation
 * and the next 16 its version, of which 1 refuses SHMAT outright, first
 * and second are ints, and a compat call's third and ptr are their low
 * 32 bits.  Shape, then ownership, then magic, as
 * post_state_claim_owned() orders them.
 */
static int vet_final_ipc(struct syscallrecord *rec,
			 const struct syscallentry *entry __unused__)
{
	struct ipc_post_state *snap =
		(struct ipc_post_state *) rec->post_state;
	unsigned int call = (unsigned int) rec->a1;
	unsigned long mask = rec->do32bit ? UINT_MAX : ULONG_MAX;

	if ((call & 0xffff) != SHMAT || (call >> 16) == 1 ||
	    (int) rec->a2 < 0)
		return 0;

	if ((!((unsigned int) rec->a3 & SHM_REMAP) || !(rec->a5 & mask)) &&
	    !is_corrupt_ptr_shape(snap) && post_state_is_owned(snap) &&
	    snap->magic == IPC_POST_STATE_MAGIC &&
	    (rec->a4 & mask) == snap->raddr)
		return 0;

	outputerr("arg-coupling: ipc rejected: a SHMAT stores its result, or remaps, where sanitise did not vet\n");
	return -1;
}

static void sanitise_ipc(struct syscallrecord *rec)
{
	unsigned long call = rec->a1;

	switch (call) {
	case SEMOP:
	case SEMTIMEDOP:
		sanitise_ipc_semop(rec, call);
		break;
	case SEMGET:
		sanitise_ipc_semget(rec);
		break;
	case SEMCTL:
		sanitise_ipc_semctl(rec);
		break;
	case MSGSND:
		sanitise_ipc_msgsnd(rec);
		break;
	case MSGRCV:
		sanitise_ipc_msgrcv(rec);
		break;
	case MSGGET:
		sanitise_ipc_msgget(rec);
		break;
	case MSGCTL:
		sanitise_ipc_msgctl(rec);
		break;
	case SHMAT:
		sanitise_ipc_shmat(rec);
		break;
	case SHMDT:
		sanitise_ipc_shmdt(rec);
		break;
	case SHMGET:
		sanitise_ipc_shmget(rec);
		break;
	case SHMCTL:
		sanitise_ipc_shmctl(rec);
		break;
	}
}

/*
 * The ipc() multiplexer can dispatch to semget/msgget/shmget, each of
 * which allocates a kernel IPC array via newary() that persists until
 * explicitly removed. Mirror the post handlers on the modern direct
 * syscalls (post_semget/post_msgget/post_shmget) and IPC_RMID the freshly
 * created id immediately, otherwise a long fuzz run accumulates thousands
 * of sem/msg arrays totalling several GB of vmalloc and OOM-kills the box.
 */
static void post_ipc(struct syscallrecord *rec)
{
	unsigned long call = get_arg_snapshot(rec, 1);
	unsigned long retval = rec->retval;
	long ret = (long) retval;
	int id;

	/* Ordinary error return: -1 with errno set. */
	if (ret < 0)
		return;

	switch (call) {
	case SEMGET:
	case MSGGET:
	case SHMGET:
		break;
	default:
		return;
	}

	/*
	 * The kernel ABI guarantees these *get() calls return either -1 or
	 * a non-negative int IPC id (0..INT_MAX). A retval outside that
	 * range cannot have come from the kernel; silently truncating to
	 * (int) would IPC_RMID an unrelated object on the host that
	 * happens to share the low 31 bits of the garbage.
	 */
	if (ret > INT_MAX) {
		output(0, "ipc oracle: returned IPC id 0x%lx out of "
			  "range (must be 0..INT_MAX)\n",
			  retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	id = (int) ret;

	switch (call) {
	case SEMGET:
		semctl(id, 0, IPC_RMID);
		break;
	case MSGGET:
		msgctl(id, IPC_RMID, NULL);
		break;
	case SHMGET:
		shmctl(id, IPC_RMID, NULL);
		break;
	}
}

/* The snapshot was vet_final_ipc()'s alone. */
static void cleanup_ipc(struct syscallrecord *rec)
{
	struct ipc_post_state *snap;

	snap = post_state_claim_owned(rec, IPC_POST_STATE_MAGIC, __func__);
	post_state_release(rec, snap);
}

struct syscallentry syscall_ipc = {
	.name = "ipc",
	.group = GROUP_IPC,
	.num_args = 6,
	.argtype = { [0] = ARG_OP, [4] = ARG_ADDRESS },
	.argname = { [0] = "call", [1] = "first", [2] = "second", [3] = "third", [4] = "ptr", [5] = "fifth" },
	.arg_params[0].list = ARGLIST(ipc_calls),
	.flags = IGNORE_ENOSYS | REEXEC_SANITISE_OK,
	.sanitise = sanitise_ipc,
	.vet_final = vet_final_ipc,
	.post = post_ipc,
	.cleanup = cleanup_ipc,
	.arg_snapshot_mask = (1u << 0),
	.rettype = RET_BORING,
};
