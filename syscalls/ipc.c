/*
 * SYSCALL_DEFINE6(ipc, unsigned int, call, int, first, unsigned long, second,
                  unsigned long, third, void __user *, ptr, long, fifth)
 *
 * Old-style IPC multiplexer.  Maps to semop/semget/semctl/msgsnd/msgrcv/
 * msgget/msgctl/shmat/shmdt/shmget/shmctl via the 'call' argument.
 */
#include <limits.h>
#include <linux/ipc.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <string.h>
#include "random.h"
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
	SETVAL, SETALL, SEM_INFO, SEM_STAT,
};

static int msg_cmds[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	MSG_INFO, MSG_STAT,
};

static int shm_cmds[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	SHM_INFO, SHM_STAT, SHM_LOCK, SHM_UNLOCK,
};

static void sanitise_ipc(struct syscallrecord *rec)
{
	unsigned long call = rec->a1;

	switch (call) {
	case SEMOP:
	case SEMTIMEDOP: {
		/*
		 * first=semid, second=nsops, ptr=struct sembuf[],
		 * fifth=timeout (SEMTIMEDOP only)
		 */
		struct sembuf *sops;
		unsigned int nsops, i;

		nsops = 1 + (rand() % 8);
		sops = (struct sembuf *) get_writable_struct(nsops * sizeof(*sops));
		if (!sops)
			break;
		for (i = 0; i < nsops; i++) {
			sops[i].sem_num = rand() % 32;
			sops[i].sem_op = (rand() % 5) - 2;	/* -2..2 */
			sops[i].sem_flg = 0;
			if (RAND_BOOL())
				sops[i].sem_flg |= IPC_NOWAIT;
			if (RAND_BOOL())
				sops[i].sem_flg |= SEM_UNDO;
		}
		rec->a2 = rand() % 1000;	/* semid */
		rec->a3 = nsops;
		rec->a5 = (unsigned long) sops;

		if (call == SEMTIMEDOP) {
			struct timespec *ts;
			ts = (struct timespec *) get_writable_struct(sizeof(*ts));
			if (!ts)
				break;
			ts->tv_sec = 0;
			ts->tv_nsec = rand() % 1000000;	/* up to 1ms */
			rec->a6 = (unsigned long) ts;
		}
		break;
	}

	case SEMGET:
		/* first=key, second=nsems, third=semflg */
		rec->a2 = RAND_BOOL() ? IPC_PRIVATE : rand32();
		rec->a3 = 1 + (rand() % 32);
		rec->a4 = 0666;
		if (RAND_BOOL())
			rec->a4 |= IPC_CREAT;
		if (RAND_BOOL())
			rec->a4 |= IPC_EXCL;
		break;

	case SEMCTL: {
		/*
		 * first=semid, second=semnum, third=cmd,
		 * ptr=union semun (for IPC_SET/GETALL/SETALL/SETVAL)
		 */
		int cmd;

		rec->a2 = rand() % 1000;	/* semid */
		rec->a3 = rand() % 32;		/* semnum */
		cmd = sem_cmds[rand() % ARRAY_SIZE(sem_cmds)];
		rec->a4 = cmd;

		switch (cmd) {
		case IPC_STAT:
		case IPC_SET:
		case SEM_STAT: {
			struct semid_ds *buf;
			buf = (struct semid_ds *) get_writable_struct(sizeof(*buf));
			if (!buf)
				break;
			memset(buf, 0, sizeof(*buf));
			rec->a5 = (unsigned long) buf;
			break;
		}
		case SETVAL:
			/* ptr is the value directly for old-style ipc() */
			rec->a5 = rand() % 32768;
			break;
		case GETALL:
		case SETALL: {
			unsigned short *arr;
			unsigned int nsems = 1 + (rand() % 32);
			unsigned int j;
			arr = (unsigned short *) get_writable_struct(nsems * sizeof(*arr));
			if (!arr)
				break;
			for (j = 0; j < nsems; j++)
				arr[j] = rand() % 32768;
			rec->a5 = (unsigned long) arr;
			break;
		}
		case IPC_INFO:
		case SEM_INFO: {
			/* Kernel writes struct seminfo */
			void *buf;
			buf = get_writable_struct(256);
			if (!buf)
				break;
			memset(buf, 0, 256);
			rec->a5 = (unsigned long) buf;
			break;
		}
		}
		break;
	}

	case MSGSND: {
		/*
		 * first=msqid, ptr=msgbuf, second=msgsz, third=msgflg
		 */
		struct msgbuf *mb;
		size_t msgsz;

		msgsz = 1 + (rand() % 256);
		mb = (struct msgbuf *) get_writable_struct(sizeof(long) + msgsz);
		if (!mb)
			break;
		mb->mtype = 1 + (rand() % 100);
		memset(mb->mtext, 'A', msgsz);

		rec->a2 = rand() % 1000;	/* msqid */
		rec->a3 = msgsz;
		rec->a4 = RAND_BOOL() ? IPC_NOWAIT : 0;
		rec->a5 = (unsigned long) mb;
		break;
	}

	case MSGRCV: {
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

		mb = (struct msgbuf *) get_writable_struct(sizeof(long) + 256);
		if (!mb)
			break;
		memset(mb, 0, sizeof(long) + 256);

		tmp = (void *) get_writable_struct(sizeof(*tmp));
		if (!tmp)
			break;
		tmp->msgp = mb;
		tmp->msgtyp = rand() % 10;	/* 0=any type */

		rec->a2 = rand() % 1000;	/* msqid */
		rec->a3 = 256;			/* msgsz */
		rec->a4 = RAND_BOOL() ? IPC_NOWAIT : 0;
		rec->a5 = (unsigned long) tmp;
		break;
	}

	case MSGGET:
		/* first=key, second=msgflg */
		rec->a2 = RAND_BOOL() ? IPC_PRIVATE : rand32();
		rec->a3 = 0666;
		if (RAND_BOOL())
			rec->a3 |= IPC_CREAT;
		if (RAND_BOOL())
			rec->a3 |= IPC_EXCL;
		break;

	case MSGCTL: {
		/* first=msqid, second=cmd, ptr=struct msqid_ds */
		int cmd;

		rec->a2 = rand() % 1000;
		cmd = msg_cmds[rand() % ARRAY_SIZE(msg_cmds)];
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
			break;
		}
		}
		break;
	}

	case SHMAT: {
		/* first=shmid, ptr=shmaddr, second=shmflg */
		rec->a2 = rand() % 1000;	/* shmid */
		rec->a3 = 0;			/* let kernel pick */
		rec->a5 = 0;			/* shmaddr=NULL */
		if (RAND_BOOL())
			rec->a3 |= SHM_RDONLY;
		break;
	}

	case SHMDT: {
		/* ptr=shmaddr — use a valid writable page */
		void *addr = get_writable_struct(4096);

		if (addr)
			rec->a5 = (unsigned long) addr;
		break;
	}

	case SHMGET:
		/* first=key, second=size, third=shmflg */
		rec->a2 = RAND_BOOL() ? IPC_PRIVATE : rand32();
		rec->a3 = 4096 * (1 + (rand() % 16));	/* 4K-64K */
		rec->a4 = 0666;
		if (RAND_BOOL())
			rec->a4 |= IPC_CREAT;
		if (RAND_BOOL())
			rec->a4 |= IPC_EXCL;
		break;

	case SHMCTL: {
		/* first=shmid, second=cmd, ptr=struct shmid_ds */
		int cmd;

		rec->a2 = rand() % 1000;
		cmd = shm_cmds[rand() % ARRAY_SIZE(shm_cmds)];
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
			break;
		}
		}
		break;
	}
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
	unsigned long call = rec->a1;
	long ret = (long) rec->retval;
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
			  (unsigned long) rec->retval);
		(void) looks_like_corrupted_ptr(rec,
						(const void *) rec->retval);
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

struct syscallentry syscall_ipc = {
	.name = "ipc",
	.group = GROUP_IPC,
	.num_args = 6,
	.argtype = { [0] = ARG_OP, [4] = ARG_ADDRESS },
	.argname = { [0] = "call", [1] = "first", [2] = "second", [3] = "third", [4] = "ptr", [5] = "fifth" },
	.arg_params[0].list = ARGLIST(ipc_calls),
	.flags = IGNORE_ENOSYS,
	.sanitise = sanitise_ipc,
	.post = post_ipc,
};
