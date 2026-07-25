/*
 * Part of the recipe_runner catalogue; see recipe-runner.c for the
 * design rationale and recipe-runner-internal.h for the shared
 * declarations and macros.
 */

#include <errno.h>
#include <limits.h>
#include <mqueue.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <linux/userfaultfd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "syscall-gate.h"
#include "maps.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "pids.h"

#include "childops/recipe/internal.h"

#include "kernel/eventfd.h"
#include "kernel/fcntl.h"
#include "kernel/timerfd.h"
#include "kernel/memfd.h"
/*
 * Recipe 9: SysV shared-memory segment lifecycle.
 *
 * shmget(IPC_PRIVATE) → shmat → write to the segment → shmdt → shmctl
 * (IPC_RMID).  IPC_PRIVATE keys produce per-process unique segments,
 * so concurrent recipe runs in sibling children don't collide.
 */
bool recipe_shmget(bool *unsupported __unused__)
{
	void *addr = (void *)-1;
	int shmid = -1;
	bool ok = false;

	shmid = shmget(IPC_PRIVATE, page_size, IPC_CREAT | 0600);
	if (shmid < 0)
		goto out;

	addr = shmat(shmid, NULL, 0);
	if (addr == (void *)-1)
		goto out;

	((volatile char *)addr)[0] = (char)(rnd_u32() & 0xff);

	if (shmdt(addr) < 0)
		goto out;
	addr = (void *)-1;

	if (shmctl(shmid, IPC_RMID, NULL) < 0)
		goto out;
	shmid = -1;

	ok = true;
out:
	if (addr != (void *)-1)
		(void)shmdt(addr);
	if (shmid >= 0)
		(void)shmctl(shmid, IPC_RMID, NULL);
	return ok;
}

/*
 * Recipe 10: SysV message queue lifecycle.
 *
 * msgget(IPC_PRIVATE) → msgsnd → msgrcv → msgctl(IPC_RMID).
 * Uses a small fixed-size struct so we hit the common-case allocation
 * path without stressing the kernel's per-queue size limits.
 */
struct trinity_msgbuf {
	long mtype;
	char mtext[32];
};

bool recipe_msgget(bool *unsupported __unused__)
{
	struct trinity_msgbuf m;
	int qid = -1;
	bool ok = false;

	qid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
	if (qid < 0)
		goto out;

	m.mtype = 1;
	memset(m.mtext, 'm', sizeof(m.mtext));
	if (msgsnd(qid, &m, sizeof(m.mtext), IPC_NOWAIT) < 0)
		goto out;

	if (msgrcv(qid, &m, sizeof(m.mtext), 0, IPC_NOWAIT) < 0)
		goto out;

	if (msgctl(qid, IPC_RMID, NULL) < 0)
		goto out;
	qid = -1;

	ok = true;
out:
	if (qid >= 0)
		(void)msgctl(qid, IPC_RMID, NULL);
	return ok;
}

/*
 * Recipe 11: SysV semaphore lifecycle.
 *
 * semget(IPC_PRIVATE, 1) → semop(P=-1) — but only after we've already
 * SETVAL'd the semaphore to 1 so the P doesn't block — then semop(V=+1)
 * → semctl(IPC_RMID).
 *
 * union semun is glibc-private and not declared in any header; callers
 * must provide their own definition per the man page.
 */
union trinity_semun {
	int val;
	struct semid_ds *buf;
	unsigned short *array;
};

bool recipe_semget(bool *unsupported __unused__)
{
	struct sembuf op;
	union trinity_semun arg;
	int sid = -1;
	bool ok = false;

	sid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
	if (sid < 0)
		goto out;

	arg.val = 1;
	if (semctl(sid, 0, SETVAL, arg) < 0)
		goto out;

	op.sem_num = 0;
	op.sem_op = -1;
	op.sem_flg = IPC_NOWAIT;
	if (semop(sid, &op, 1) < 0)
		goto out;

	op.sem_op = 1;
	op.sem_flg = 0;
	if (semop(sid, &op, 1) < 0)
		goto out;

	if (semctl(sid, 0, IPC_RMID) < 0)
		goto out;
	sid = -1;

	ok = true;
out:
	if (sid >= 0)
		(void)semctl(sid, 0, IPC_RMID);
	return ok;
}
