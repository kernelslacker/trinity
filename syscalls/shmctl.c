/*
 * SYSCALL_DEFINE3(shmctl, int, shmid, int, cmd, struct shmid_ds __user *, buf)
 */
#include <linux/ipc.h>
#include <linux/shm.h>
#include <unistd.h>
#include "ipc-common.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long shmctl_ops[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	SHM_INFO, SHM_STAT, SHM_STAT_ANY, SHM_LOCK, SHM_UNLOCK,
};

static void sanitise_shmctl(struct syscallrecord *rec)
{
	void *buf;
	unsigned long allocated_size;
	bool input_buf = false;

	rec->post_state = 0;

	switch (rec->a2) {
	case IPC_RMID:
	case SHM_LOCK:
	case SHM_UNLOCK:
		rec->a3 = 0;
		return;
	case IPC_INFO:
		allocated_size = sizeof(struct shminfo);
		buf = zmalloc_tracked(allocated_size);
		break;
	case SHM_INFO:
		allocated_size = sizeof(struct shm_info);
		buf = zmalloc_tracked(allocated_size);
		break;
	case IPC_SET: {
		/*
		 * IPC_SET copies shm_perm.uid / .gid / .mode out of the
		 * caller-supplied shmid_ds and applies them to the segment's
		 * permission record.  A zeroed buffer leaves uid=gid=0 +
		 * mode=0 which either gets the syscall denied with EPERM
		 * (non-root child can't reassign ownership to root) or
		 * locks the segment out from any subsequent fuzzed operation
		 * with mode 0 -- so the IPC_SET path is effectively a
		 * no-op for coverage.  Populate the perm triple instead.
		 *
		 * Modes come from a tiny dictionary of plausible IPC mode
		 * bits.  Critical: always OR in 0400 so the calling child
		 * keeps read access to the segment after the SET -- without
		 * this guard a later shmat / shmctl(IPC_STAT) from the
		 * same child trips EACCES, defeating the point of fixing
		 * the coverage gap.
		 */
		static const unsigned short mode_dict[] = { 0600, 0644, 0666 };
		struct shmid_ds *ds;

		allocated_size = sizeof(struct shmid_ds);
		buf = zmalloc_tracked(allocated_size);
		ds = buf;
		ds->shm_perm.uid = getuid();
		ds->shm_perm.gid = getgid();
		ds->shm_perm.mode =
			mode_dict[rnd_modulo_u32(ARRAY_SIZE(mode_dict))] | 0400;
		input_buf = true;
		break;
	}
	default:
		/* IPC_STAT, SHM_STAT, SHM_STAT_ANY */
		allocated_size = sizeof(struct shmid_ds);
		buf = zmalloc_tracked(allocated_size);
		break;
	}

	rec->a3 = (unsigned long) buf;

	ipcctl_post_state_alloc(rec, buf, allocated_size);

	/*
	 * IPC_SET is the only input branch: the kernel reads shm_perm
	 * from the buffer.  Relocate copy-preserving so the curated
	 * uid/gid/mode survive the move into the writable pool; without
	 * it the kernel reads pool zeros and EINVALs/EPERMs the call,
	 * silently neutering IPC_SET coverage.  IPC_INFO / SHM_INFO /
	 * IPC_STAT / SHM_STAT / SHM_STAT_ANY are pure outputs -- the
	 * kernel writes them, so the cheaper relocate-only suffices.
	 */
	if (input_buf)
		avoid_shared_buffer_inout(&rec->a3, allocated_size);
	else
		avoid_shared_buffer_out(&rec->a3, allocated_size);
}

static void post_shmctl(struct syscallrecord *rec)
{
	post_ipcctl_buf_free(rec, "post_shmctl");
}

struct syscallentry syscall_shmctl = {
	.name = "shmctl",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_SYSV_SHM, [1] = ARG_OP, [2] = ARG_ADDRESS },
	.argname = { [0] = "shmid", [1] = "cmd", [2] = "buf" },
	.arg_params[1].list = ARGLIST(shmctl_ops),
	.sanitise = sanitise_shmctl,
	.post = post_shmctl,
};
