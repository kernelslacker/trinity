/*
 * SYSCALL_DEFINE3(shmctl, int, shmid, int, cmd, struct shmid_ds __user *, buf)
 */
#include <linux/ipc.h>
#include <linux/shm.h>
#include <string.h>
#include <unistd.h>
#include "ipc-common.h"
#include "output-poison.h"
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
	struct ipcctl_post_state *snap;
	void *buf;
	unsigned long allocated_size;

	rec->post_state = 0;

	switch (rec->a2) {
	case IPC_RMID:
	case SHM_LOCK:
	case SHM_UNLOCK:
		rec->a3 = 0;
		return;
	case IPC_INFO:
		allocated_size = sizeof(struct shminfo);
		break;
	case SHM_INFO:
		allocated_size = sizeof(struct shm_info);
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
		 * the coverage gap.  The buffer comes from the call's pool,
		 * where the kernel reads it in place.
		 */
		static const unsigned short mode_dict[] = { 0600, 0644, 0666 };
		struct shmid_ds *ds = get_writable_struct(sizeof(*ds));

		rec->a3 = (unsigned long) ds;
		if (ds == NULL)
			return;
		memset(ds, 0, sizeof(*ds));
		ds->shm_perm.uid = getuid();
		ds->shm_perm.gid = getgid();
		ds->shm_perm.mode =
			mode_dict[rnd_modulo_u32(ARRAY_SIZE(mode_dict))] | 0400;
		return;
	}
	default:
		/* IPC_STAT, SHM_STAT, SHM_STAT_ANY */
		allocated_size = sizeof(struct shmid_ds);
		break;
	}

	/*
	 * The rest are pure outputs.  The buffer comes from the call's
	 * pool, which avoid_shared_buffer_out() would leave where it is,
	 * so the kernel writes the buffer the poison is stamped into, and
	 * the shared post handler re-reads it to catch a success return
	 * with no matching copy_to_user().
	 */
	buf = get_writable_struct(allocated_size);
	rec->a3 = (unsigned long) buf;
	if (buf == NULL)
		return;
	snap = ipcctl_post_state_alloc(rec, buf, allocated_size);
	snap->poison_seed = poison_output_struct(buf, allocated_size, 0);
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
	.rettype = RET_BORING,
	.flags = REEXEC_SANITISE_OK,
};
