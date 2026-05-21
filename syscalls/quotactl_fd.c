/*
 * SYSCALL_DEFINE4(quotactl_fd, unsigned int, fd, unsigned int, cmd,
	 qid_t, id, void __user *, addr)
 */
#include <linux/quota.h>
#include <string.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static int quota_fd_subcmds[] = {
	Q_SYNC, Q_QUOTAON, Q_QUOTAOFF, Q_GETFMT,
	Q_GETINFO, Q_SETINFO, Q_GETQUOTA, Q_SETQUOTA, Q_GETNEXTQUOTA,
};

static int quota_fd_types[] = { USRQUOTA, GRPQUOTA, PRJQUOTA };

static void sanitise_quotactl_fd(struct syscallrecord *rec)
{
	int subcmd, type;

	subcmd = quota_fd_subcmds[rnd_modulo_u32(ARRAY_SIZE(quota_fd_subcmds))];
	type = quota_fd_types[rnd_modulo_u32(ARRAY_SIZE(quota_fd_types))];
	rec->a2 = QCMD(subcmd, type);

	rec->a3 = rnd_modulo_u32(65536);

	switch (subcmd) {
	case Q_GETQUOTA:
	case Q_SETQUOTA:
	case Q_GETNEXTQUOTA: {
		struct if_dqblk *dqb;
		dqb = (struct if_dqblk *) get_writable_struct(sizeof(*dqb));
		if (!dqb)
			break;
		memset(dqb, 0, sizeof(*dqb));
		if (subcmd == Q_SETQUOTA) {
			dqb->dqb_bhardlimit = rand32();
			dqb->dqb_bsoftlimit = rand32();
			dqb->dqb_ihardlimit = rnd_modulo_u32(100000);
			dqb->dqb_isoftlimit = rnd_modulo_u32(100000);
		}
		rec->a4 = (unsigned long) dqb;
		/* Shared branch: Q_SETQUOTA input bytes must survive
		 * the relocation -- use _inout.  See quotactl.c for the
		 * full rationale. */
		avoid_shared_buffer_inout(&rec->a4, sizeof(*dqb));
		break;
	}
	case Q_GETINFO:
	case Q_SETINFO: {
		struct if_dqinfo *dqi;
		dqi = (struct if_dqinfo *) get_writable_struct(sizeof(*dqi));
		if (!dqi)
			break;
		memset(dqi, 0, sizeof(*dqi));
		if (subcmd == Q_SETINFO) {
			dqi->dqi_bgrace = 3600 * (1 + (rnd_modulo_u32(168)));
			dqi->dqi_igrace = 3600 * (1 + (rnd_modulo_u32(168)));
		}
		rec->a4 = (unsigned long) dqi;
		/* Same shape as the dqb branch above: Q_SETINFO carries
		 * input bytes -- use _inout. */
		avoid_shared_buffer_inout(&rec->a4, sizeof(*dqi));
		break;
	}
	case Q_GETFMT: {
		__u32 *fmt;
		fmt = (__u32 *) get_writable_struct(sizeof(*fmt));
		if (!fmt)
			break;
		rec->a4 = (unsigned long) fmt;
		avoid_shared_buffer_out(&rec->a4, sizeof(*fmt));
		break;
	}
	default:
		break;
	}
}

struct syscallentry syscall_quotactl_fd = {
	.name = "quotactl_fd",
	.num_args = 4,
	.argtype = { [0] = ARG_FD },
	.argname = { [0] = "fd", [1] = "cmd", [2] = "id", [3] = "addr" },
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_quotactl_fd,
	.rettype = RET_ZERO_SUCCESS,
};
