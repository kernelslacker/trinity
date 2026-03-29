/*
 * SYSCALL_DEFINE4(quotactl_fd, unsigned int, fd, unsigned int, cmd,
	 qid_t, id, void __user *, addr)
 */
#include <linux/quota.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"

static int quota_fd_subcmds[] = {
	Q_SYNC, Q_QUOTAON, Q_QUOTAOFF, Q_GETFMT,
	Q_GETINFO, Q_SETINFO, Q_GETQUOTA, Q_SETQUOTA, Q_GETNEXTQUOTA,
};

static int quota_fd_types[] = { USRQUOTA, GRPQUOTA, PRJQUOTA };

static void sanitise_quotactl_fd(struct syscallrecord *rec)
{
	int subcmd, type;

	subcmd = quota_fd_subcmds[rand() % ARRAY_SIZE(quota_fd_subcmds)];
	type = quota_fd_types[rand() % ARRAY_SIZE(quota_fd_types)];
	rec->a2 = QCMD(subcmd, type);

	rec->a3 = rand() % 65536;

	switch (subcmd) {
	case Q_GETQUOTA:
	case Q_SETQUOTA:
	case Q_GETNEXTQUOTA: {
		struct if_dqblk *dqb;
		dqb = (struct if_dqblk *) get_writable_address(sizeof(*dqb));
		memset(dqb, 0, sizeof(*dqb));
		if (subcmd == Q_SETQUOTA) {
			dqb->dqb_bhardlimit = rand32();
			dqb->dqb_bsoftlimit = rand32();
			dqb->dqb_ihardlimit = rand() % 100000;
			dqb->dqb_isoftlimit = rand() % 100000;
		}
		rec->a4 = (unsigned long) dqb;
		break;
	}
	case Q_GETINFO:
	case Q_SETINFO: {
		struct if_dqinfo *dqi;
		dqi = (struct if_dqinfo *) get_writable_address(sizeof(*dqi));
		memset(dqi, 0, sizeof(*dqi));
		if (subcmd == Q_SETINFO) {
			dqi->dqi_bgrace = 3600 * (1 + (rand() % 168));
			dqi->dqi_igrace = 3600 * (1 + (rand() % 168));
		}
		rec->a4 = (unsigned long) dqi;
		break;
	}
	case Q_GETFMT: {
		__u32 *fmt;
		fmt = (__u32 *) get_writable_address(sizeof(*fmt));
		rec->a4 = (unsigned long) fmt;
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
};
