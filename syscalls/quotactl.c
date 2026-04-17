/*
 * SYSCALL_DEFINE4(quotactl, unsigned int, cmd, const char __user *, special,
	 qid_t, id, void __user *, addr)
 */
#include <linux/quota.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"

static int quota_subcmds[] = {
	Q_SYNC, Q_QUOTAON, Q_QUOTAOFF, Q_GETFMT,
	Q_GETINFO, Q_SETINFO, Q_GETQUOTA, Q_SETQUOTA, Q_GETNEXTQUOTA,
};

static int quota_types[] = { USRQUOTA, GRPQUOTA, PRJQUOTA };

static void sanitise_quotactl(struct syscallrecord *rec)
{
	int subcmd, type;
	char *special;

	subcmd = quota_subcmds[rand() % ARRAY_SIZE(quota_subcmds)];
	type = quota_types[rand() % ARRAY_SIZE(quota_types)];
	rec->a1 = QCMD(subcmd, type);

	/* arg2: block device path */
	special = (char *) get_writable_struct(32);
	if (!special)
		return;
	strncpy(special, "/dev/sda1", 31);
	special[31] = '\0';
	rec->a2 = (unsigned long) special;

	/* arg3: uid/gid/projid */
	rec->a3 = rand() % 65536;

	/* arg4: depends on subcmd */
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
			dqb->dqb_ihardlimit = rand() % 100000;
			dqb->dqb_isoftlimit = rand() % 100000;
		}
		rec->a4 = (unsigned long) dqb;
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
			dqi->dqi_bgrace = 3600 * (1 + (rand() % 168));
			dqi->dqi_igrace = 3600 * (1 + (rand() % 168));
		}
		rec->a4 = (unsigned long) dqi;
		break;
	}
	case Q_GETFMT: {
		__u32 *fmt;
		fmt = (__u32 *) get_writable_struct(sizeof(*fmt));
		if (!fmt)
			break;
		rec->a4 = (unsigned long) fmt;
		break;
	}
	default:
		/* Q_SYNC, Q_QUOTAON, Q_QUOTAOFF don't use addr meaningfully */
		break;
	}
}

struct syscallentry syscall_quotactl = {
	.name = "quotactl",
	.num_args = 4,
	.argname = { [0] = "cmd", [1] = "special", [2] = "id", [3] = "addr" },
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_quotactl,
};
