/*
 * SYSCALL_DEFINE4(quotactl, unsigned int, cmd, const char __user *, special,
	 qid_t, id, void __user *, addr)
 */
#include <linux/quota.h>
#include <unistd.h>
#include <string.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static int quota_subcmds[] = {
	Q_SYNC, Q_QUOTAON, Q_QUOTAOFF, Q_GETFMT,
	Q_GETINFO, Q_SETINFO, Q_GETQUOTA, Q_SETQUOTA, Q_GETNEXTQUOTA,
};

static const char *quotafile_paths[] = {
	"aquota.user", "aquota.group", "aquota.project",
	"/aquota.user", "/aquota.group",
	"/tmp/aquota.user", "/var/lib/aquota.user",
};

static int quota_formats[] = {
	QFMT_VFS_OLD, QFMT_VFS_V0, QFMT_VFS_V1,
#ifdef QFMT_OCFS2
	QFMT_OCFS2,
#endif
#ifdef QFMT_SHMEM
	QFMT_SHMEM,
#endif
};

static int pick_quota_type(void)
{
	unsigned int pick = rnd_modulo_u32(100);

	/* 40% USRQUOTA / 40% GRPQUOTA / 15% PRJQUOTA / 5% invalid */
	if (pick < 40)
		return USRQUOTA;
	if (pick < 80)
		return GRPQUOTA;
	if (pick < 95)
		return PRJQUOTA;
	return 16 + rnd_modulo_u32(240);	/* invalid -- past MAXQUOTAS */
}

static unsigned int pick_quota_id(int type)
{
	switch (rnd_modulo_u32(5)) {
	case 0:
		/* current task identity -- most likely to find a row */
		if (type == GRPQUOTA)
			return getgid();
		return getuid();
	case 1:
		return 0;
	case 2:
		return rnd_modulo_u32(256);
	case 3:
		return rnd_modulo_u32(65536);
	default:
		return rand32();
	}
}

static char *fill_quotafile(void)
{
	const char *src = quotafile_paths[rnd_modulo_u32(ARRAY_SIZE(quotafile_paths))];
	char *buf = (char *) get_writable_struct(48);

	if (!buf)
		return NULL;
	strncpy(buf, src, 47);
	buf[47] = '\0';
	return buf;
}

static void sanitise_quotactl(struct syscallrecord *rec)
{
	int subcmd, type;
	char *special;

	subcmd = quota_subcmds[rnd_modulo_u32(ARRAY_SIZE(quota_subcmds))];
	type = pick_quota_type();
	rec->a1 = QCMD(subcmd, type);

	/* arg2: block device path */
	special = (char *) get_writable_struct(32);
	if (!special)
		return;
	strncpy(special, "/dev/sda1", 31);
	special[31] = '\0';
	rec->a2 = (unsigned long) special;

	/* arg3: uid/gid/projid */
	rec->a3 = pick_quota_id(type);

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
			dqb->dqb_ihardlimit = rnd_modulo_u32(100000);
			dqb->dqb_isoftlimit = rnd_modulo_u32(100000);
		}
		rec->a4 = (unsigned long) dqb;
		/*
		 * Shared branch: Q_GETQUOTA/Q_GETNEXTQUOTA only write back
		 * (zero-filled dqb is harmless to relocate), but Q_SETQUOTA
		 * is input -- the limits we just populated above must survive
		 * the relocation.  Use _inout so the populated bytes are
		 * memcpy'd into the replacement allocation for the SETQUOTA
		 * case; the GET cases tolerate the extra copy.
		 */
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
		/*
		 * Same shape as the dqb branch above: Q_GETINFO is write-
		 * only but Q_SETINFO carries the dqi_bgrace/dqi_igrace bytes
		 * we just populated.  Use _inout so the populated bytes
		 * survive the relocation for SETINFO; GETINFO tolerates the
		 * extra copy of zeros.
		 */
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
	case Q_QUOTAON:
		/* id slot carries the format id; addr is a path string. */
		rec->a3 = quota_formats[rnd_modulo_u32(ARRAY_SIZE(quota_formats))];
		rec->a4 = (unsigned long) fill_quotafile();
		break;
	case Q_QUOTAOFF:
	case Q_SYNC:
		rec->a4 = 0;
		break;
	default:
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
	.rettype = RET_ZERO_SUCCESS,
};
