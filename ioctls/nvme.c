#ifdef USE_NVME
#include <linux/ioctl.h>
#include <linux/nvme_ioctl.h>

#include "compat.h"
#include "ioctls.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_nvme_admin_cmd(struct syscallrecord *rec)
{
	struct nvme_passthru_cmd *cmd;
	/* 0x02=Get Log Page, 0x06=Identify, 0x08=Abort, 0x09=Set Features,
	 * 0x0a=Get Features, 0x10=Firmware Activate, 0x11=Firmware Download,
	 * 0x14=Self-test, 0x80=Format NVM.  AER (0x0c) omitted: blocks until
	 * cancelled and hangs the fuzzer. */
	static const __u8 admin_opcodes[] = {
		0x02, 0x06, 0x08, 0x09, 0x0a, 0x10, 0x11, 0x14, 0x80,
	};

	cmd = (struct nvme_passthru_cmd *) get_writable_struct(sizeof(*cmd));
	if (!cmd)
		return;
	cmd->opcode = admin_opcodes[rand() % ARRAY_SIZE(admin_opcodes)];
	cmd->nsid = RAND_BOOL() ? 0 : rand32();
	cmd->addr = (unsigned long) get_writable_struct(4096);
	cmd->data_len = 4096;
	cmd->timeout_ms = 1000;
	cmd->cdw10 = rand32();
	cmd->cdw11 = rand32();
	cmd->cdw12 = rand32();
	cmd->cdw13 = rand32();
	cmd->cdw14 = rand32();
	cmd->cdw15 = rand32();
	rec->a3 = (unsigned long) cmd;
}

static void sanitise_nvme_admin64_cmd(struct syscallrecord *rec)
{
	struct nvme_passthru_cmd64 *cmd;
	static const __u8 admin_opcodes[] = {
		0x02, 0x06, 0x08, 0x09, 0x0a, 0x10, 0x11, 0x14, 0x80,
	};

	cmd = (struct nvme_passthru_cmd64 *) get_writable_struct(sizeof(*cmd));
	if (!cmd)
		return;
	cmd->opcode = admin_opcodes[rand() % ARRAY_SIZE(admin_opcodes)];
	cmd->nsid = RAND_BOOL() ? 0 : rand32();
	cmd->addr = (unsigned long) get_writable_struct(4096);
	cmd->data_len = 4096;
	cmd->timeout_ms = 1000;
	cmd->cdw10 = rand32();
	cmd->cdw11 = rand32();
	cmd->cdw12 = rand32();
	cmd->cdw13 = rand32();
	cmd->cdw14 = rand32();
	cmd->cdw15 = rand32();
	rec->a3 = (unsigned long) cmd;
}

static void sanitise_nvme_io_cmd(struct syscallrecord *rec)
{
	struct nvme_passthru_cmd *cmd;

	cmd = (struct nvme_passthru_cmd *) get_writable_struct(sizeof(*cmd));
	if (!cmd)
		return;
	cmd->opcode = RAND_BOOL() ? 0x01 : 0x02;
	cmd->nsid = RAND_BOOL() ? 1 : rand32();
	cmd->addr = (unsigned long) get_writable_struct(4096);
	cmd->data_len = 4096;
	rec->a3 = (unsigned long) cmd;
}

static void sanitise_nvme_io64_cmd(struct syscallrecord *rec)
{
	struct nvme_passthru_cmd64 *cmd;

	cmd = (struct nvme_passthru_cmd64 *) get_writable_struct(sizeof(*cmd));
	if (!cmd)
		return;
	cmd->opcode = RAND_BOOL() ? 0x01 : 0x02;
	cmd->nsid = RAND_BOOL() ? 1 : rand32();
	cmd->addr = (unsigned long) get_writable_struct(4096);
	cmd->data_len = 4096;
	rec->a3 = (unsigned long) cmd;
}

static void sanitise_nvme_submit_io(struct syscallrecord *rec)
{
	struct nvme_user_io *io;

	io = (struct nvme_user_io *) get_writable_struct(sizeof(*io));
	if (!io)
		return;
	memset(io, 0, sizeof(*io));
	io->opcode = RAND_BOOL() ? 0x01 : 0x02;
	io->addr = (unsigned long) get_writable_struct(4096);
	io->nblocks = rand() % 8;
	rec->a3 = (unsigned long) io;
}

static void sanitise_nvme_io64_cmd_vec(struct syscallrecord *rec)
{
	struct nvme_passthru_cmd64 *cmd;

	cmd = (struct nvme_passthru_cmd64 *) get_writable_struct(sizeof(*cmd));
	if (!cmd)
		return;
	cmd->opcode  = RAND_BOOL() ? 0x01 : 0x02;
	cmd->nsid    = RAND_BOOL() ? 1 : rand32();
	cmd->vec_cnt = 1;
	cmd->addr    = (unsigned long) get_writable_struct(4096);
	rec->a3 = (unsigned long) cmd;
}

static void nvme_sanitise(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case NVME_IOCTL_ADMIN_CMD:
		sanitise_nvme_admin_cmd(rec);
		break;
	case NVME_IOCTL_ADMIN64_CMD:
		sanitise_nvme_admin64_cmd(rec);
		break;
	case NVME_IOCTL_IO_CMD:
		sanitise_nvme_io_cmd(rec);
		break;
	case NVME_IOCTL_IO64_CMD:
		sanitise_nvme_io64_cmd(rec);
		break;
	case NVME_IOCTL_IO64_CMD_VEC:
		sanitise_nvme_io64_cmd_vec(rec);
		break;
	case NVME_IOCTL_SUBMIT_IO:
		sanitise_nvme_submit_io(rec);
		break;
	default:
		break;
	}
}

static const struct ioctl nvme_ioctls[] = {
	IOCTL(NVME_IOCTL_ID),
	IOCTL(NVME_IOCTL_ADMIN_CMD),
	IOCTL(NVME_IOCTL_SUBMIT_IO),
	IOCTL(NVME_IOCTL_IO_CMD),
	IOCTL(NVME_IOCTL_RESET),
	IOCTL(NVME_IOCTL_SUBSYS_RESET),
	IOCTL(NVME_IOCTL_RESCAN),
	IOCTL(NVME_IOCTL_ADMIN64_CMD),
	IOCTL(NVME_IOCTL_IO64_CMD),
	IOCTL(NVME_IOCTL_IO64_CMD_VEC),
};

static const char *const nvme_devs[] = {
	"nvme",
};

static const struct ioctl_group nvme_grp_misc = {
	.devtype = DEV_CHAR,
	.devs = nvme_devs,
	.devs_cnt = ARRAY_SIZE(nvme_devs),
	.sanitise = nvme_sanitise,
	.ioctls = nvme_ioctls,
	.ioctls_cnt = ARRAY_SIZE(nvme_ioctls),
};

REG_IOCTL_GROUP(nvme_grp_misc)

static const struct ioctl_group nvme_grp_block = {
	.devtype = DEV_BLOCK,
	.devs = nvme_devs,
	.devs_cnt = ARRAY_SIZE(nvme_devs),
	.sanitise = nvme_sanitise,
	.ioctls = nvme_ioctls,
	.ioctls_cnt = ARRAY_SIZE(nvme_ioctls),
};

REG_IOCTL_GROUP(nvme_grp_block);
#endif
