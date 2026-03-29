/*
 * SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd, void __user *, arg)
 */
#include <linux/reboot.h>
#include "sanitise.h"

static unsigned long reboot_magic2_vals[] = {
	LINUX_REBOOT_MAGIC2, LINUX_REBOOT_MAGIC2A,
	LINUX_REBOOT_MAGIC2B, LINUX_REBOOT_MAGIC2C,
};

static unsigned long reboot_cmds[] = {
	LINUX_REBOOT_CMD_RESTART, LINUX_REBOOT_CMD_HALT,
	LINUX_REBOOT_CMD_CAD_ON, LINUX_REBOOT_CMD_CAD_OFF,
	LINUX_REBOOT_CMD_POWER_OFF, LINUX_REBOOT_CMD_RESTART2,
	LINUX_REBOOT_CMD_SW_SUSPEND, LINUX_REBOOT_CMD_KEXEC,
};

static void sanitise_reboot(struct syscallrecord *rec)
{
	rec->a1 = LINUX_REBOOT_MAGIC1;
}

struct syscallentry syscall_reboot = {
	.name = "reboot",
	.num_args = 4,
	.argtype = { [1] = ARG_LIST, [2] = ARG_LIST, [3] = ARG_ADDRESS },
	.argname = { [0] = "magic1", [1] = "magic2", [2] = "cmd", [3] = "arg" },
	.arg2list = ARGLIST(reboot_magic2_vals),
	.arg3list = ARGLIST(reboot_cmds),
	.sanitise = sanitise_reboot,
	.group = GROUP_PROCESS,
};
