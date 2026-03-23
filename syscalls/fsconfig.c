/*
 *  SYSCALL_DEFINE5(fsconfig, int, fd, unsigned int, cmd, const char __user *, _key, const void __user *, _value, int, aux)
 */
#include "sanitise.h"

enum fsconfig_command {
    FSCONFIG_SET_FLAG       = 0,    /* Set parameter, supplying no value */
    FSCONFIG_SET_STRING     = 1,    /* Set parameter, supplying a string value */
    FSCONFIG_SET_BINARY     = 2,    /* Set parameter, supplying a binary blob value */
    FSCONFIG_SET_PATH       = 3,    /* Set parameter, supplying an object by path */
    FSCONFIG_SET_PATH_EMPTY = 4,    /* Set parameter, supplying an object by (empty) path */
    FSCONFIG_SET_FD         = 5,    /* Set parameter, supplying an object by fd */
    FSCONFIG_CMD_CREATE     = 6,    /* Invoke superblock creation */
    FSCONFIG_CMD_RECONFIGURE = 7,   /* Invoke superblock reconfiguration */
    FSCONFIG_CMD_CREATE_EXCL = 8,   /* Create new, fail if reusing existing */
};

static unsigned long fsconfig_ops[] = {
 FSCONFIG_SET_FLAG, FSCONFIG_SET_STRING, FSCONFIG_SET_BINARY, FSCONFIG_SET_PATH,
 FSCONFIG_SET_PATH_EMPTY, FSCONFIG_SET_FD, FSCONFIG_CMD_CREATE, FSCONFIG_CMD_RECONFIGURE,
 FSCONFIG_CMD_CREATE_EXCL,
};

struct syscallentry syscall_fsconfig = {
	.name = "fsconfig",
	.num_args = 5,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "cmd",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(fsconfig_ops),
	.arg3name = "_key",
	.arg3type = ARG_ADDRESS,
	.arg4name = "_value",
	.arg4type = ARG_ADDRESS,
	.arg5name = "aux",
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
};
