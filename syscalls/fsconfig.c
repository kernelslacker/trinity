/*
 *  SYSCALL_DEFINE5(fsconfig, int, fd, unsigned int, cmd, const char __user *, _key, const void __user *, _value, int, aux)
 */
#include <fcntl.h>
#include <string.h>
#include "fd.h"
#include "object-types.h"
#include "random.h"
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

/* Common mount option keys */
static const char *config_keys[] = {
	"source", "ro", "rw", "nosuid", "nodev", "noexec",
	"sync", "dirsync", "noatime", "nodiratime", "relatime",
	"lazytime", "errors", "data", "commit", "barrier",
	"discard", "max_ratio", "nr_inodes", "size", "mode",
};

static void fill_key(char *buf)
{
	const char *key = config_keys[rand() % ARRAY_SIZE(config_keys)];
	strncpy(buf, key, 31);
	buf[31] = '\0';
}

static void sanitise_fsconfig(struct syscallrecord *rec)
{
	unsigned long cmd;
	char *key, *val;

	cmd = rec->a2;

	switch (cmd) {
	case FSCONFIG_SET_FLAG:
		/* key only, no value */
		key = (char *) get_writable_address(32);
		fill_key(key);
		rec->a3 = (unsigned long) key;
		rec->a4 = 0;
		rec->a5 = 0;
		break;

	case FSCONFIG_SET_STRING:
		key = (char *) get_writable_address(32);
		fill_key(key);
		val = (char *) get_writable_address(64);
		switch (rand() % 3) {
		case 0: strncpy(val, "1", 63); break;
		case 1: strncpy(val, "/dev/sda1", 63); break;
		default: strncpy(val, "defaults", 63); break;
		}
		val[63] = '\0';
		rec->a3 = (unsigned long) key;
		rec->a4 = (unsigned long) val;
		rec->a5 = 0;
		break;

	case FSCONFIG_SET_BINARY:
		key = (char *) get_writable_address(32);
		fill_key(key);
		val = (char *) get_writable_address(64);
		rec->a3 = (unsigned long) key;
		rec->a4 = (unsigned long) val;
		rec->a5 = 1 + (rand() % 64);	/* aux = length */
		break;

	case FSCONFIG_SET_PATH:
	case FSCONFIG_SET_PATH_EMPTY:
		key = (char *) get_writable_address(32);
		fill_key(key);
		val = (char *) get_writable_address(32);
		strncpy(val, "/", 31);
		val[31] = '\0';
		rec->a3 = (unsigned long) key;
		rec->a4 = (unsigned long) val;
		rec->a5 = AT_FDCWD;
		break;

	case FSCONFIG_SET_FD:
		key = (char *) get_writable_address(32);
		fill_key(key);
		rec->a3 = (unsigned long) key;
		rec->a4 = 0;
		rec->a5 = get_random_fd();	/* aux = fd */
		break;

	case FSCONFIG_CMD_CREATE:
	case FSCONFIG_CMD_RECONFIGURE:
	case FSCONFIG_CMD_CREATE_EXCL:
		/* No key, value, or aux */
		rec->a3 = 0;
		rec->a4 = 0;
		rec->a5 = 0;
		break;
	}
}

struct syscallentry syscall_fsconfig = {
	.name = "fsconfig",
	.num_args = 5,
	.argtype = { [0] = ARG_FD_FS_CTX, [1] = ARG_OP },
	.argname = { [0] = "fd", [1] = "cmd", [2] = "_key", [3] = "_value", [4] = "aux" },
	.arg_params[1].list = ARGLIST(fsconfig_ops),
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_fsconfig,
};
