/*
 * SYSCALL_DEFINE5(keyctl, int, option, unsigned long, arg2, unsigned long, arg3,
	unsigned long, arg4, unsigned long, arg5)
 */
#include <linux/keyctl.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"
#include "compat.h"

#ifndef KEYCTL_INVALIDATE
#define KEYCTL_INVALIDATE		21
#endif
#ifndef KEYCTL_GET_PERSISTENT
#define KEYCTL_GET_PERSISTENT		22
#endif
#ifndef KEYCTL_RESTRICT_KEYRING
#define KEYCTL_RESTRICT_KEYRING		29
#endif
#ifndef KEYCTL_MOVE
#define KEYCTL_MOVE			30
#endif
#ifndef KEYCTL_CAPABILITIES
#define KEYCTL_CAPABILITIES		31
#endif
#ifndef KEYCTL_WATCH_KEY
#define KEYCTL_WATCH_KEY		32
#endif

static unsigned long keyctl_cmds[] = {
	KEYCTL_GET_KEYRING_ID, KEYCTL_JOIN_SESSION_KEYRING, KEYCTL_UPDATE, KEYCTL_REVOKE,
	KEYCTL_CHOWN, KEYCTL_SETPERM, KEYCTL_DESCRIBE, KEYCTL_CLEAR,
	KEYCTL_LINK, KEYCTL_UNLINK, KEYCTL_SEARCH, KEYCTL_READ,
	KEYCTL_INSTANTIATE, KEYCTL_NEGATE, KEYCTL_SET_REQKEY_KEYRING, KEYCTL_SET_TIMEOUT,
	KEYCTL_ASSUME_AUTHORITY, KEYCTL_GET_SECURITY, KEYCTL_SESSION_TO_PARENT, KEYCTL_REJECT,
	KEYCTL_INSTANTIATE_IOV, KEYCTL_INVALIDATE, KEYCTL_GET_PERSISTENT,
	KEYCTL_RESTRICT_KEYRING, KEYCTL_MOVE, KEYCTL_CAPABILITIES, KEYCTL_WATCH_KEY,
};

static long key_specs[] = {
	KEY_SPEC_THREAD_KEYRING, KEY_SPEC_PROCESS_KEYRING,
	KEY_SPEC_SESSION_KEYRING, KEY_SPEC_USER_KEYRING,
	KEY_SPEC_USER_SESSION_KEYRING, KEY_SPEC_GROUP_KEYRING,
	KEY_SPEC_REQKEY_AUTH_KEY, KEY_SPEC_REQUESTOR_KEYRING,
};

static long random_key_id(void)
{
	/* Half special keyrings, half random serial numbers. */
	if (RAND_BOOL())
		return key_specs[rand() % ARRAY_SIZE(key_specs)];
	return 1 + (rand() % 1000);
}

/*
 * Stratified cmd picker.  Uniform sampling across the full cmd list under-
 * exercises the rarer kernel paths (instantiate_iov/move/watch/restrict/
 * persistent/session_to_parent/perm-mgmt), because most of the cmds in
 * keyctl_cmds[] route into a small set of common key lookup/read paths.
 * Bias the picker so the rare paths get hit ~40% of the time, and also
 * drop in a fully random cmd ~10% of the time to cover out-of-table values
 * that exercise the kernel's input validation.
 */
static const unsigned long keyctl_cmds_common[] = {
	KEYCTL_GET_KEYRING_ID, KEYCTL_REVOKE, KEYCTL_READ,
	KEYCTL_DESCRIBE, KEYCTL_LINK, KEYCTL_UNLINK,
};

static const unsigned long keyctl_cmds_rare[] = {
	KEYCTL_INSTANTIATE_IOV, KEYCTL_MOVE, KEYCTL_WATCH_KEY,
	KEYCTL_RESTRICT_KEYRING, KEYCTL_GET_PERSISTENT,
	KEYCTL_SESSION_TO_PARENT, KEYCTL_JOIN_SESSION_KEYRING,
	KEYCTL_SET_REQKEY_KEYRING, KEYCTL_CHOWN, KEYCTL_SETPERM,
};

static unsigned long pick_keyctl_cmd(void)
{
	unsigned int r = rand() % 100;

	if (r < 50)
		return keyctl_cmds_common[rand() % ARRAY_SIZE(keyctl_cmds_common)];
	if (r < 90)
		return keyctl_cmds_rare[rand() % ARRAY_SIZE(keyctl_cmds_rare)];
	return (unsigned long) rand32();
}

static void sanitise_keyctl(struct syscallrecord *rec)
{
	unsigned long cmd;
	char *buf;

	rec->a1 = pick_keyctl_cmd();
	cmd = rec->a1;

	switch (cmd) {
	case KEYCTL_GET_KEYRING_ID:
		/* arg2=key, arg3=create flag */
		rec->a2 = (unsigned long) random_key_id();
		rec->a3 = RAND_BOOL();
		break;

	case KEYCTL_JOIN_SESSION_KEYRING:
		/* arg2=name (or NULL to join anonymous) */
		if (RAND_BOOL()) {
			rec->a2 = 0;
		} else {
			buf = (char *) get_writable_address(32);
			strncpy(buf, "trinity_sess", 31);
			buf[31] = '\0';
			rec->a2 = (unsigned long) buf;
		}
		break;

	case KEYCTL_UPDATE:
		/* arg2=key, arg3=payload, arg4=plen */
		rec->a2 = (unsigned long) random_key_id();
		buf = (char *) get_writable_address(64);
		strncpy(buf, "test_payload", 63);
		buf[63] = '\0';
		rec->a3 = (unsigned long) buf;
		rec->a4 = strlen("test_payload");
		break;

	case KEYCTL_REVOKE:
	case KEYCTL_CLEAR:
	case KEYCTL_INVALIDATE:
	case KEYCTL_ASSUME_AUTHORITY:
		/* arg2=key */
		rec->a2 = (unsigned long) random_key_id();
		break;

	case KEYCTL_CHOWN:
		/* arg2=key, arg3=uid, arg4=gid (-1 = no change) */
		rec->a2 = (unsigned long) random_key_id();
		rec->a3 = RAND_BOOL() ? (unsigned long) -1 : (unsigned long)(rand() % 65536);
		rec->a4 = RAND_BOOL() ? (unsigned long) -1 : (unsigned long)(rand() % 65536);
		break;

	case KEYCTL_SETPERM:
		/* arg2=key, arg3=perm mask */
		rec->a2 = (unsigned long) random_key_id();
		rec->a3 = rand32();
		break;

	case KEYCTL_DESCRIBE:
	case KEYCTL_READ:
	case KEYCTL_GET_SECURITY:
		/* arg2=key, arg3=buffer, arg4=buflen */
		rec->a2 = (unsigned long) random_key_id();
		buf = (char *) get_writable_address(256);
		rec->a3 = (unsigned long) buf;
		rec->a4 = 256;
		break;

	case KEYCTL_LINK:
	case KEYCTL_UNLINK:
		/* arg2=key, arg3=keyring */
		rec->a2 = (unsigned long) random_key_id();
		rec->a3 = (unsigned long) random_key_id();
		break;

	case KEYCTL_SEARCH:
		/* arg2=keyring, arg3=type, arg4=description, arg5=dest_keyring */
		rec->a2 = (unsigned long) random_key_id();
		buf = (char *) get_writable_address(32);
		strncpy(buf, "user", 31);
		buf[31] = '\0';
		rec->a3 = (unsigned long) buf;
		buf = (char *) get_writable_address(32);
		strncpy(buf, "trinity_key", 31);
		buf[31] = '\0';
		rec->a4 = (unsigned long) buf;
		rec->a5 = (unsigned long) random_key_id();
		break;

	case KEYCTL_SET_REQKEY_KEYRING:
		/* arg2=reqkey destination */
		rec->a2 = rand() % 8;	/* KEY_REQKEY_DEFL_* range */
		break;

	case KEYCTL_SET_TIMEOUT:
		/* arg2=key, arg3=timeout_secs */
		rec->a2 = (unsigned long) random_key_id();
		rec->a3 = rand() % 3600;
		break;

	case KEYCTL_INSTANTIATE:
		/* arg2=key, arg3=payload, arg4=plen, arg5=dest_keyring */
		rec->a2 = (unsigned long) random_key_id();
		buf = (char *) get_writable_address(64);
		rec->a3 = (unsigned long) buf;
		rec->a4 = 1 + (rand() % 63);
		rec->a5 = (unsigned long) random_key_id();
		break;

	case KEYCTL_NEGATE:
		/* arg2=key, arg3=timeout, arg4=dest_keyring */
		rec->a2 = (unsigned long) random_key_id();
		rec->a3 = rand() % 60;
		rec->a4 = (unsigned long) random_key_id();
		break;

	case KEYCTL_REJECT:
		/* arg2=key, arg3=timeout, arg4=error, arg5=dest_keyring */
		rec->a2 = (unsigned long) random_key_id();
		rec->a3 = rand() % 60;
		rec->a4 = 1 + (rand() % 4095);	/* errno range: 1..MAX_ERRNO */
		rec->a5 = (unsigned long) random_key_id();
		break;

	case KEYCTL_MOVE:
		/* arg2=key, arg3=from_keyring, arg4=to_keyring, arg5=flags */
		rec->a2 = (unsigned long) random_key_id();
		rec->a3 = (unsigned long) random_key_id();
		rec->a4 = (unsigned long) random_key_id();
		rec->a5 = RAND_BOOL() ? KEYCTL_MOVE_EXCL : 0;
		break;

	case KEYCTL_GET_PERSISTENT:
		/* arg2=uid, arg3=dest_keyring */
		rec->a2 = RAND_BOOL() ? (unsigned long) -1 : (unsigned long)(rand() % 65536);
		rec->a3 = (unsigned long) random_key_id();
		break;

	case KEYCTL_CAPABILITIES:
		/* arg2=buffer, arg3=buflen */
		buf = (char *) get_writable_address(64);
		rec->a2 = (unsigned long) buf;
		rec->a3 = 64;
		break;

	case KEYCTL_SESSION_TO_PARENT:
		/* no args */
		break;
	}
}

struct syscallentry syscall_keyctl = {
	.name = "keyctl",
	.num_args = 5,
	.argtype = { [0] = ARG_OP },
	.argname = { [0] = "cmd", [1] = "arg2", [2] = "arg3", [3] = "arg4", [4] = "arg5" },
	.arg_params[0].list = ARGLIST(keyctl_cmds),
	.group = GROUP_IPC,
	.sanitise = sanitise_keyctl,
};
