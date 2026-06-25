/*
 * SYSCALL_DEFINE5(keyctl, int, option, unsigned long, arg2, unsigned long, arg3,
	unsigned long, arg4, unsigned long, arg5)
 */
#include <linux/keyctl.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "objects.h"
#include "publish_resource.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "compat.h"

#ifndef KEYCTL_GET_PERSISTENT
#define KEYCTL_GET_PERSISTENT		22
#endif
#ifndef KEYCTL_DH_COMPUTE
#define KEYCTL_DH_COMPUTE		23
#endif
#ifndef KEYCTL_PKEY_QUERY
#define KEYCTL_PKEY_QUERY		24
#endif
#ifndef KEYCTL_PKEY_ENCRYPT
#define KEYCTL_PKEY_ENCRYPT		25
#endif
#ifndef KEYCTL_PKEY_DECRYPT
#define KEYCTL_PKEY_DECRYPT		26
#endif
#ifndef KEYCTL_PKEY_SIGN
#define KEYCTL_PKEY_SIGN		27
#endif
#ifndef KEYCTL_PKEY_VERIFY
#define KEYCTL_PKEY_VERIFY		28
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

/*
 * OBJ_KEY_SERIAL pool: producer-side cache of live key serials returned
 * by add_key/request_key (and the keyctl subcommands that mint keys).
 * Consumed by keyctl/add_key/request_key argument generation so subsequent
 * fuzzed calls hit serials the kernel actually has on hand instead of
 * dead-on-arrival random integers.  Lives in the per-child OBJ_LOCAL pool;
 * the pool destructor calls KEYCTL_INVALIDATE on shutdown so produced
 * keys don't leak past child lifetime.
 */
static void key_serial_destructor(struct object *obj)
{
	syscall(SYS_keyctl, KEYCTL_INVALIDATE, obj->keyserialobj.serial);
}

static void init_key_serial_pool(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_KEY_SERIAL);
	if (head == NULL)
		return;

	/* Wire the destructor on the OBJ_GLOBAL head; child OBJ_LOCAL
	 * pools inherit it from here at child fork time
	 * (init_object_lists() copies destroy/dump from the GLOBAL head). */
	head->destroy = &key_serial_destructor;
}

REG_GLOBAL_OBJ(key_serial, init_key_serial_pool);

void register_key_serial(int32_t serial)
{
	if (serial <= 0)
		return;

	publish_resource(OBJ_KEY_SERIAL, (unsigned long)serial, NULL);
}

int32_t get_random_key_serial(void)
{
	struct object *obj;

	if (objects_pool_empty(OBJ_LOCAL, OBJ_KEY_SERIAL) == true)
		return (int32_t) (1 + (rnd_modulo_u32(1000)));

	obj = get_random_object(OBJ_KEY_SERIAL, OBJ_LOCAL);
	if (obj == NULL)
		return (int32_t) (1 + (rnd_modulo_u32(1000)));
	return obj->keyserialobj.serial;
}

static unsigned long keyctl_cmds[] = {
	KEYCTL_GET_KEYRING_ID, KEYCTL_JOIN_SESSION_KEYRING, KEYCTL_UPDATE, KEYCTL_REVOKE,
	KEYCTL_CHOWN, KEYCTL_SETPERM, KEYCTL_DESCRIBE, KEYCTL_CLEAR,
	KEYCTL_LINK, KEYCTL_UNLINK, KEYCTL_SEARCH, KEYCTL_READ,
	KEYCTL_INSTANTIATE, KEYCTL_NEGATE, KEYCTL_SET_REQKEY_KEYRING, KEYCTL_SET_TIMEOUT,
	KEYCTL_ASSUME_AUTHORITY, KEYCTL_GET_SECURITY, KEYCTL_SESSION_TO_PARENT, KEYCTL_REJECT,
	KEYCTL_INSTANTIATE_IOV, KEYCTL_INVALIDATE, KEYCTL_GET_PERSISTENT,
	KEYCTL_DH_COMPUTE,
	KEYCTL_PKEY_QUERY, KEYCTL_PKEY_ENCRYPT, KEYCTL_PKEY_DECRYPT,
	KEYCTL_PKEY_SIGN, KEYCTL_PKEY_VERIFY,
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
	/* Three-way mix:
	 *   ~1/2  special keyring constant (KEY_SPEC_*)
	 *   ~3/8  live serial from the OBJ_KEY_SERIAL producer pool
	 *         (falls back to a low random integer if the pool is empty,
	 *         see get_random_key_serial())
	 *   ~1/8  fully random low integer to keep input-validation paths
	 *         exercised independent of pool state
	 */
	switch (rnd_modulo_u32(8)) {
	case 0 ... 3:
		return key_specs[rnd_modulo_u32(ARRAY_SIZE(key_specs))];
	case 4 ... 6:
		return (long) get_random_key_serial();
	default:
		return 1 + (rnd_modulo_u32(1000));
	}
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
	unsigned int r = rnd_modulo_u32(100);

	if (r < 50)
		return keyctl_cmds_common[rnd_modulo_u32(ARRAY_SIZE(keyctl_cmds_common))];
	if (r < 90)
		return keyctl_cmds_rare[rnd_modulo_u32(ARRAY_SIZE(keyctl_cmds_rare))];
	return (unsigned long) rand32();
}

static void sanitise_keyctl_get_keyring_id(struct syscallrecord *rec)
{
	/* arg2=key, arg3=create flag */
	rec->a2 = (unsigned long) random_key_id();
	rec->a3 = RAND_BOOL();
}

static void sanitise_keyctl_join_session_keyring(struct syscallrecord *rec)
{
	char *buf;

	/* arg2=name (or NULL to join anonymous) */
	if (RAND_BOOL()) {
		rec->a2 = 0;
	} else {
		buf = (char *) get_writable_address(32);
		if (buf == NULL)
			return;
		strncpy(buf, "trinity_sess", 31);
		buf[31] = '\0';
		rec->a2 = (unsigned long) buf;
	}
}

static void sanitise_keyctl_update(struct syscallrecord *rec)
{
	char *buf;

	/* arg2=key, arg3=payload, arg4=plen */
	rec->a2 = (unsigned long) random_key_id();
	buf = (char *) get_writable_address(64);
	if (buf == NULL)
		return;
	strncpy(buf, "test_payload", 63);
	buf[63] = '\0';
	rec->a3 = (unsigned long) buf;
	rec->a4 = strlen("test_payload");
}

static void sanitise_keyctl_key_only(struct syscallrecord *rec)
{
	/* arg2=key */
	rec->a2 = (unsigned long) random_key_id();
}

static void sanitise_keyctl_chown(struct syscallrecord *rec)
{
	/* arg2=key, arg3=uid, arg4=gid (-1 = no change) */
	rec->a2 = (unsigned long) random_key_id();
	rec->a3 = RAND_BOOL() ? (unsigned long) -1 : (unsigned long)(rnd_modulo_u32(65536));
	rec->a4 = RAND_BOOL() ? (unsigned long) -1 : (unsigned long)(rnd_modulo_u32(65536));
}

static void sanitise_keyctl_setperm(struct syscallrecord *rec)
{
	/* arg2=key, arg3=perm mask */
	rec->a2 = (unsigned long) random_key_id();
	rec->a3 = rand32();
}

static void sanitise_keyctl_read_like(struct syscallrecord *rec)
{
	char *buf;

	/* arg2=key, arg3=buffer, arg4=buflen */
	rec->a2 = (unsigned long) random_key_id();
	buf = (char *) get_writable_address(256);
	if (buf == NULL)
		return;
	rec->a3 = (unsigned long) buf;
	rec->a4 = 256;
	avoid_shared_buffer_out(&rec->a3, rec->a4);
}

static void sanitise_keyctl_link(struct syscallrecord *rec)
{
	/* arg2=key, arg3=keyring */
	rec->a2 = (unsigned long) random_key_id();
	rec->a3 = (unsigned long) random_key_id();
}

static void sanitise_keyctl_search(struct syscallrecord *rec)
{
	char *buf;

	/* arg2=keyring, arg3=type, arg4=description, arg5=dest_keyring */
	rec->a2 = (unsigned long) random_key_id();
	buf = (char *) get_writable_address(32);
	if (buf == NULL)
		return;
	strncpy(buf, "user", 31);
	buf[31] = '\0';
	rec->a3 = (unsigned long) buf;
	buf = (char *) get_writable_address(32);
	if (buf == NULL)
		return;
	strncpy(buf, "trinity_key", 31);
	buf[31] = '\0';
	rec->a4 = (unsigned long) buf;
	rec->a5 = (unsigned long) random_key_id();
}

static void sanitise_keyctl_set_reqkey_keyring(struct syscallrecord *rec)
{
	/* arg2=reqkey destination */
	rec->a2 = rnd_modulo_u32(8);	/* KEY_REQKEY_DEFL_* range */
}

static void sanitise_keyctl_set_timeout(struct syscallrecord *rec)
{
	/* arg2=key, arg3=timeout_secs */
	rec->a2 = (unsigned long) random_key_id();
	rec->a3 = rnd_modulo_u32(3600);
}

static void sanitise_keyctl_instantiate(struct syscallrecord *rec)
{
	char *buf;

	/* arg2=key, arg3=payload, arg4=plen, arg5=dest_keyring */
	rec->a2 = (unsigned long) random_key_id();
	buf = (char *) get_writable_address(64);
	rec->a3 = (unsigned long) buf;
	rec->a4 = 1 + (rnd_modulo_u32(63));
	rec->a5 = (unsigned long) random_key_id();
}

static void sanitise_keyctl_negate(struct syscallrecord *rec)
{
	/* arg2=key, arg3=timeout, arg4=dest_keyring */
	rec->a2 = (unsigned long) random_key_id();
	rec->a3 = rnd_modulo_u32(60);
	rec->a4 = (unsigned long) random_key_id();
}

static void sanitise_keyctl_reject(struct syscallrecord *rec)
{
	/* arg2=key, arg3=timeout, arg4=error, arg5=dest_keyring */
	rec->a2 = (unsigned long) random_key_id();
	rec->a3 = rnd_modulo_u32(60);
	rec->a4 = 1 + (rnd_modulo_u32(4095));	/* errno range: 1..MAX_ERRNO */
	rec->a5 = (unsigned long) random_key_id();
}

static void sanitise_keyctl_move(struct syscallrecord *rec)
{
	/* arg2=key, arg3=from_keyring, arg4=to_keyring, arg5=flags */
	rec->a2 = (unsigned long) random_key_id();
	rec->a3 = (unsigned long) random_key_id();
	rec->a4 = (unsigned long) random_key_id();
	rec->a5 = RAND_BOOL() ? KEYCTL_MOVE_EXCL : 0;
}

static void sanitise_keyctl_get_persistent(struct syscallrecord *rec)
{
	/* arg2=uid, arg3=dest_keyring */
	rec->a2 = RAND_BOOL() ? (unsigned long) -1 : (unsigned long)(rnd_modulo_u32(65536));
	rec->a3 = (unsigned long) random_key_id();
}

static void sanitise_keyctl_capabilities(struct syscallrecord *rec)
{
	char *buf;

	/* arg2=buffer, arg3=buflen */
	buf = (char *) get_writable_address(64);
	rec->a2 = (unsigned long) buf;
	rec->a3 = 64;
	avoid_shared_buffer_out(&rec->a2, rec->a3);
}

static void sanitise_keyctl_watch_key(struct syscallrecord *rec)
{
	char *buf;
	/* arg2=key, arg3=watch_queue_fd, arg4=filter (NULL=remove) */
	int fd = -1;

	/*
	 * Same OBJ_GLOBAL lockless-reader UAF class that the
	 * fds/sockets.c get_rand_socketinfo() wireup defends against
	 * (sanitise-hook-audit-2026-05-05 row 9): the parent can
	 * destroy and recycle the OBJ_FD_WATCH_QUEUE slot between the
	 * lockless pick and our deref of obj->watch_queueobj.fd,
	 * leaving a stale or recycled obj pointer that would feed
	 * garbage into rec->a3 as the watch_queue fd argument to
	 * KEYCTL_WATCH_KEY.  Mirror the wireup shape used by
	 * get_rand_socketinfo() — versioned pick + slot-version
	 * handle re-validation immediately before the deref — but
	 * keep it inline since this is the only sanitise-hook
	 * consumer of obj->watch_queueobj.
	 */
	if (objects_empty(OBJ_FD_WATCH_QUEUE) == false) {
		for (int i = 0; i < 1000; i++) {
			struct object *obj;

			obj = get_random_object(OBJ_FD_WATCH_QUEUE, OBJ_GLOBAL);
			if (!objpool_check(obj, OBJ_FD_WATCH_QUEUE))
				continue;

			fd = obj->watch_queueobj.fd;
			break;
		}
	}
	rec->a2 = (unsigned long) random_key_id();
	rec->a3 = (unsigned long) fd;
	if (RAND_BOOL()) {
		rec->a4 = 0;
	} else {
		buf = (char *) get_writable_address(64);
		rec->a4 = (unsigned long) buf;
	}
	if (rec->a4)
		avoid_shared_buffer_out(&rec->a4, 64);
}

static void sanitise_keyctl(struct syscallrecord *rec)
{
	unsigned long cmd;

	rec->a1 = pick_keyctl_cmd();
	cmd = rec->a1;

	switch (cmd) {
	case KEYCTL_GET_KEYRING_ID:
		sanitise_keyctl_get_keyring_id(rec);
		break;

	case KEYCTL_JOIN_SESSION_KEYRING:
		sanitise_keyctl_join_session_keyring(rec);
		break;

	case KEYCTL_UPDATE:
		sanitise_keyctl_update(rec);
		break;

	case KEYCTL_REVOKE:
	case KEYCTL_CLEAR:
	case KEYCTL_INVALIDATE:
	case KEYCTL_ASSUME_AUTHORITY:
		sanitise_keyctl_key_only(rec);
		break;

	case KEYCTL_CHOWN:
		sanitise_keyctl_chown(rec);
		break;

	case KEYCTL_SETPERM:
		sanitise_keyctl_setperm(rec);
		break;

	case KEYCTL_DESCRIBE:
	case KEYCTL_READ:
	case KEYCTL_GET_SECURITY:
		sanitise_keyctl_read_like(rec);
		break;

	case KEYCTL_LINK:
	case KEYCTL_UNLINK:
		sanitise_keyctl_link(rec);
		break;

	case KEYCTL_SEARCH:
		sanitise_keyctl_search(rec);
		break;

	case KEYCTL_SET_REQKEY_KEYRING:
		sanitise_keyctl_set_reqkey_keyring(rec);
		break;

	case KEYCTL_SET_TIMEOUT:
		sanitise_keyctl_set_timeout(rec);
		break;

	case KEYCTL_INSTANTIATE:
		sanitise_keyctl_instantiate(rec);
		break;

	case KEYCTL_NEGATE:
		sanitise_keyctl_negate(rec);
		break;

	case KEYCTL_REJECT:
		sanitise_keyctl_reject(rec);
		break;

	case KEYCTL_MOVE:
		sanitise_keyctl_move(rec);
		break;

	case KEYCTL_GET_PERSISTENT:
		sanitise_keyctl_get_persistent(rec);
		break;

	case KEYCTL_CAPABILITIES:
		sanitise_keyctl_capabilities(rec);
		break;

	case KEYCTL_WATCH_KEY:
		sanitise_keyctl_watch_key(rec);
		break;

	case KEYCTL_SESSION_TO_PARENT:
		/* no args */
		break;
	}
}

/*
 * Per-cmd producer wireup.  keyctl is multiplexed so the dispatcher's
 * generic .ret_objtype hook can't be used: only some subcommands return
 * a freshly minted key_serial_t in rec->retval, the rest return 0, a
 * bytes-written count, or -errno.  Funnel the producer subcommands
 * through register_key_serial() so the OBJ_KEY_SERIAL pool sees the
 * serials they mint, mirroring the .ret_objtype = OBJ_KEY_SERIAL
 * annotation that add_key/request_key already use.
 *
 * Producers wired here (all return key_serial_t > 0 on success):
 *   KEYCTL_GET_KEYRING_ID       - returns the resolved keyring's serial
 *   KEYCTL_JOIN_SESSION_KEYRING - returns the joined/created session keyring
 *   KEYCTL_SEARCH               - returns the found key's serial
 *   KEYCTL_GET_PERSISTENT       - returns the persistent keyring's serial
 *
 * Not wired: KEYCTL_INSTANTIATE / KEYCTL_NEGATE / KEYCTL_REJECT /
 * KEYCTL_INSTANTIATE_IOV all return 0 on success — they operate on an
 * already-allocated key, they don't mint a new serial.  Pool teardown
 * is handled by the existing OBJ_KEY_SERIAL destructor (KEYCTL_INVALIDATE).
 */
static void post_keyctl(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret <= 0 || ret > INT32_MAX)
		return;

	switch (get_arg_snapshot(rec, 1)) {
	case KEYCTL_GET_KEYRING_ID:
	case KEYCTL_JOIN_SESSION_KEYRING:
	case KEYCTL_SEARCH:
	case KEYCTL_GET_PERSISTENT:
		register_key_serial((int32_t) ret);
		break;
	default:
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
	.post = post_keyctl,
	/* a1 (cmd) drives post_keyctl's switch -- it selects which
	 * KEYCTL_* class the retval bound check attributes to, and only
	 * the keyring/serial-minting commands feed register_key_serial().
	 * Shadow it so a sibling stomp between dispatch and post cannot
	 * swing the switch into a different case and either register a
	 * fabricated serial under the wrong cmd or skip a legitimate one;
	 * mismatch bumps arg_shadow_stomp from inside get_arg_snapshot()
	 * and the handler still dispatches against the cmd the kernel
	 * actually executed. */
	.arg_snapshot_mask = (1u << 0),
};
