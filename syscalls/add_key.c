/*
 * SYSCALL_DEFINE5(add_key, const char __user *, _type,
	const char __user *, _description,
	const void __user *, _payload,
	size_t, plen,
	key_serial_t, ringid)
 *
 * On success add_key() returns the serial number of the key it created or updated.
 * On error, the value -1 will be returned and errno will have been set to an appropriate error.
 */
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/keyctl.h>
#include "random.h"
#include "sanitise.h"
#include "trinity.h"

static const char *keytypes[] = {
	"user", "keyring", "big_key",
};

static void sanitise_add_key(struct syscallrecord *rec)
{
	rec->a1 = (unsigned long) RAND_ARRAY(keytypes);
}

static unsigned long addkey_ringids[] = {
	KEY_SPEC_THREAD_KEYRING,
	KEY_SPEC_PROCESS_KEYRING,
	KEY_SPEC_SESSION_KEYRING,
	KEY_SPEC_USER_KEYRING,
	KEY_SPEC_USER_SESSION_KEYRING,
	KEY_SPEC_GROUP_KEYRING,
	KEY_SPEC_REQKEY_AUTH_KEY,
	KEY_SPEC_REQUESTOR_KEYRING,
};

static void post_add_key(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret <= 0 || ret > INT32_MAX) {
		if (ret > 0)
			output(0, "add_key oracle: returned key_serial_t %ld is out of range (must be 1..INT32_MAX)\n",
				ret);
		return;
	}

	syscall(SYS_keyctl, KEYCTL_INVALIDATE, ret);
}

struct syscallentry syscall_add_key = {
	.name = "add_key",
	.num_args = 5,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_LEN, [4] = ARG_OP },
	.argname = { [0] = "_type", [1] = "_description", [2] = "_payload", [3] = "plen", [4] = "ringid" },
	.arg_params[4].list = ARGLIST(addkey_ringids),
	.rettype = RET_KEY_SERIAL_T,
	.sanitise = sanitise_add_key,
	.post = post_add_key,
	.group = GROUP_IPC,
};
