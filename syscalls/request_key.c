/*
 * SYSCALL_DEFINE4(request_key, const char __user *, _type,
	const char __user *, _description,
	const char __user *, _callout_info,
	key_serial_t, destringid)
 */
#include <linux/keyctl.h>
#include "sanitise.h"

static unsigned long request_key_ids[] = {
	KEY_SPEC_THREAD_KEYRING, KEY_SPEC_PROCESS_KEYRING,
	KEY_SPEC_SESSION_KEYRING, KEY_SPEC_USER_KEYRING,
	KEY_SPEC_USER_SESSION_KEYRING, KEY_SPEC_GROUP_KEYRING,
	KEY_SPEC_REQKEY_AUTH_KEY, KEY_SPEC_REQUESTOR_KEYRING,
};

struct syscallentry syscall_request_key = {
	.name = "request_key",
	.num_args = 4,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_OP },
	.argname = { [0] = "_type", [1] = "_description", [2] = "_callout_info", [3] = "destringid" },
	.arg_params[3].list = ARGLIST(request_key_ids),
	.group = GROUP_IPC,
};
