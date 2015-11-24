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
	.arg1name = "_type",
	.arg1type = ARG_ADDRESS,
	.arg2name = "_description",
	.arg2type = ARG_ADDRESS,
	.arg3name = "_callout_info",
	.arg3type = ARG_ADDRESS,
	.arg4name = "destringid",
	.arg4type = ARG_OP,
	.arg4list = ARGLIST(request_key_ids),
};
