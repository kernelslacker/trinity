/*
 * SYSCALL_DEFINE4(request_key, const char __user *, _type,
	const char __user *, _description,
	const char __user *, _callout_info,
	key_serial_t, destringid)
 *
 * Without a sanitise hook the dispatcher hands the kernel random userspace
 * addresses for _type/_description/_callout_info.  strndup_user() on a
 * random pointer either EFAULTs or interns an effectively-random short
 * string; either way the kernel's lookup_user_key()/key_type lookup
 * rejects it before request_key_and_link() can run anything interesting
 * (key cache lookup, upcall, /sbin/request-key invocation, link into
 * destination keyring), so the syscall stays stuck on the early
 * EINVAL/EFAULT cliff and the OBJ_KEY_SERIAL producer pool (the wired
 * .ret_objtype = OBJ_KEY_SERIAL hook) never sees a successful return.
 *
 * Mirror add_key()'s shape: pick a real key-type string from the
 * registered set, build a randomized "<prefix>_<hex>" description so
 * dcache compares hit different slots, and either pass NULL callout_info
 * (lookup-only, no upcall) or a short string (drives the upcall path).
 * Destination keyring draws from the OBJ_KEY_SERIAL pool when populated
 * and falls back to a KEY_SPEC_* constant, so the link step actually
 * resolves.
 */
#include <linux/keyctl.h>
#include <stdio.h>
#include <string.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

static const char * const request_key_types[] = {
	"user", "logon", "keyring", "asymmetric", "big_key",
};

static const char * const request_key_desc_prefixes[] = {
	"trinity_key", "trinity_ring", "fuzz_key", "tk", "k",
	"trinity:scratch",
};

static const long request_key_specs[] = {
	KEY_SPEC_THREAD_KEYRING, KEY_SPEC_PROCESS_KEYRING,
	KEY_SPEC_SESSION_KEYRING, KEY_SPEC_USER_KEYRING,
	KEY_SPEC_USER_SESSION_KEYRING, KEY_SPEC_GROUP_KEYRING,
	KEY_SPEC_REQKEY_AUTH_KEY, KEY_SPEC_REQUESTOR_KEYRING,
};

static long request_key_pick_destring(void)
{
	/* ~3/4 KEY_SPEC_*, ~1/4 a live serial from the producer pool.
	 * get_random_key_serial() falls back to a low int when the pool
	 * is empty so this still terminates without the helper. */
	if (rnd_modulo_u32(4) == 0)
		return (long) get_random_key_serial();
	return request_key_specs[rnd_modulo_u32(ARRAY_SIZE(request_key_specs))];
}

static void sanitise_request_key(struct syscallrecord *rec)
{
	const char *type;
	const char *prefix;
	char *type_buf;
	char *desc_buf;
	char *callout_buf;

	type = request_key_types[rnd_modulo_u32(ARRAY_SIZE(request_key_types))];

	type_buf = (char *) get_writable_address(32);
	if (type_buf == NULL) {
		rec->a1 = 0;
		rec->a2 = 0;
		rec->a3 = 0;
		return;
	}
	strncpy(type_buf, type, 31);
	type_buf[31] = '\0';
	rec->a1 = (unsigned long) type_buf;

	desc_buf = (char *) get_writable_address(96);
	if (desc_buf == NULL) {
		rec->a2 = 0;
		rec->a3 = 0;
		return;
	}
	prefix = request_key_desc_prefixes[rnd_modulo_u32(ARRAY_SIZE(request_key_desc_prefixes))];
	/* logon-type keys require a "<subtype>:" prefix on the description; mirror the
	 * shape add_key uses for that type so request_key("logon", ...) also matches. */
	if (!strcmp(type, "logon"))
		snprintf(desc_buf, 96, "trinity:%s_%08x", prefix, rand32());
	else
		snprintf(desc_buf, 96, "%s_%08x", prefix, rand32());
	rec->a2 = (unsigned long) desc_buf;

	/* callout_info NULL means "lookup-only, don't upcall"; non-NULL drives
	 * the call_sbin_request_key() path and the keyring search retry. */
	switch (rnd_modulo_u32(3)) {
	case 0:
		rec->a3 = 0;
		break;
	default:
		callout_buf = (char *) get_writable_address(32);
		if (callout_buf == NULL) {
			rec->a3 = 0;
			break;
		}
		snprintf(callout_buf, 32, "trinity_%08x", rand32());
		rec->a3 = (unsigned long) callout_buf;
		break;
	}

	rec->a4 = (unsigned long) request_key_pick_destring();
}

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
	.rettype = RET_KEY_SERIAL_T,
	.ret_objtype = OBJ_KEY_SERIAL,
	.sanitise = sanitise_request_key,
	.group = GROUP_IPC,
};
