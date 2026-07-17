#include <stddef.h>
#include "stats-internal.h"

/* uid_change_logged: check_uid saw the child's uid drift away from
 * orig_uid + overflowuid.  Non-root drifts log-and-continue rather than
 * hard-bailing, so the drift count is the only positive signal that a
 * fuzzed setresuid/setreuid/setfsuid landed inside an unshared user
 * namespace.  A single-field category surfaces the count in both dumps;
 * text self-gates so a stable-uid run emits nothing. */
static const struct stat_field uid_change_fields[] = {
	STAT_FIELD_SUB(uid_change, logged),
};

const struct stat_category uid_change_category =
	STAT_CATEGORY("uid_change",
	              uid_change.logged,
	              uid_change_fields);
