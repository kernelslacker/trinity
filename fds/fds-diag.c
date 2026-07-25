#include <stddef.h>
#include <string.h>

#include "fd.h"
#include "fds-internal.h"

/*
 * Per-init failure-reason slot.  __open_fds() resets these immediately
 * before calling provider->init(); on a false return it logs whichever
 * reason the provider stamped via fd_provider_init_fail().  A provider
 * that returns false without calling the helper leaves the slot at
 * FD_INIT_REASON_NONE and the dispatcher falls back to the bare
 * "Error during initialization of <name>" line.
 */
enum fd_init_reason last_init_reason;
int last_init_errno;
char last_init_detail[128];

void fd_provider_init_fail(enum fd_init_reason reason, int captured_errno,
			   const char *detail)
{
	last_init_reason = reason;
	last_init_errno = captured_errno;
	if (detail != NULL) {
		strncpy(last_init_detail, detail, sizeof(last_init_detail) - 1);
		last_init_detail[sizeof(last_init_detail) - 1] = '\0';
	} else {
		last_init_detail[0] = '\0';
	}
}

const char *fd_init_reason_name(enum fd_init_reason r)
{
	switch (r) {
	case FD_INIT_REASON_NONE:		return "none";
	case FD_INIT_REASON_ERRNO:		return "errno";
	case FD_INIT_REASON_CONFIG_ABSENT:	return "config-absent";
	case FD_INIT_REASON_CAP_MISSING:	return "cap-missing";
	case FD_INIT_REASON_RESOURCE:		return "resource";
	}
	return "unknown";
}
