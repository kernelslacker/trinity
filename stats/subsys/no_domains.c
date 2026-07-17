#include <stddef.h>
#include "stats-internal.h"

/* no_domains_runtime_skipped: socket families auto-marked in no_domains[]
 * at startup because socket() probes returned EAFNOSUPPORT/EPROTONOSUPPORT
 * for both SOCK_STREAM and SOCK_DGRAM.  Non-zero tells the operator how
 * many random-syscall socket() picks per cycle the running kernel can
 * never reach, and confirms the auto-skip ran (vs. --exclude-domains by
 * hand).  Text self-gates so a fully-supported build emits nothing. */
static const struct stat_field no_domains_fields[] = {
	STAT_FIELD_SUB(no_domains, runtime_skipped),
};

const struct stat_category no_domains_category =
	STAT_CATEGORY("no_domains",
	              no_domains.runtime_skipped,
	              no_domains_fields);
