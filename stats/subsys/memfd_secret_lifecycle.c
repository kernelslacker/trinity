#include <stddef.h>
#include "stats-internal.h"

/* memfd_secret_lifecycle oracle and lifecycle counters.
 * oracle_pass: negative cross-process reads correctly denied (EPERM/EIO).
 * oracle_fired: negative reads that succeeded -- direct kernel bug signal.
 * conc_truncate_races: ftruncate round-trips from the concurrent stress
 *   thread; non-zero means the truncate path was exercised.
 * setup_rejected: invocations where memfd_secret(2) returned ENOSYS/EINVAL
 *   (CONFIG_SECRETMEM=n or secretmem.enable_secretmem=0). */
static const struct stat_field memfd_secret_lifecycle_fields[] = {
	STAT_FIELD_SUB(memfd_secret_lifecycle, oracle_pass),
	STAT_FIELD_SUB(memfd_secret_lifecycle, oracle_fired),
	STAT_FIELD_SUB(memfd_secret_lifecycle, conc_truncate_races),
	STAT_FIELD_SUB(memfd_secret_lifecycle, setup_rejected),
};

const struct stat_category memfd_secret_lifecycle_category =
	STAT_CATEGORY("memfd_secret_lifecycle",
	              memfd_secret_lifecycle.oracle_pass,
	              memfd_secret_lifecycle_fields);
