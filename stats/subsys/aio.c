#include <stddef.h>
#include "stats-internal.h"

/* aio_submitted: iocbs the kernel accepted on io_submit's success branch
 * (retval > 0 and within [0, nr]).  A single-field category sits next to
 * its iouring siblings so a quiet success window is distinguishable from
 * a quiet rejection window in both JSON and text dumps. */
static const struct stat_field aio_fields[] = {
	STAT_FIELD_SUB(aio, submitted),
};

const struct stat_category aio_category =
	STAT_CATEGORY("aio",
	              aio.submitted,
	              aio_fields);
