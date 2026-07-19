/*
 * cmp_hints JSON emitter for --stats-json.  Reads the durable
 * per-nr pool inside cmp_hints_shm and emits a two-number summary
 * (total surviving hints and how many syscalls own any).  Short-
 * circuits to ",\"cmp_hints\":null" when the shm is not attached.
 */

#include <stdio.h>
#include "cmp_hints.h"
#include "stats/json/internal.h"

void json_emit_cmp_hints_section(void)
{
	unsigned int i, a, total_hints = 0, syscalls_with_hints = 0;

	if (cmp_hints_shm == NULL) {
		fputs(",\"cmp_hints\":null", stdout);
		return;
	}

	/* Per-arch slots count individually so the histogram reflects the
	 * post-arch-split storage shape; under biarch the 32-bit and
	 * 64-bit halves of the same nr are unrelated syscalls. */
	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		for (a = 0; a < 2; a++) {
			unsigned int n = cmp_hints_pool_safe_count(&cmp_hints_shm->pools[i][a]);

			if (n > 0) {
				total_hints += n;
				syscalls_with_hints++;
			}
		}
	}
	printf(",\"cmp_hints\":{\"values_total\":%u,\"syscalls_with_hints\":%u}",
		total_hints, syscalls_with_hints);
}
