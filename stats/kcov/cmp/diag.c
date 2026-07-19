/*
 * Steady periodic diagnostic reporting.
 *
 * Owns the modes block (cumulative PC/CMP child population mix), the
 * KCOV CMP DIAG first-failure-wins errno block, and the KCOV PC DIAG
 * first-failure-wins errno + retry counters block.  Separated from the
 * experiment/cohort rows so steady periodic diagnostics have a home
 * that doesn't move when a new cohort renderer lands.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/utsname.h>
#include <stdio.h>
#include "arch.h"
#include "kcov.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "trinity.h"
#include "utils.h"

#include "stats/kcov/cmp/internal.h"

/*
 * Per-mode child population (cumulative).  Realised PC/CMP mode mix in the
 * time series so the operator can read the split at each dump window rather
 * than only at shutdown.
 */
void kcov_cmp_render_modes_block(void)
{
	unsigned int pc_kids, cmp_kids;

	pc_kids  = __atomic_load_n(&kcov_shm->pc_mode_children,  __ATOMIC_RELAXED);
	cmp_kids = __atomic_load_n(&kcov_shm->cmp_mode_children, __ATOMIC_RELAXED);

	if ((pc_kids | cmp_kids) != 0) {
		stats_log_write("KCOV CMP modes (cumulative):\n");
		stats_log_write("  pc_mode_children=%u cmp_mode_children=%u\n",
				pc_kids, cmp_kids);
	}
}
void kcov_cmp_render_diag_errnos_block(void)
{
	char init_buf[256];
	char rt_buf[256];
	int ni, nr;

	ni = kcov_cmp_diag_format(init_buf, sizeof(init_buf),
				  KCOV_CMP_DIAG_INIT);
	nr = kcov_cmp_diag_format(rt_buf, sizeof(rt_buf),
				  KCOV_CMP_DIAG_RUNTIME);

	if (ni > 0 || nr > 0) {
		stats_log_write("KCOV CMP DIAG errnos (first-failure-wins, cumulative count):\n");
		if (ni > 0)
			stats_log_write(" %s\n", init_buf);
		if (nr > 0)
			stats_log_write(" %s\n", rt_buf);
	}
}
void kcov_cmp_render_pc_diag_block(void)
{
	char pc_buf[256];
	int np;

	np = kcov_pc_diag_format(pc_buf, sizeof(pc_buf));
	if (np > 0) {
		stats_log_write("KCOV PC DIAG (first-failure-wins errnos + retry counters, cumulative):\n");
		stats_log_write(" %s\n", pc_buf);
	}
}
