/*
 * Self-check for deactivate_extrafork_syscalls() (tables/tables.c).  Where
 * do_extrafork() is compiled out (ASAN) a live run never issues an
 * EXTRA_FORK call, so those entries have to leave the active table.
 * --dry-run issues no call anywhere and takes them in the child like the
 * rest, and every other build leaves the table alone.
 */

#include <stdbool.h>
#include <string.h>

#include "arch.h"		/* biarch */
#include "debug.h"		/* BUG */
#include "params.h"		/* dry_run */
#include "syscall.h"
#include "tables.h"
#include "utils.h"		/* ARRAY_SIZE */

#include "fake_parent.h"	/* fake_output_log */

#ifdef __SANITIZE_ADDRESS__
#define EXTRAFORK_COMPILED_OUT	true
#else
#define EXTRAFORK_COMPILED_OUT	false
#endif

/*
 * The deactivation in table-activate.c, which this binary does not link, for
 * this test and for the ENOSYS path dispatch_extrafork_test.c reaches.  What
 * the sweep asked it to remove is the answer.
 */
static struct {
	unsigned int calln;
	bool do32bit;
} deactivated[8];
static unsigned int nr_deactivated;

void deactivate_syscall_nolock(unsigned int calln, bool do32bit)
{
	if (nr_deactivated < ARRAY_SIZE(deactivated)) {
		deactivated[nr_deactivated].calln = calln;
		deactivated[nr_deactivated].do32bit = do32bit;
	}
	nr_deactivated++;
}

/*
 * A table as the activation paths leave it.  PLAIN is an ordinary entry.
 * FORKS and ALARM are EXTRA_FORK entries that made it into the active table,
 * as fchroot and fchdir do.  IDLE is one that never did, as execve's
 * AVOID_SYSCALL keeps it out, though mark_all_syscalls_active() still flags
 * it ACTIVE.
 */
enum { PLAIN, FORKS, IDLE, ALARM, NR_PROBES };

struct probes {
	struct syscallentry entry[NR_PROBES];
	struct syscall_runtime rt[NR_PROBES];
	struct syscalltable table[NR_PROBES];
};

static void probes_init(struct probes *p)
{
	static const unsigned int flags[NR_PROBES] = {
		[PLAIN] = ACTIVE,
		[FORKS] = ACTIVE | EXTRA_FORK,
		[IDLE]  = ACTIVE | EXTRA_FORK | AVOID_SYSCALL,
		[ALARM] = ACTIVE | EXTRA_FORK | NEED_ALARM,
	};
	unsigned int i;

	memset(p, 0, sizeof(*p));
	for (i = 0; i < NR_PROBES; i++) {
		p->entry[i].name = "probe";
		p->entry[i].flags = flags[i];
		p->entry[i].rt = &p->rt[i];
		p->rt[i].active_number = (i == IDLE) ? 0 : i + 1;
		p->table[i].entry = &p->entry[i];
	}
}

static void run_sweep(bool dry)
{
	nr_deactivated = 0;
	fake_output_log[0] = '\0';
	dry_run = dry;
	deactivate_extrafork_syscalls();
	dry_run = false;
}

static bool was_deactivated(unsigned int calln, bool do32bit)
{
	unsigned int i;

	for (i = 0; i < nr_deactivated && i < ARRAY_SIZE(deactivated); i++) {
		if (deactivated[i].calln == calln &&
		    deactivated[i].do32bit == do32bit)
			return true;
	}
	return false;
}

/* The sweep left @p alone and said nothing. */
static void table_untouched(const struct probes *p, const char *why)
{
	unsigned int i;

	if (nr_deactivated != 0)
		BUG(why);
	if (fake_output_log[0] != '\0')
		BUG("tables_extrafork: logged a deactivation that never happened");
	for (i = 0; i < NR_PROBES; i++) {
		if (!(p->entry[i].flags & ACTIVE))
			BUG("tables_extrafork: cleared ACTIVE on an entry it left in the table");
	}
}

static void selftest_uniarch(void)
{
	struct probes p;

	probes_init(&p);
	biarch = false;
	syscalls = p.table;
	max_nr_syscalls = NR_PROBES;

	run_sweep(false);
	if (!EXTRAFORK_COMPILED_OUT) {
		table_untouched(&p, "tables_extrafork: a build that issues EXTRA_FORK calls dropped some");
	} else {
		if (nr_deactivated != 2 || !was_deactivated(FORKS, false) ||
		    !was_deactivated(ALARM, false))
			BUG("tables_extrafork: an active EXTRA_FORK entry was kept, or another was taken");
		if ((p.entry[FORKS].flags & ACTIVE) || (p.entry[ALARM].flags & ACTIVE))
			BUG("tables_extrafork: a deactivated entry is still flagged ACTIVE");
		if (!(p.entry[PLAIN].flags & ACTIVE))
			BUG("tables_extrafork: an entry without EXTRA_FORK lost its ACTIVE flag");
		if (strstr(fake_output_log, "deactivated 2 EXTRA_FORK") == NULL)
			BUG("tables_extrafork: the deactivation was not logged with its count");
	}

	/* --dry-run runs these through the in-child path, in every build. */
	probes_init(&p);
	run_sweep(true);
	table_untouched(&p, "tables_extrafork: a --dry-run run dropped EXTRA_FORK entries");

	/* With no EXTRA_FORK entry in the active table there is nothing to say. */
	probes_init(&p);
	p.rt[FORKS].active_number = 0;
	p.rt[ALARM].active_number = 0;
	run_sweep(false);
	table_untouched(&p, "tables_extrafork: took an entry that was not in the active table");

	syscalls = NULL;
	max_nr_syscalls = 0;
}

/* The two tables are swept apart: a 32-bit entry is not a 64-bit one. */
static void selftest_biarch(void)
{
	struct probes p32, p64;

	probes_init(&p32);
	probes_init(&p64);
	p32.rt[ALARM].active_number = 0;
	biarch = true;
	syscalls_32bit = p32.table;
	syscalls_64bit = p64.table;
	max_nr_32bit_syscalls = NR_PROBES;
	max_nr_64bit_syscalls = NR_PROBES;

	run_sweep(false);
	if (!EXTRAFORK_COMPILED_OUT) {
		table_untouched(&p32, "tables_extrafork: a build that issues EXTRA_FORK calls dropped some");
		table_untouched(&p64, "tables_extrafork: a build that issues EXTRA_FORK calls dropped some");
	} else {
		if (nr_deactivated != 3 || !was_deactivated(FORKS, true) ||
		    !was_deactivated(FORKS, false) || !was_deactivated(ALARM, false))
			BUG("tables_extrafork: biarch did not sweep each table for what is active in it");
		if (strstr(fake_output_log, "deactivated 3 EXTRA_FORK") == NULL)
			BUG("tables_extrafork: biarch logged the wrong count");
	}

	biarch = false;
	syscalls_32bit = NULL;
	syscalls_64bit = NULL;
	max_nr_32bit_syscalls = 0;
	max_nr_64bit_syscalls = 0;
}

void tables_extrafork_self_check(void);
void tables_extrafork_self_check(void)
{
	selftest_uniarch();
	selftest_biarch();
}
