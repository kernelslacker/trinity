/*
 * Regression fixture for the kmsg-monitor WARNING trigger.  Since v6.19
 * __warn() prints "WARNING: <file>:<line> at <sym>, CPU#<n>: <comm>/<pid>"
 * where it printed "WARNING: CPU: <n> PID: <n> at ...".  "WARNING: " must
 * match both banners and lockdep's, while the old "WARNING: CPU:" misses the
 * new one; a future upstream reword then fails here, not silently.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"		/* BUG_ON */

void kmsg_trigger_self_check(void);

/*
 * Trigger string used by the FIXED monitor (kmsg_triggers[] entry).
 * Must stay in sync with health/kmsg-monitor.c.
 */
static const char TRIGGER_CURRENT[] = "WARNING: ";

/*
 * Trigger string used by the OLD (broken) monitor, kept here only to
 * document what it missed.
 */
static const char TRIGGER_OLD[] = "WARNING: CPU:";

/*
 * Concrete verbatim kernel banner specimens.
 *
 * OLD format (pre-v6.19): __warn() emitted "WARNING: CPU: <n> PID: <n> at ..."
 * NEW format (v6.19+): "WARNING: <file>:<line> at <sym>, CPU#<n>: <comm>/<pid>",
 * or, when __warn() has no file, "WARNING: at <sym>, CPU#<n>: <comm>/<pid>"
 *
 * These are the strings that would appear in the /dev/kmsg record body
 * after the sequence-number/timestamp prefix is stripped.
 */

/* Pre-v6.19 banner — both old and new trigger must match */
static const char BANNER_OLD_FORMAT[] =
	"WARNING: CPU: 3 PID: 1842 at mm/slub.c:3521 kmem_cache_alloc+0x0/0x200";

/* v6.19+ banner — only the new trigger matches; old is blind */
static const char BANNER_NEW_FORMAT[] =
	"WARNING: mm/slub.c:3521 at kmem_cache_alloc+0x0/0x200, CPU#3: kworker/3:1/42";

/* Second new-format specimen: the file-less form __warn() prints when it
 * has no file */
static const char BANNER_NEW_FORMAT_2[] =
	"WARNING: at some_func+0x0/0x10, CPU#0: comm/123";

/* Lockdep variant — must match the current trigger */
static const char BANNER_LOCKDEP[] =
	"WARNING: possible circular locking dependency detected";

/*
 * Minimal trigger matcher: returns non-zero if `trigger` appears
 * anywhere in `body`, mirroring what strstr does in line_matches_trigger().
 */
static int trigger_matches(const char *body, const char *trigger)
{
	return strstr(body, trigger) != NULL;
}

void kmsg_trigger_self_check(void)
{
	/* --- CURRENT trigger ("WARNING: ") must match everything --- */

	BUG_ON(!trigger_matches(BANNER_OLD_FORMAT, TRIGGER_CURRENT));
	BUG_ON(!trigger_matches(BANNER_NEW_FORMAT, TRIGGER_CURRENT));
	BUG_ON(!trigger_matches(BANNER_NEW_FORMAT_2, TRIGGER_CURRENT));
	BUG_ON(!trigger_matches(BANNER_LOCKDEP, TRIGGER_CURRENT));

	/* --- OLD trigger ("WARNING: CPU:") is blind to the new format --- */

	BUG_ON(!trigger_matches(BANNER_OLD_FORMAT, TRIGGER_OLD));  /* old matched old */
	BUG_ON(trigger_matches(BANNER_NEW_FORMAT, TRIGGER_OLD)); /* old MISSES new */
	BUG_ON(trigger_matches(BANNER_NEW_FORMAT_2, TRIGGER_OLD)); /* old MISSES new */

	printf("    kmsg_trigger: current trigger matches old+new banner formats OK\n");
	printf("    kmsg_trigger: old trigger blind-spot on v6.19+ format confirmed OK\n");
}
