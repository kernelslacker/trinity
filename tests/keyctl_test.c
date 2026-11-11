/*
 * Self-check for keyctl's sanitiser (syscalls/keyctl/keyctl.c): a
 * KEYCTL_WATCH_KEY call carries a watch id keyctl_watch_key() takes, -1 to
 * remove a watch or 0..0xff to add one, which the kernel checks before it
 * looks the key up.
 */

#include <string.h>

#include "debug.h"		/* BUG */
#include "kernel/keyctl.h"	/* KEYCTL_WATCH_KEY */
#include "objects.h"		/* struct objhead */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_keyctl */

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

/* No key serial or watch queue pool: the sanitiser draws without them. */
static struct objhead *no_pool(enum obj_scope scope, enum objecttype type)
{
	(void) scope;
	(void) type;
	return NULL;
}

void keyctl_self_check(void);
void keyctl_self_check(void)
{
	unsigned int i, watches = 0, removes = 0;

	fake_get_objhead = no_pool;
	for (i = 0; i < 10000; i++) {
		struct syscallrecord rec;
		int id;

		memset(&rec, 0, sizeof(rec));
		syscall_keyctl.sanitise(&rec);
		if (rec.a1 != KEYCTL_WATCH_KEY)
			continue;
		id = (int) rec.a4;
		if (id < -1 || id > 0xff)
			BUG("keyctl: a WATCH_KEY call carried a watch id the kernel refuses");
		watches++;
		if (id == -1)
			removes++;
	}
	fake_get_objhead = NULL;
	if (watches == 0 || removes == 0)
		BUG("keyctl: no WATCH_KEY call removed a watch");
}
