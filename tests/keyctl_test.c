/*
 * Self-check for keyctl's sanitiser (syscalls/keyctl/keyctl.c): a
 * KEYCTL_WATCH_KEY call carries a watch id keyctl_watch_key() takes, -1 to
 * remove a watch or 0..0xff to add one, which the kernel checks before it
 * looks the key up; and a compat KEYCTL_INSTANTIATE_IOV call carries the
 * 8-byte struct compat_iovec its kernel reads.
 */

#include <string.h>

#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "kernel/keyctl.h"	/* KEYCTL_WATCH_KEY, KEYCTL_INSTANTIATE_IOV */
#include "objects.h"		/* struct objhead */
#include "sanitise.h"		/* iovec_entry_base, iovec_entry_len */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_keyctl */

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */
extern struct childdata *fake_this_child;	/* fake_shm.c */

/* keyctl on i386. */
#define NR_KEYCTL_32	288

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
	static struct childdata compat;
	unsigned int i, watches = 0, removes = 0, iovs;

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
	if (watches == 0 || removes == 0)
		BUG("keyctl: no WATCH_KEY call removed a watch");

	/* A sanitiser builds the call in this_child()'s record, whose
	 * being compat sends its buffers to the low pool. */
	fake_this_child = &compat;
	for (i = 0, iovs = 0; i < 10000 && iovs < 64; i++) {
		struct syscallrecord *crec = &compat.syscall;
		unsigned long n;

		memset(crec, 0, sizeof(*crec));
		crec->do32bit = true;
		crec->nr = NR_KEYCTL_32;
		syscall_keyctl.sanitise(crec);
		if (crec->a1 != KEYCTL_INSTANTIATE_IOV || crec->a3 == 0)
			continue;
		iovs++;
		for (n = 0; n < crec->a4; n++) {
			if (iovec_entry_base((void *) crec->a3, n, true) == 0 ||
			    iovec_entry_len((void *) crec->a3, n, true) == 0)
				BUG("keyctl: a compat INSTANTIATE_IOV entry read as no payload");
		}
	}
	fake_this_child = NULL;
	fake_get_objhead = NULL;
	if (iovs == 0)
		BUG("keyctl: no compat INSTANTIATE_IOV call was built");
}
