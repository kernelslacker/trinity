/*
 * Self-check for what the lseek and llseek sanitisers hand the kernel.  A
 * SEEK_DATA or SEEK_HOLE call goes to a sparse file three times in four and
 * stays on the fd it drew otherwise, where default_llseek() and the other
 * handlers without a sparse walk judge it, and carries a negative offset one
 * time in eight; the other whences never carry one, since an
 * FOP_UNSIGNED_OFFSET file takes it and answers a position the post
 * handlers count as torn.  The sparse-file pool is a fake holding one file.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "kernel/fs.h"		/* SEEK_DATA, SEEK_HOLE */
#include "objects.h"		/* get_objhead */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_lseek, syscall_llseek */
#include "utils-macros.h"	/* ARRAY_SIZE */

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

#define ROUNDS		40000
#define DRAWN_FD	37	/* what generic_sanitise drew; no protected fd */
#define SPARSE_FD	38
#define SPARSE_SIZE	(1L << 20)

static struct object sparse_obj;
static struct object *sparse_array[] = { &sparse_obj };
static struct objhead sparse_pool = { .array = sparse_array, .num_entries = 1 };
static struct objhead no_pool;

static struct objhead *the_pools(enum obj_scope scope, enum objecttype type)
{
	if (scope == OBJ_GLOBAL && type == OBJ_FD_SPARSE_FILE)
		return &sparse_pool;
	return &no_pool;
}

/*
 * @whence through @entry's sanitiser: how many calls in ROUNDS went to the
 * sparse file and how many carry a negative offset, llseek's built from its
 * two words as SYSCALL_DEFINE5(llseek) builds it.
 */
static void tally_seeks(struct syscallentry *entry, bool llseek,
			unsigned int whence, unsigned int *sparse,
			unsigned int *negative)
{
	static struct syscallrecord rec;
	static long long result;
	unsigned int i;

	*sparse = 0;
	*negative = 0;
	for (i = 0; i < ROUNDS; i++) {
		long long offset;

		memset(&rec, 0, sizeof(rec));
		rec.a1 = DRAWN_FD;
		if (llseek) {
			rec.a4 = (unsigned long) &result;
			rec.a5 = whence;
		} else {
			rec.a3 = whence;
		}
		entry->sanitise(&rec);

		if (rec.a1 != DRAWN_FD && rec.a1 != SPARSE_FD)
			BUG("seek: a sanitiser aimed the call at an fd it was not given");
		if (llseek)
			offset = (long long) (((unsigned long long) rec.a2 << 32) |
					      rec.a3);
		else
			offset = (long) rec.a2;
		*sparse += rec.a1 == SPARSE_FD;
		*negative += offset < 0;
	}
}

static void seeks_aim_where_the_kernel_judges_them(struct syscallentry *entry,
						   bool llseek)
{
	static const unsigned int whences[] = {
		SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA, SEEK_HOLE,
	};
	unsigned int w, sparse, negative;

	for (w = 0; w < ARRAY_SIZE(whences); w++) {
		tally_seeks(entry, llseek, whences[w], &sparse, &negative);
		if (whences[w] != SEEK_DATA && whences[w] != SEEK_HOLE) {
			if (sparse || negative) {
				fprintf(stderr, "%s whence %u: %u sparse, %u negative\n",
					entry->name, whences[w], sparse, negative);
				BUG("seek: a SEEK_SET, SEEK_CUR or SEEK_END call went to the sparse file or carries a negative offset");
			}
			continue;
		}
		if (sparse < ROUNDS * 0.70 || sparse > ROUNDS * 0.80 ||
		    negative < ROUNDS * 0.10 || negative > ROUNDS * 0.15) {
			fprintf(stderr, "%s whence %u: %u sparse, %u negative of %u\n",
				entry->name, whences[w], sparse, negative, ROUNDS);
			BUG("seek: SEEK_DATA and SEEK_HOLE do not go to the sparse file three times in four, with a negative offset one time in eight");
		}
	}
}

void seek_sanitise_self_check(void);
void seek_sanitise_self_check(void)
{
	sparse_obj.obj_type = OBJ_FD_SPARSE_FILE;
	sparse_obj.sparsefileobj.fd = SPARSE_FD;
	sparse_obj.sparsefileobj.size = SPARSE_SIZE;
	fake_get_objhead = the_pools;

	seeks_aim_where_the_kernel_judges_them(&syscall_lseek, false);
	seeks_aim_where_the_kernel_judges_them(&syscall_llseek, true);

	fake_get_objhead = NULL;
}
