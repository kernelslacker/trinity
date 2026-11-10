/*
 * Self-check for handle_arg_list() (args/handle_arg.c): set_rand_bitmask()
 * always sets a bit, so a list of one flag would carry it on every call,
 * and a call whose flags == 0 path differs (lsm_get_self_attr's walk over
 * every LSM, remap_file_pages without MAP_NONBLOCK) would never take that
 * path.  A one-flag list leaves the flag clear about half the time; a
 * longer list never comes back empty.
 */

#include <stdbool.h>
#include <string.h>

#include "args-internal.h"	/* handle_arg_list, the cmp-hint gate */
#include "cmp_hints.h"
#include "debug.h"		/* BUG */
#include "prop_ring.h"
#include "rnd.h"
#include "syscall.h"

extern unsigned long (*fake_rand_bitmask_hook)(unsigned int num,
					       const unsigned long *values);	/* genl_ops_test.c */

/*
 * cmp_hints/get.c and objects/prop_ring.c are not linked, nor is
 * args/cmp_hint_inject.c, whose gate reaches the plateau machinery: no
 * hint or ring value is ever drawn here.
 */
bool cmp_hint_baseline_should_inject(void)
{
	return false;
}

void credit_cmp_hint_injection(struct syscallrecord *rec,
			       enum cmp_hint_callsite callsite)
{
	(void) rec;
	(void) callsite;
	BUG("arg list: a cmp hint was credited with the gate shut");
}

bool cmp_hints_try_get_ex(unsigned int nr, bool do32, enum cmp_hint_use use,
			  unsigned long old, bool allow_hyp_inject,
			  const struct cmp_accept_range *accept,
			  unsigned int arg_idx,
			  enum cmp_hint_callsite callsite,
			  unsigned long *out)
{
	(void) nr;
	(void) do32;
	(void) use;
	(void) old;
	(void) allow_hyp_inject;
	(void) accept;
	(void) arg_idx;
	(void) callsite;
	(void) out;
	return false;
}

bool prop_ring_try_get(struct childdata *child, const struct syscallrecord *rec,
		       unsigned long *out)
{
	(void) child;
	(void) rec;
	(void) out;
	return false;
}

/* The shape of rand/random.c's set_rand_bitmask(): never an empty mask. */
static unsigned long some_values(unsigned int num, const unsigned long *values)
{
	return values[rnd_modulo_u32(num)];
}

#define DRAWS	4096

void arg_list_self_check(void);
void arg_list_self_check(void)
{
	static unsigned long one[] = { 0x40 };
	static unsigned long three[] = { 0x1, 0x2, 0x4 };
	static struct syscallentry entry;
	struct syscallrecord rec;
	unsigned int clear = 0, i;

	memset(&rec, 0, sizeof(rec));
	fake_rand_bitmask_hook = some_values;
	entry.arg_params[0].list.num = 1;
	entry.arg_params[0].list.values = one;
	for (i = 0; i < DRAWS; i++) {
		unsigned long mask = handle_arg_list(&entry, &rec, 1);

		if (mask == 0)
			clear++;
		else if (!(mask & one[0]))
			BUG("arg list: a one-flag list drew a mask without its flag");
	}
	if (clear < DRAWS / 4 || clear > DRAWS * 3 / 4)
		BUG("arg list: a one-flag list did not leave its flag clear about half the time");

	entry.arg_params[0].list.num = 3;
	entry.arg_params[0].list.values = three;
	for (i = 0; i < DRAWS; i++) {
		if (handle_arg_list(&entry, &rec, 1) == 0)
			BUG("arg list: a list of three came back empty");
	}
	fake_rand_bitmask_hook = NULL;
}
