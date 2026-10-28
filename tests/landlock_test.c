/*
 * Self-check for the Landlock sanitisers (syscalls/landlock/): the rules and
 * rulesets they build are held to what security/landlock/syscalls.c answers
 * a call with, the kernel half of each rule cited where it is checked.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"		/* BUG */
#include "kernel/landlock.h"
#include "syscall.h"
#include "syscalls/syscalls.h"	/* syscall_landlock_add_rule */

void landlock_self_check(void);

extern bool fake_random_fd_empty;	/* fake_stubs.c */

/* Calls per case: enough that a draw one time in sixteen is seen hundreds of
 * times. */
#define NR_CALLS	20000

static unsigned int failed;

/* A rule broken by every call would print NR_CALLS lines; the first few say it. */
static void expect(bool ok, const char *what, unsigned long got)
{
	if (ok)
		return;
	if (failed++ < 10)
		fprintf(stderr, "landlock: %s (got %lu)\n", what, got);
}

/*
 * add_rule_namespace() and add_rule_capability(), for a ruleset that handles
 * the permission: any flag is -EINVAL (LANDLOCK_ADD_RULE_QUIET too, "Namespace
 * rules support no add-rule flags"), no permission is -ENOMSG, a selector other
 * than the one the type is for is -EINVAL, and a rule that neither allows nor
 * quiets a member is -ENOMSG.
 */
static int permission_rule_answer(unsigned long rule_type, unsigned long flags,
				  const struct landlock_permission_attr *pa)
{
	unsigned long long want = rule_type == LANDLOCK_RULE_CAPABILITY_COMPAT ?
		LANDLOCK_PERMISSION_CAPABILITY_USE :
		LANDLOCK_PERMISSION_NAMESPACE_USE;

	if (flags)
		return -EINVAL;
	if (!pa->permissions)
		return -ENOMSG;
	if (pa->permissions != want)
		return -EINVAL;
	if (!pa->allowed && !pa->quiet)
		return -ENOMSG;
	return 0;
}

static void check_permission_rules(void)
{
	static const unsigned long types[] = {
		LANDLOCK_RULE_NAMESPACE_COMPAT, LANDLOCK_RULE_CAPABILITY_COMPAT,
	};
	unsigned int t;

	for (t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
		unsigned long accepted = 0, enomsg = 0, einval = 0, every = 0, i;

		for (i = 0; i < NR_CALLS; i++) {
			const struct landlock_permission_attr *pa;
			struct syscallrecord rec;
			int ret;

			memset(&rec, 0, sizeof(rec));
			rec.a2 = types[t];
			syscall_landlock_add_rule.sanitise(&rec);

			expect(rec.a3 != 0, "the rule is built", types[t]);
			if (rec.a3 == 0)
				continue;
			pa = (const struct landlock_permission_attr *) rec.a3;
			expect(rec.a4 == 0, "a permission rule carries no flag",
			       rec.a4);

			ret = permission_rule_answer(types[t], rec.a4, pa);
			accepted += ret == 0;
			enomsg += ret == -ENOMSG;
			einval += ret == -EINVAL;
			every += pa->allowed == ~0ULL;
		}

		expect(accepted * 4 >= NR_CALLS * 3,
		       "three in four permission rules are ones the kernel takes",
		       accepted);
		expect(enomsg > 0 && einval > 0,
		       "the refusals are drawn as well", enomsg);
		expect(every * 2 > NR_CALLS,
		       "most allowed masks name every member", every);
	}
}

/* The two older rule types keep the quiet flag the kernel takes for them. */
static void check_older_rule_flags(void)
{
	static const unsigned long types[] = {
		LANDLOCK_RULE_PATH_BENEATH_COMPAT, LANDLOCK_RULE_NET_PORT_COMPAT,
	};
	unsigned int t;

	/* The path rule names an fd from the pool, which is empty here. */
	fake_random_fd_empty = true;

	for (t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
		unsigned long quiet = 0, i;

		for (i = 0; i < NR_CALLS; i++) {
			struct syscallrecord rec;

			memset(&rec, 0, sizeof(rec));
			rec.a2 = types[t];
			syscall_landlock_add_rule.sanitise(&rec);

			expect(rec.a4 == 0 || rec.a4 == LANDLOCK_ADD_RULE_QUIET,
			       "a path or port rule takes the quiet flag or none",
			       rec.a4);
			quiet += rec.a4 == LANDLOCK_ADD_RULE_QUIET;
		}
		expect(quiet > NR_CALLS / 4 && quiet < NR_CALLS * 3 / 4,
		       "the quiet flag is drawn about half the time", quiet);
	}

	fake_random_fd_empty = false;
}

/* A rule type the sanitiser builds is dead code unless the draw of the type
 * argument can name it. */
static void check_rule_types_drawn(void)
{
	static const unsigned long types[] = {
		LANDLOCK_RULE_PATH_BENEATH_COMPAT, LANDLOCK_RULE_NET_PORT_COMPAT,
		LANDLOCK_RULE_NAMESPACE_COMPAT, LANDLOCK_RULE_CAPABILITY_COMPAT,
	};
	const struct arglist *list = &syscall_landlock_add_rule.arg_params[1].list;
	unsigned int t, i;

	for (t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
		bool found = false;

		for (i = 0; i < list->num; i++)
			found |= list->values[i] == types[t];
		expect(found, "the rule type argument can name the type", types[t]);
	}
}

void landlock_self_check(void)
{
	check_permission_rules();
	check_older_rule_flags();
	check_rule_types_drawn();

	if (failed != 0)
		BUG("landlock: a check failed");
}
