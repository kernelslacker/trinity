/*
 * Self-check for cpulist_weight() (lib/numa.c), which counts the cpus
 * /sys/devices/system/cpu/possible lists for possible_cpus().  A list it
 * cannot read whole counts 0, so the caller falls back rather than size a
 * per-cpu row by part of the list.
 */

#include <stdio.h>

#include "debug.h"		/* BUG */
#include "numa.h"
#include "utils-macros.h"	/* ARRAY_SIZE */

void numa_self_check(void);

void numa_self_check(void)
{
	static const struct {
		const char *list;
		unsigned int weight;
	} cases[] = {
		/* As the kernel prints a cpumask list, newline and all. */
		{ "0\n", 1 },
		{ "0-315\n", 316 },
		{ "0-3,8-11\n", 8 },
		{ "0,2,4-5\n", 4 },
		{ "0-3", 4 },
		/* Nothing, or something that is no list. */
		{ "", 0 },
		{ "\n", 0 },
		{ "0-3,x\n", 0 },
		{ "3-1\n", 0 },
		{ "-1\n", 0 },
		{ "0-\n", 0 },
		/* strtol() saturates; the count would not fit. */
		{ "0-99999999999999999999\n", 0 },
		{ "0-4294967295\n", 0 },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		unsigned int got = cpulist_weight(cases[i].list);

		if (got != cases[i].weight) {
			fprintf(stderr, "numa: \"%s\" counts %u, not %u\n",
				cases[i].list, got, cases[i].weight);
			BUG("numa: a cpulist was miscounted");
		}
	}
}
