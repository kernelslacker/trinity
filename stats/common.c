#include <stdbool.h>
#include "minicorpus.h"
#include "stats-internal.h"
#include "utils.h"

/*
 * Linker-provided bounds of the running binary's executable text.  Used
 * to filter PC samples whose storage was itself stomped by the wild
 * writes we are trying to attribute -- an entry whose pc lands outside
 * [__executable_start, _etext) cannot be a real call site and would
 * otherwise dump as garbage.
 */
extern char __executable_start[];
extern char _etext[];

bool pc_in_text(void *pc)
{
	return pc >= (void *)__executable_start && pc < (void *)_etext;
}

const char * const op_names[MUT_NUM_OPS] = {
	"bit-flip", "add", "sub", "boundary", "byte-shuf", "keep",
	"bswap-add", "bswap-sub", "fd-swap"
};

void stat_row(const char *category, const char *metric, unsigned long value)
{
	output(0, STATS_ROW_FMT, category, metric, value);
}

/* Insertion-sort push for a top-N table held as parallel arrays
 * (vals[], nrs[], descending by value, capped at cap).  Shared by the
 * kcov dump paths that track leading edge-producing, recent-growth, and
 * CMP-insert syscalls. */
void topn_push(unsigned long *vals, unsigned int *nrs,
	       unsigned int *count, unsigned int cap,
	       unsigned long value, unsigned int nr)
{
	unsigned int j;

	for (j = *count; j > 0 && value > vals[j - 1]; j--) {
		if (j < cap) {
			vals[j] = vals[j - 1];
			nrs[j] = nrs[j - 1];
		}
	}
	if (j < cap) {
		vals[j] = value;
		nrs[j] = nr;
		if (*count < cap)
			(*count)++;
	}
}
