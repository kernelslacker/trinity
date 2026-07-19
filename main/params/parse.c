/*
 * Parser orchestrator for the params cluster.  parse_args() runs the
 * getopt_long() loop and threads each parsed option through the
 * parse_*_options() family helpers (declared in internal.h) in a
 * fixed order until one claims it.  parse_duration() and
 * parse_unsigned() are the small scalar helpers every family reuses;
 * they live here so the family files don't need to redeclare them.
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "random.h"
#include "taint.h"
#include "trinity.h"	// output, outputerr, outputstd

#include "internal.h"

/*
 * Parse a duration string with optional suffix:
 *   s = seconds (default if no suffix)
 *   m = minutes
 *   h = hours
 *   d = days
 * On success, writes the value (in seconds) to *out and returns true.
 * Returns false for empty input, garbage, multi-char suffix, unknown
 * suffix, negative values, zero, or anything that overflows unsigned int.
 */
bool parse_duration(const char *s, unsigned int *out)
{
	char *end;
	unsigned long val;
	unsigned long mult = 1;

	if (s == NULL || *s == '\0')
		return false;

	if (s[0] == '-' || s[0] == '+')
		return false;

	errno = 0;
	val = strtoul(s, &end, 10);
	if (end == s || errno == ERANGE)
		return false;

	if (val == 0)
		return false;

	if (*end != '\0') {
		if (end[1] != '\0')
			return false;
		switch (*end) {
		case 's': mult = 1; break;
		case 'm': mult = 60UL; break;
		case 'h': mult = 60UL * 60; break;
		case 'd': mult = 60UL * 60 * 24; break;
		default: return false;
		}
	}

	if (mult != 0 && val > ULONG_MAX / mult)
		return false;
	val *= mult;

	if (val > UINT_MAX)
		return false;

	*out = (unsigned int)val;
	return true;
}

/*
 * Parse a non-negative decimal integer from optarg.  Requires the entire
 * string be consumed (no trailing junk), rejects empty input and overflow,
 * and optionally rejects zero.  On success writes the value to *out and
 * returns true; on failure prints a diagnostic and returns false.
 */
bool parse_unsigned(const char *s, const char *name,
			   bool allow_zero, unsigned long *out)
{
	char *end;
	unsigned long val;

	if (s == NULL || *s == '\0') {
		outputerr("--%s: missing value\n", name);
		return false;
	}

	/*
	 * strtoul() silently accepts a leading '-' and returns the negation
	 * modulo ULONG_MAX+1, turning "-1" into a huge "unsigned" limit.
	 * Reject it up front so the parser matches its documented contract.
	 */
	if (s[0] == '-' || s[0] == '+') {
		outputerr("--%s: negative value '%s' not allowed\n", name, s);
		return false;
	}

	errno = 0;
	val = strtoul(s, &end, 10);
	if (end == s || *end != '\0') {
		outputerr("--%s: can't parse '%s' as a number\n", name, s);
		return false;
	}
	if (errno == ERANGE) {
		outputerr("--%s: value '%s' out of range\n", name, s);
		return false;
	}
	if (!allow_zero && val == 0) {
		outputerr("--%s: zero is not a meaningful value\n", name);
		return false;
	}

	*out = val;
	return true;
}

static void reject_extra_positional_args(int argc, char *argv[])
{
	if (optind >= argc)
		return;

	outputerr("unexpected argument(s):");
	while (optind < argc)
		outputerr(" '%s'", argv[optind++]);
	outputerr("\n");
	exit(EXIT_FAILURE);
}

void parse_args(int argc, char *argv[])
{
	int opt;
	int opt_index = 0;

	while ((opt = getopt_long(argc, argv, paramstr, longopts, &opt_index)) != -1) {
		const char *long_name = (opt == 0) ? longopts[opt_index].name : NULL;

		if (parse_child_options(opt, long_name, optarg))
			continue;
		if (parse_kcov_options(opt, long_name, optarg))
			continue;
		if (parse_cmp_options(opt, long_name, optarg))
			continue;
		if (parse_cache_options(opt, long_name, optarg))
			continue;
		if (parse_strategy_options(opt, long_name, optarg))
			continue;
		if (parse_memory_options(opt, long_name, optarg))
			continue;
		if (parse_runtime_options(opt, long_name, optarg))
			continue;
		if (parse_stats_options(opt, long_name, optarg))
			continue;
		if (parse_writer_pin_options(opt, long_name, optarg))
			continue;
		if (parse_guard_shared_options(opt, long_name, optarg))
			continue;
		if (parse_selection_options(opt, long_name, optarg))
			continue;
		if (parse_diagnostic_options(opt, long_name, optarg))
			continue;
		if (parse_info_options(opt, long_name, optarg))
			continue;
		if (parse_long_misc_options(opt, long_name, optarg))
			continue;

		switch (opt) {
		default:
			if (opt == '?')
				exit(EXIT_FAILURE);
			else
				outputstd("opt:%c\n", opt);
			return;

		/* Long-only opt claimed by no parser helper -- table/parser drift.
		 * Fatal rather than silently ignoring operator input. */
		case 0:
			outputerr("internal error: unhandled long option --%s\n",
				  long_name);
			exit(EXIT_FAILURE);

		case 'd':
			dangerous = true;
			break;

		case 's': {
			unsigned long val;

			if (!parse_unsigned(optarg, "s", true, &val))
				exit(EXIT_FAILURE);
			if (val > UINT_MAX) {
				outputerr("-s: value %lu exceeds UINT_MAX\n", val);
				exit(EXIT_FAILURE);
			}
			seed = (unsigned int)val;
			user_set_seed = true;
			break;
		}

		case 'T':
			//Load mask for kernel taint flags.
			process_taint_arg(optarg);
			if (kernel_taint_mask != 0xFFFFFFFF)
				outputstd("Custom kernel taint mask has been specified: 0x%08x (%d).\n",
					kernel_taint_mask, kernel_taint_mask);
			break;

		case 'V':
			if (nr_victim_paths >= MAX_VICTIM_PATHS) {
				outputerr("Too many victim paths (max %d).\n", MAX_VICTIM_PATHS);
				exit(EXIT_FAILURE);
			}
			victim_paths[nr_victim_paths] = strdup(optarg);
			if (!victim_paths[nr_victim_paths]) {
				outputerr("strdup failed\n");
				exit(EXIT_FAILURE);
			}
			nr_victim_paths++;
			break;
		}
	}

	reject_extra_positional_args(argc, argv);

	if (verbosity > MAX_LOGLEVEL)
		verbosity = MAX_LOGLEVEL;

	output(1, "Done parsing arguments.\n");
}
