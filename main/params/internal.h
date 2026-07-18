/*
 * Private declarations shared inside the main/params/ cluster.
 * Nothing here is part of the public parser surface -- callers
 * outside main/params/ should include "params.h" instead.
 */

#pragma once

#include <stdbool.h>
#include <getopt.h>

/* Scalar parsing helpers (parse.c).  Shared by every parse_*_options
 * family helper. */
bool parse_duration(const char *s, unsigned int *out);
bool parse_unsigned(const char *s, const char *name, bool allow_zero,
		    unsigned long *out);

/* max_children cap derivation (defaults.c).  parse_child_options() in
 * childop.c also reaches for these to validate the -C path against the
 * same cap clamp_default_max_children() applies to the default. */
enum max_children_binding {
	BINDING_PROJECT_MAX,
	BINDING_SHARED_REGIONS,
	BINDING_NPROC,
	BINDING_NOFILE,
};
const char *binding_name(enum max_children_binding b);
unsigned long derive_max_children_cap(enum max_children_binding *out_binding);

/* Help + getopt metadata (help.c / options.c). */
void usage(void);
extern const char paramstr[];
extern const struct option longopts[];

/* Option-family dispatch helpers.  Each helper claims a related cluster
 * of options out of the parse_args() getopt loop: it inspects the
 * already-parsed (opt, name, arg) triple, applies side effects for any
 * option it owns, and returns true to signal the option was consumed.
 * For short options opt is the short char and name is NULL; for
 * long-only options opt is 0 and name is longopts[opt_index].name.
 * The longopts[] table itself remains the single source of truth for
 * option definitions -- helpers only carry the dispatch strings.
 */
bool parse_child_options(int opt, const char *name, char *arg);
bool parse_kcov_options(int opt, const char *name, char *arg);
bool parse_cmp_options(int opt, const char *name, char *arg);
bool parse_cache_options(int opt, const char *name, char *arg);
bool parse_strategy_options(int opt, const char *name, char *arg);
bool parse_memory_options(int opt, const char *name, char *arg);
bool parse_runtime_options(int opt, const char *name, char *arg);
bool parse_stats_options(int opt, const char *name, char *arg);
bool parse_writer_pin_options(int opt, const char *name, char *arg);
bool parse_guard_shared_options(int opt, const char *name, char *arg);
bool parse_selection_options(int opt, const char *name, char *arg);
bool parse_diagnostic_options(int opt, const char *name, char *arg);
bool parse_info_options(int opt, const char *name, char *arg);
bool parse_long_misc_options(int opt, const char *name, char *arg);
