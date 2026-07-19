/*
 * Debug-adjacent option families: writer-pin canary,
 * --guard-shared, small verbosity/diagnostics flags, the
 * print/list/help info commands, and long-only misc rows
 * (--clowntown, --dry-run, --enable-fds/--disable-fds,
 * --self-corrupt-canary, --show-unannotated,
 * --print-disabled-syscalls, --blob-ab-mode).
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "bdevs.h"
#include "blob_mutator.h"
#include "fd.h"
#include "kcov.h"
#include "params.h"
#include "tables.h"
#include "trinity.h"	// progname, max_files_rlimit

#include "internal.h"

/* Writer-pinning canary (default-OFF, heavyweight debug
 * tool).  See include/params.h for the row description.
 * No range validation on writer_watch_addr: any non-zero
 * value is forwarded as-is to perf_event_open, which
 * is the canonical authority on whether the address is
 * acceptable as a hardware breakpoint target. */
bool parse_writer_pin_options(int opt, const char *name, char *arg)
{
	if (opt != 0)
		return false;

	if (strcmp("writer-pin-sweep", name) == 0) {
		writer_pin_sweep = true;
		return true;
	}

	if (strcmp("writer-pin-stride", name) == 0) {
		unsigned long val;

		if (!parse_unsigned(arg, "writer-pin-stride",
				    false, &val))
			exit(EXIT_FAILURE);
		if (val == 0 || val > UINT_MAX) {
			outputerr("--writer-pin-stride=%lu out of range (1..UINT_MAX)\n",
				  val);
			exit(EXIT_FAILURE);
		}
		writer_pin_stride = (unsigned int)val;
		return true;
	}

	if (strcmp("writer-watch", name) == 0) {
		const char *p = arg;
		const char *sign_check = arg;
		char *end = NULL;
		unsigned long val;

		/*
		 * strtoul() silently accepts a leading '-'/'+' even in
		 * base 16, wrapping a negative value into a huge address.
		 * Reject a sign up front (after any leading whitespace)
		 * so "-1", "+0x10" etc. are diagnosed rather than turned
		 * into a wild watch address.
		 */
		while (isspace((unsigned char)*sign_check))
			sign_check++;
		if (*sign_check == '-' || *sign_check == '+') {
			outputerr("--writer-watch: can't parse '%s' as hex address\n",
				  arg);
			exit(EXIT_FAILURE);
		}

		/* Accept either bare hex or 0x-prefixed; strtoul
		 * with base 16 handles a leading 0x but errno=0
		 * + end==start is our only error signal. */
		if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
			p += 2;
		errno = 0;
		val = strtoul(p, &end, 16);
		if (errno != 0 || end == p ||
		    (end != NULL && *end != '\0')) {
			outputerr("--writer-watch: can't parse '%s' as hex address\n",
				  arg);
			exit(EXIT_FAILURE);
		}
		if (val == 0) {
			outputerr("--writer-watch=0 disables the watch; pass a non-zero address\n");
			exit(EXIT_FAILURE);
		}
		writer_watch_addr = val;
		return true;
	}

	return false;
}

bool parse_guard_shared_options(int opt, const char *name, char *arg)
{
	if (opt != 0)
		return false;
	if (strcmp("guard-shared", name) != 0)
		return false;

#ifdef CONFIG_GUARD_SHARED
	/* --guard-shared        -> pools (default)
	 * --guard-shared=pools  -> pools
	 * --guard-shared=all    -> all
	 * --guard-shared=off    -> off (explicit no-op)
	 *
	 * Decided defaults from the 2026-06-09 spec:
	 * pools is the focused scope (kcov_shm, shared
	 * str/obj heap, childdata) and is what an
	 * operator wants the first time they reach for
	 * the flag.  ALL is the wider sweep; warn the
	 * operator that the VMA budget may need a
	 * vm.max_map_count bump so a guarded fleet host
	 * doesn't ENOMEM on its own mprotect splits.
	 */
	if (arg == NULL ||
	    strcmp(arg, "pools") == 0) {
		guard_shared_scope = GUARD_SCOPE_POOLS;
	} else if (strcmp(arg, "all") == 0) {
		guard_shared_scope = GUARD_SCOPE_ALL;
		outputerr("--guard-shared=all: every alloc_shared region is guarded; "
			  "consider raising vm.max_map_count if mprotect splits ENOMEM\n");
	} else if (strcmp(arg, "off") == 0) {
		guard_shared_scope = GUARD_SCOPE_OFF;
	} else {
		outputerr("--guard-shared: unknown scope '%s' (use pools|all|off)\n",
			  arg);
		exit(EXIT_FAILURE);
	}
#else
	(void)arg;
	/*
	 * Build does NOT have CONFIG_GUARD_SHARED.  The
	 * longopt entry above is unconditional (it has to
	 * be, or getopt would reject --guard-shared with a
	 * generic "unrecognised option" line that hides
	 * what actually happened).  Without this branch the
	 * flag is silently accepted and ignored, which has
	 * already misled two corruption-hunt sessions into
	 * believing armour was active when the binary was
	 * built plain.  Loudly diagnose instead so the
	 * operator sees the configure step they need to
	 * re-run.
	 */
	outputerr("WARNING: --guard-shared ignored -- "
		  "binary built without GUARD_SHARED=1; "
		  "rebuild with GUARD_SHARED=1 ./configure && make\n");
#endif
	return true;
}

/* Diagnostic-output verbosity knobs. */
bool parse_diagnostic_options(int opt, const char *name, char *arg)
{
	(void)name;
	(void)arg;

	switch (opt) {
	case 'D':
		set_debug = true;
		return true;
	case 'q':
		quiet = true;
		return true;
	case 'S':
		do_syslog = true;
		return true;
	case 'v':
		verbosity++;
		return true;
	}

	return false;
}

/* Info-dump commands: usage/list/etc.  All of these print and exit. */
bool parse_info_options(int opt, const char *name, char *arg)
{
	(void)name;

	switch (opt) {
	case 'b':
		init_bdev_list();
		process_bdev_param(arg);
		dump_bdev_list();
		outputstd("--bdev doesn't do anything useful yet.\n");
		exit(EXIT_SUCCESS);
	case 'h':
		usage();
		exit(EXIT_SUCCESS);
	case 'I':
		show_ioctl_list = true;
		return true;
	case 'L':
		show_syscall_list = true;
		return true;
	}

	return false;
}

/* Long-only options that don't belong to any other family.  Must run
 * after all other opt==0 helpers so they claim their names first. */
bool parse_long_misc_options(int opt, const char *name, char *arg)
{
	if (opt != 0)
		return false;

	if (strcmp("clowntown", name) == 0) {
		clowntown = true;
		return true;
	}

	if (strcmp("disable-fds", name) == 0) {
		process_fds_param(arg, false);
		return true;
	}

	if (strcmp("dry-run", name) == 0) {
		dry_run = true;
		return true;
	}

	if (strcmp("blob-ab-mode", name) == 0) {
		blob_ab_mode = true;
		return true;
	}

	if (strcmp("self-corrupt-canary", name) == 0) {
		self_corrupt_canary = true;
		return true;
	}

	if (strcmp("enable-fds", name) == 0) {
		process_fds_param(arg, true);
		return true;
	}

	if (strcmp("show-unannotated", name) == 0) {
		show_unannotated = true;
		return true;
	}

	if (strcmp("print-disabled-syscalls", name) == 0) {
		show_disabled_syscalls = true;
		return true;
	}

	return false;
}
