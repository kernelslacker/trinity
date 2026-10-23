/*
 * Golden check for the periodic KCOV CMP dump and the core --stats-json
 * emitters: every counter gets a value of its own, the renderers run, and
 * their text must match stats_render_golden.c byte for byte.  Scenarios
 * run in forked children because the renderers keep their window state in
 * function statics.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch.h"		/* biarch */
#include "cmp_hints.h"
#include "debug.h"		/* BUG */
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"		/* syscalls, max_nr_syscalls */
#include "utils.h"		/* waitpid_eintr */

#include "stats/json/internal.h"

#include "fake_parent.h"
#include "stats_render_golden.h"

/* ---------- Fakes ---------------------------------------------------- */

/*
 * What the periodic dump writes lands here.  stats_log_write() does what
 * production's does minus the log file: format a line and hand it to
 * output().  The output() fake keeps a short buffer of its own, so its
 * text is moved into the capture ahead of every line to keep the direct
 * output() calls in order with the logged ones.
 */
static char capture[1 << 18];
static size_t capture_len;

static void capture_append(const char *s)
{
	size_t n = strlen(s);

	if (n >= sizeof(capture) - capture_len)
		BUG("stats render: capture buffer full");
	memcpy(capture + capture_len, s, n + 1);
	capture_len += n;
}

static void capture_drain_output(void)
{
	capture_append(fake_output_log);
	fake_output_log[0] = '\0';
}

void stats_log_write(const char *fmt, ...)
{
	char buf[1024];		/* stats/log.c's line buffer */
	va_list args;

	capture_drain_output();
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	capture_append(buf);
}

/* Whether the kcov diag formatters have a failure to report. */
static bool fake_diag_on;

int kcov_cmp_diag_format(char *buf, size_t bufsz, enum kcov_cmp_diag_part part)
{
	if (!fake_diag_on || part == KCOV_CMP_DIAG_ALL)
		return 0;
	return snprintf(buf, bufsz, " %s=EFAULT/3",
			part == KCOV_CMP_DIAG_INIT ? "init_open" : "runtime_enable");
}

int kcov_pc_diag_format(char *buf, size_t bufsz)
{
	if (!fake_diag_on)
		return 0;
	return snprintf(buf, bufsz, " pc_enable=EBADF/2");
}

static bool fake_chaos_active;

bool cmp_hints_chaos_query(void)
{
	return fake_chaos_active;
}

enum redqueen_pending_pick_mode_t redqueen_pending_pick_mode_arg =
	REDQUEEN_PENDING_PICK_FIRST;

const char *redqueen_pending_pick_name(enum redqueen_pending_pick_mode_t mode)
{
	return mode == REDQUEEN_PENDING_PICK_RANDOM ? "random" : "first";
}

/* ---------- Golden comparison ---------------------------------------- */

static unsigned int golden_failures;

/*
 * Print @text as a paste-ready definition of @name for
 * stats_render_golden.c: after an intentional change to what the
 * renderers print, run the test and paste what it prints for each golden
 * that differs.
 */
static void golden_print(const char *name, const char *text, char split)
{
	const char *p = text;

	fprintf(stderr, "const char %s[] =", name);
	if (*p == '\0')
		fputs("\n\t\"\"", stderr);
	while (*p != '\0') {
		const char *end = strchr(p, split);
		size_t n = end ? (size_t)(end - p) + 1 : strlen(p);
		size_t i;

		fputs("\n\t\"", stderr);
		for (i = 0; i < n; i++) {
			unsigned char c = (unsigned char)p[i];

			if (c == '\n')
				fputs("\\n", stderr);
			else if (c == '"' || c == '\\')
				fprintf(stderr, "\\%c", c);
			else if (c < 0x20 || c > 0x7e)
				fprintf(stderr, "\\%03o", c);
			else
				fputc(c, stderr);
		}
		fputc('"', stderr);
		p += n;
	}
	fputs(";\n\n", stderr);
}

/*
 * Compare one rendering with its golden.  @split is the character each
 * source line of a pasted golden ends after: a newline for text, a comma
 * for the one-line JSON document.
 */
static void golden_expect(const char *what, const char *golden_name,
			  const char *golden, const char *actual, char split)
{
	size_t i = 0;

	if (strcmp(golden, actual) == 0)
		return;

	while (golden[i] != '\0' && golden[i] == actual[i])
		i++;
	golden_failures++;
	fprintf(stderr, "stats render: %s differs from %s at byte %zu\n"
		"  golden: %.80s\n  actual: %.80s\n",
		what, golden_name, i, golden + i, actual + i);
	golden_print(golden_name, actual, split);
}

/* ---------- Filling the counters ------------------------------------- */

#define NFAKE_SYSCALLS	12

static const char * const fake_names[NFAKE_SYSCALLS] = {
	"read", "write", "open", "close", "stat", "fstat",
	"lstat", "poll", "lseek", "mmap", "mprotect", "munmap",
};
static struct syscallentry fake_entry[NFAKE_SYSCALLS];
static struct syscalltable fake_table[NFAKE_SYSCALLS];

/*
 * Give every 64-bit word of a block its own value: base plus 17 per
 * index, plus a step per window that differs from word to word, so no
 * two counters share a total or a delta.
 */
static void fill_block(void *p, size_t bytes, unsigned long base,
		       unsigned int win)
{
	unsigned long *w = p;
	size_t i;

	for (i = 0; i < bytes / sizeof(*w); i++) {
		unsigned long v = base + 17 * i;
		unsigned int k;

		for (k = 1; k <= win; k++)
			v += 3 + (i * 37 + k * 101) % 1999;
		w[i] = v;
	}
}

/*
 * Every counter at window @win.  The 32-bit cohort populations share a
 * word with a neighbour, which the word fill would leave at zero, so
 * they get a value of their own.
 */
static void fill_state(unsigned int win)
{
	unsigned int n, e, k;

	fill_block((char *)kcov_shm + sizeof(kcov_shm->bucket_seen),
		   sizeof(*kcov_shm) - sizeof(kcov_shm->bucket_seen),
		   100000, win);
	fill_block(&shm->stats, sizeof(shm->stats), 200000, win);
	fill_block(&parent_stats, sizeof(parent_stats), 9000000, win);

	kcov_shm->child_mode.pc_mode_children = 7 + win;
	kcov_shm->child_mode.cmp_mode_children = 9 + win;
	kcov_shm->cohorts.cmp_inject_arm_a_children = 11 + win;
	kcov_shm->cohorts.cmp_inject_arm_b_children = 13 + win;
	kcov_shm->cohorts.prop_ring_argop_arm_a_children = 15 + win;
	kcov_shm->cohorts.prop_ring_argop_arm_b_children = 17 + win;
	kcov_shm->cohorts.frontier_blend_arm_a_children = 19 + win;
	kcov_shm->cohorts.frontier_blend_arm_b_children = 21 + win;
	kcov_shm->cohorts.remote_adaptive_arm_a_children = 23 + win;
	kcov_shm->cohorts.remote_adaptive_arm_b_children = 25 + win;

	minicorpus_shm->mut_structured_shadow_samples = 500000 + 4000 * win;
	minicorpus_shm->mut_structured_shadow_divergences = 510000 + 700 * win;
	minicorpus_shm->mut_structured_arm_a_children = 27 + win;
	minicorpus_shm->mut_structured_arm_b_children = 29 + win;

	/* Two occupied pools, so the typed-hypothesis blocks have rows. */
	for (n = 0; n < 2; n++) {
		struct cmp_hyp_pool *p =
			&cmp_hints_shm->hyp_pools[3 + 4 * n][0];

		p->count = 6 + 5 * n;
		for (k = 0; k < CMP_HYP_KIND_NR; k++)
			p->per_kind_count[k] = 1 + k + n;
		for (e = 0; e < p->count; e++) {
			struct cmp_hypothesis *h = &p->entries[e];

			h->pc_wins = 11 * (e + 1) + 100 * n + 1000 * win;
			h->consumed_count = 13 * (e + 1) + 110 * n + 1100 * win;
			h->misses = 17 * (e + 1) + 120 * n + 1200 * win;
			h->corpus_save_wins = 19 * (e + 1) + 130 * n + 1300 * win;
			h->destructive_skips = 23 * (e + 1) + 140 * n + 1400 * win;
			h->context_skips = 29 * (e + 1) + 150 * n + 1500 * win;
		}
	}
}

/*
 * What a fresh child sees: a fake clock, a short syscall table, and the
 * shared regions the renderers read, all zero.  The globals the earlier
 * suites left in shm and parent_stats are cleared too.
 */
static void scenario_setup(void)
{
	unsigned int i;

	fake_clock_start();
	fake_sleep_hook = NULL;
	fake_output_log[0] = '\0';
	fake_diag_on = false;
	fake_chaos_active = false;

	memset(&shm->stats, 0, sizeof(shm->stats));
	memset(&parent_stats, 0, sizeof(parent_stats));
	kcov_shm = calloc(1, sizeof(*kcov_shm));
	cmp_hints_shm = calloc(1, sizeof(*cmp_hints_shm));
	minicorpus_shm = calloc(1, sizeof(*minicorpus_shm));
	if (kcov_shm == NULL || cmp_hints_shm == NULL || minicorpus_shm == NULL)
		BUG("stats render: cannot allocate the fake shared regions");

	for (i = 0; i < NFAKE_SYSCALLS; i++) {
		fake_entry[i].name = fake_names[i];
		fake_table[i].entry = &fake_entry[i];
	}
	biarch = false;
	syscalls = fake_table;
	max_nr_syscalls = NFAKE_SYSCALLS;
}

/* ---------- Periodic KCOV CMP dump ----------------------------------- */

/*
 * Let @sleep_s seconds pass, run the dump once, and compare what it
 * printed with @golden.
 */
static void periodic_dump(unsigned int sleep_s, const char *what,
			  const char *golden_name, const char *golden)
{
	if (sleep_s != 0)
		sleep(sleep_s);
	capture_len = 0;
	capture[0] = '\0';
	fake_output_log[0] = '\0';
	kcov_cmp_stats_periodic_dump();
	capture_drain_output();
	golden_expect(what, golden_name, golden, capture, '\n');
}

#define DUMP(sleep_s, what, golden) \
	periodic_dump(sleep_s, what, #golden, golden)

/* Every counter moves, each by its own amount. */
static void scenario_cmp_full(void)
{
	scenario_setup();
	fake_diag_on = true;

	fill_state(0);
	DUMP(0, "the arming call", "");
	fill_state(1);
	DUMP(599, "a call inside the interval", "");
	DUMP(1, "the first window", stats_golden_cmp_full_1);
	fill_state(2);
	DUMP(777, "the second window", stats_golden_cmp_full_2);
	DUMP(600, "a window with nothing moving", stats_golden_cmp_idle);
}

/*
 * One counter moves in an otherwise quiet window.  The any-delta gate
 * opens for each of these but the first, and the cohort row each one feeds
 * prints under the header it opens.  A scenario keeps to four windows, so
 * its 600 s apiece stay well inside the fake clock's limit.
 */
static void scenario_cmp_gates_a(void)
{
	struct stats_s *st = &shm->stats;

	scenario_setup();

	DUMP(0, "the arming call", "");
	st->frontier.plateau.blend_samples += 3;
	DUMP(600, "frontier_blend_samples alone", stats_golden_cmp_probe_frontier);
	kcov_shm->cmp_records.cmp_records_collected += 5;
	DUMP(600, "cmp_records_collected alone", stats_golden_cmp_probe_records);
	kcov_shm->reexec_gate.reexec_gate_pass += 7;
	DUMP(600, "reexec_gate_pass alone", stats_golden_cmp_probe_gate_pass);
	kcov_shm->cmp_parent.cmp_parent_new_cmps_control += 9;
	DUMP(600, "cmp_parent_new_cmps_control alone",
	     stats_golden_cmp_probe_parent_ctl);
}

static void scenario_cmp_gates_b(void)
{
	struct stats_s *st = &shm->stats;

	scenario_setup();

	DUMP(0, "the arming call", "");
	kcov_shm->hint_flat.cmp_hint_credit_entry_evicted += 11;
	DUMP(600, "cmp_hint_credit_entry_evicted alone",
	     stats_golden_cmp_probe_credit_evicted);
	minicorpus_shm->mut_structured_shadow_divergences += 2;
	DUMP(600, "mut_structured_shadow_divergences alone",
	     stats_golden_cmp_probe_mut_structured);
	st->remote_adaptive.samples += 4;
	DUMP(600, "remote_adaptive.samples alone",
	     stats_golden_cmp_probe_remote_adaptive);
	kcov_shm->hint_callsite.cmp_hint_callsite_injected[3] += 4;
	DUMP(600, "a callsite's injections alone", stats_golden_cmp_probe_callsite);
}

/* The same, for the rest of the per-callsite and per-arm arrays. */
static void scenario_cmp_gates_c(void)
{
	scenario_setup();

	DUMP(0, "the arming call", "");
	kcov_shm->hint_callsite.cmp_hint_callsite_pc_wins[2] += 6;
	DUMP(600, "a callsite's pc wins alone", stats_golden_cmp_probe_wins);
	kcov_shm->hint_callsite.cmp_hint_callsite_misses[5] += 8;
	DUMP(600, "a callsite's misses alone", stats_golden_cmp_probe_misses);
	kcov_shm->hints_flat.propagation_injected_callsite[1] += 3;
	DUMP(600, "a propagation callsite alone", stats_golden_cmp_probe_prop);
	kcov_shm->reexec_arms.reexec_attempts_by_arm[1] += 12;
	DUMP(600, "an arm's reexec attempts alone", stats_golden_cmp_probe_by_arm);
}

/*
 * Counters the dump only shows as totals do not open the gate; a counter
 * read from parent_stats does, and the chaos counter has a row of its own
 * that reads the chaos toggle.
 */
static void scenario_cmp_totals(void)
{
	struct stats_s *st = &shm->stats;

	scenario_setup();

	DUMP(0, "the arming call", "");
	st->remote_adaptive.would_demote += 5;
	st->arg.meta_addr_with_meta += 5;
	kcov_shm->cohorts.cmp_inject_arm_a_children += 2;
	DUMP(600, "totals alone", stats_golden_cmp_probe_levels);
	parent_stats.cmp_hints_try_get_attempts += 6;
	DUMP(600, "cmp_hints_try_get_attempts alone",
	     stats_golden_cmp_probe_try_get);
	kcov_shm->hints_flat.cmp_hints_chaos_suppressed += 4;
	DUMP(600, "chaos_suppressed, chaos off", stats_golden_cmp_probe_chaos_off);
	kcov_shm->hints_flat.cmp_hints_chaos_suppressed += 4;
	fake_chaos_active = true;
	DUMP(600, "chaos_suppressed, chaos on", stats_golden_cmp_probe_chaos_on);
}

/*
 * The paths around the gate: no kcov region, a counter that went back
 * since the last window, and no minicorpus region.
 */
static void scenario_cmp_edges(void)
{
	struct kcov_shared *kcov;

	scenario_setup();

	kcov = kcov_shm;
	kcov_shm = NULL;
	DUMP(0, "no kcov region", "");
	kcov_shm = kcov;

	DUMP(0, "the arming call", "");
	kcov_shm->cmp_records.cmp_records_collected += 9;
	DUMP(600, "a counter that moved", stats_golden_cmp_edge_up);
	kcov_shm->cmp_records.cmp_records_collected -= 5;
	DUMP(600, "a counter that went back", stats_golden_cmp_edge_back);
	minicorpus_shm->mut_structured_shadow_divergences += 3;
	DUMP(600, "a divergence count", stats_golden_cmp_edge_divergence);
	minicorpus_shm = NULL;
	DUMP(600, "no minicorpus region", stats_golden_cmp_edge_no_minicorpus);
}

/* ---------- Core --stats-json sections ------------------------------- */

/*
 * The sections of the "stats" object that stats/json/core.c owns, in the
 * order dump_stats_json() emits them, as stdout carries them.
 */
static void scenario_json_core(void)
{
	static char json[1 << 18];
	struct stat st;
	ssize_t n;
	int saved, fd;

	fill_block(&shm->stats, sizeof(shm->stats), 1000, 0);
	fill_block(&parent_stats, sizeof(parent_stats), 9000000, 0);

	fd = memfd_create("stats-render", 0);
	if (fd < 0)
		BUG("stats render: memfd_create failed");
	fflush(stdout);
	saved = dup(STDOUT_FILENO);
	if (saved < 0 || dup2(fd, STDOUT_FILENO) < 0)
		BUG("stats render: cannot redirect stdout");

	fputs("{\"stats\":{", stdout);
	json_stats_sep_reset();
	dump_stats_json_fault_and_fd_lifecycle();
	dump_stats_json_oracle();
	dump_stats_json_basic_subsystems();
	dump_stats_json_iouring_and_zombies();
	dump_stats_json_corruption_and_audit();
	dump_stats_json_lifecycle_and_storms();
	fputs("}}\n", stdout);
	fflush(stdout);
	dup2(saved, STDOUT_FILENO);

	if (fstat(fd, &st) != 0 || (size_t)st.st_size >= sizeof(json))
		BUG("stats render: the json capture does not fit");
	n = pread(fd, json, (size_t)st.st_size, 0);
	if (n != st.st_size)
		BUG("stats render: cannot read back the json capture");
	json[n] = '\0';
	golden_expect("the core json sections", "stats_golden_json_core",
		      stats_golden_json_core, json, ',');
}

/* ---------- Driver --------------------------------------------------- */

static unsigned int scenarios_failed;

static void run_scenario(void (*scenario)(void))
{
	int status;
	pid_t pid;

	fflush(stdout);
	fflush(stderr);
	pid = fork();
	if (pid < 0)
		BUG("stats render: fork failed");
	if (pid == 0) {
		scenario();
		_exit(golden_failures != 0);
	}
	if (waitpid_eintr(pid, &status, 0) != pid ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		scenarios_failed++;
}

void stats_render_self_check(void);
void stats_render_self_check(void)
{
	run_scenario(scenario_cmp_full);
	run_scenario(scenario_cmp_gates_a);
	run_scenario(scenario_cmp_gates_b);
	run_scenario(scenario_cmp_gates_c);
	run_scenario(scenario_cmp_totals);
	run_scenario(scenario_cmp_edges);
	run_scenario(scenario_json_core);

	/* Every scenario runs, so one pass prints each golden to bless. */
	if (scenarios_failed != 0)
		BUG("stats render: output differs from the golden, see above");
}
