/*
 * tracefs_fuzzer - exercise the tracefs/ftrace string-parsing interfaces.
 *
 * The kprobe and uprobe event creation paths parse user-supplied strings
 * into kernel probe specifications -- essentially hand-written compilers with
 * no formal grammar, running in kernel context.  set_ftrace_filter applies a
 * glob matcher over the entire registered function list.  These paths are
 * historically buggy and are only reachable via writes to specific tracefs
 * files, which the general random-write fuzzer almost never hits.
 *
 * This childop exercises those surfaces with a mix of format-appropriate
 * content and raw garbage:
 *
 *   kprobe_events        -- kprobe/kretprobe creation spec strings
 *   uprobe_events        -- uprobe/uretprobe creation spec strings
 *   set_ftrace_filter    -- function name glob patterns (clears filter too)
 *   set_ftrace_notrace   -- negated function name glob patterns
 *   set_graph_function   -- function graph depth filter
 *   trace_options        -- option name strings (no/option toggles)
 *   events/SUBSYS/EVENT/enable -- "0" or "1" to toggle individual event files
 *   current_tracer       -- tracer name selection
 *   tracing_on           -- "0" or "1"
 *   buffer_size_kb       -- numeric string
 *
 * Cap-gate: the function-tracer subset (set_ftrace_*, current_tracer,
 * available_tracers) and the event-tracing subset (events/<subsys>/...) are
 * compiled in independently.  CONFIG_FTRACE=n with EVENT_TRACING=y is a
 * supported build and a real-world test kernel configuration.  At first
 * invocation each child probes one canonical file from each subset and
 * builds a runtime dispatch table that contains only the handlers whose
 * required subset is actually present, eliminating wasted ENOENT syscalls
 * on each random pick.
 */

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "child.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "text-payloads.h"
#include "trinity.h"
#include "utils.h"

#define MAX_EVENTS	512
#define TRACEFS_MAX_PATH	256

/*
 * Tracefs mount roots, in preferred order.  Modern kernels expose tracefs
 * directly at /sys/kernel/tracing; older systems (or those where tracefs
 * piggy-backs on debugfs) keep it at /sys/kernel/debug/tracing.  Same file
 * tree either way -- pick the first one that's actually present.  Mirrors
 * the resolver in syscalls/perf_event_open.c.
 */
static const char * const tracefs_roots[] = {
	"/sys/kernel/tracing",
	"/sys/kernel/debug/tracing",
};

/*
 * Cached root chosen by tracefs_fuzzer_init() in the parent; children
 * inherit it via COW.  NULL until init finds a usable mount, after which
 * every snprintf() in this file builds paths beneath it.
 */
static const char *tracefs_root;

/*
 * Function-filter target files.  Built once in tracefs_fuzzer_init() from
 * the resolved tracefs_root so do_ftrace_filter()'s RAND_ARRAY pick stays
 * a single indexed load.
 */
static char filter_files[3][TRACEFS_MAX_PATH];

/*
 * Stable kernel symbols likely to exist on any kernel build.  Used as
 * targets for kprobe creation -- the probe will fail gracefully if the
 * symbol is absent or inlined, exercising the error path.
 */
static const char * const kprobe_targets[] = {
	"schedule",
	"do_exit",
	"sys_read",
	"sys_write",
	"sys_open",
	"sys_close",
	"sys_mmap",
	"ksys_read",
	"ksys_write",
	"vfs_read",
	"vfs_write",
	"vfs_open",
	"do_sys_openat2",
	"alloc_pages",
	"kmalloc",
	"kfree",
	"copy_from_user",
	"copy_to_user",
	"tcp_sendmsg",
	"tcp_recvmsg",
	"sock_sendmsg",
	"inet_stream_connect",
	"security_file_open",
	"security_mmap_file",
	"do_mmap",
	"vm_mmap",
	"handle_mm_fault",
	"do_page_fault",
	"exc_page_fault",
	"wake_up_process",
};

/*
 * Available kernel tracers.  "nop" is always present; others may not be
 * compiled in but the write will simply fail with EINVAL.
 */
static const char * const tracer_names[] = {
	"nop",
	"function",
	"function_graph",
	"irqsoff",
	"preemptoff",
	"preemptirqsoff",
	"wakeup",
	"wakeup_rt",
	"wakeup_dl",
	"mmiotrace",
	"hwlat",
	"timerlat",
	"osnoise",
};

/*
 * Trace option tokens.  The kernel parser accepts "option" to enable
 * and "nooption" to disable.  We try both forms.
 */
static const char * const trace_option_names[] = {
	"print-parent",
	"sym-offset",
	"sym-addr",
	"verbose",
	"raw",
	"hex",
	"bin",
	"block",
	"stacktrace",
	"userstacktrace",
	"latency-format",
	"record-cmd",
	"overwrite",
	"disable_on_free",
	"irq-info",
	"markers",
	"event-fork",
	"pause-on-trace",
	"hash-ptr",
	"func_stack_trace",
	"display-graph",
};

/*
 * Event enable-file cache.  Discovered once in the parent from
 * tracefs_root/events/; children inherit the table via COW.
 */
static char event_enable_paths[MAX_EVENTS][TRACEFS_MAX_PATH];
static unsigned int nr_event_enables;

/*
 * Available tracers discovered once in the parent from available_tracers.
 */
static char discovered_tracers[16][32];
static unsigned int nr_discovered_tracers;

/*
 * Overall dispatch enable, set by tracefs_fuzzer_init() in the parent.
 * False means tracefs is absent or both subsets (function-tracer and
 * event-tracing) are missing — the childop body bails on every call.
 */
static bool tracefs_available;

/*
 * Per-target child-side inaccessibility cache.
 *
 * The parent runs as the invoking user (typically root) and discovers
 * write targets with access(..., W_OK).  Children then drop uid + caps
 * before dispatching ops, so most tracefs files the parent waved through
 * fail open() with EACCES/EPERM in the child.  Without a cache, every
 * dispatch wastes a syscall on the same denied path -- "attempted"
 * write counters dominated by paths the child can never open.
 *
 * On the first post-drop open() denial of a given target, the child
 * latches the corresponding slot.  Subsequent dispatches either redraw
 * (list-backed ops -- event_enable, ftrace_filter) or short-circuit
 * (single-path ops).  Latching is per-process (COW from the parent),
 * so each child accumulates its own picture as it makes attempts and
 * the dispatcher converges on targets it can actually write.
 *
 * EROFS is intentionally not latched: a remount can restore writability
 * mid-run; EACCES/EPERM are the privilege-mismatch cases.
 */
static bool event_enable_inaccessible[MAX_EVENTS];

enum single_path_id {
	SP_KPROBE_EVENTS = 0,
	SP_UPROBE_EVENTS,
	SP_TRACE_OPTIONS,
	SP_CURRENT_TRACER,
	SP_TRACING_ON,
	SP_BUFFER_SIZE_KB,
	NR_SINGLE_PATHS,
};
static bool single_path_inaccessible[NR_SINGLE_PATHS];
/* Sized to match filter_files[] -- one slot per ftrace function-filter target. */
static bool filter_file_inaccessible[3];

/*
 * Open a tracefs file for writing.  On EACCES/EPERM (the post-drop
 * privilege-mismatch errnos), latch *bad so the caller's dispatch path
 * stops drawing this target on future calls.  bad == NULL is supported
 * for the rare callsite without a cache slot.
 */
static int open_write_target(const char *path, bool *bad)
{
	int fd = open(path, O_WRONLY | O_NONBLOCK);

	if (fd < 0 && bad != NULL && (errno == EACCES || errno == EPERM))
		*bad = true;
	return fd;
}

/*
 * Recurse into tracefs_root/events/ at depth 1-2 and collect paths ending
 * in "/enable".  Depth 1 gives per-subsystem enable; depth 2 gives
 * per-event enable -- both are interesting targets.
 */
static void discover_event_enables(void)
{
	char events_root[TRACEFS_MAX_PATH];
	DIR *d1;
	struct dirent *de1;

	snprintf(events_root, sizeof(events_root), "%s/events", tracefs_root);

	d1 = opendir(events_root);
	if (d1 == NULL)
		return;

	while ((de1 = readdir(d1)) != NULL && nr_event_enables < MAX_EVENTS) {
		char sub[TRACEFS_MAX_PATH];
		DIR *d2;
		struct dirent *de2;

		if (de1->d_name[0] == '.')
			continue;

		/* Depth-1 enable: events/<subsystem>/enable */
		if (snprintf(sub, sizeof(sub), "%s/%s/enable",
			     events_root, de1->d_name) < (int)sizeof(sub)) {
			if (access(sub, W_OK) == 0 &&
			    nr_event_enables < MAX_EVENTS) {
				snprintf(event_enable_paths[nr_event_enables],
					 TRACEFS_MAX_PATH, "%s", sub);
				nr_event_enables++;
			}
		}

		/* Depth-2 enable: events/<subsystem>/<event>/enable */
		if (snprintf(sub, sizeof(sub), "%s/%s",
			     events_root, de1->d_name) >= (int)sizeof(sub))
			continue;

		d2 = opendir(sub);
		if (d2 == NULL)
			continue;

		while ((de2 = readdir(d2)) != NULL &&
		       nr_event_enables < MAX_EVENTS) {
			char path[TRACEFS_MAX_PATH];

			if (de2->d_name[0] == '.')
				continue;

			if (snprintf(path, sizeof(path), "%s/%s/%s/enable",
				     events_root, de1->d_name,
				     de2->d_name) < (int)sizeof(path) &&
			    access(path, W_OK) == 0) {
				snprintf(event_enable_paths[nr_event_enables],
					 TRACEFS_MAX_PATH, "%s", path);
				nr_event_enables++;
			}
		}
		closedir(d2);
	}

	closedir(d1);
}

/*
 * Read available_tracers once so we only write valid tracer names.
 */
static void discover_tracers(void)
{
	char path[TRACEFS_MAX_PATH];
	char buf[1024];
	char *p, *end;
	ssize_t n;
	int fd;

	snprintf(path, sizeof(path), "%s/available_tracers", tracefs_root);
	/* Raw open/read instead of fopen/fscanf/fclose: avoid stdio's
	 * per-call malloc of the FILE struct + IO buffer.  available_tracers
	 * is a single short line of whitespace-separated tracer names; one
	 * bounded read is enough. */
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';

	p = buf;
	end = buf + n;
	while (p < end && nr_discovered_tracers < 16) {
		size_t wlen;

		while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' ||
				   *p == '\r'))
			p++;
		if (p >= end)
			break;

		wlen = 0;
		while (p + wlen < end && p[wlen] != ' ' && p[wlen] != '\t' &&
		       p[wlen] != '\n' && p[wlen] != '\r')
			wlen++;
		if (wlen == 0)
			break;
		if (wlen > sizeof(discovered_tracers[0]) - 1)
			wlen = sizeof(discovered_tracers[0]) - 1;
		memcpy(discovered_tracers[nr_discovered_tracers], p, wlen);
		discovered_tracers[nr_discovered_tracers][wlen] = '\0';
		nr_discovered_tracers++;
		p += wlen;
	}
}

/*
 * Per-ARM write outcomes.  Each do_*() handler attributes its single
 * dispatch attempt to exactly one of:
 *
 *   OUTCOME_OPEN_FAIL   - open(O_WRONLY|O_NONBLOCK) returned < 0
 *                         (tracefs not mounted, EACCES after uid/cap drop,
 *                         ENOENT on a per-event enable unloaded mid-run, ...)
 *   OUTCOME_WRITE_FAIL  - open() succeeded, write() returned < 0
 *                         (EINVAL on a malformed probe spec, EBUSY, ...)
 *   OUTCOME_WRITE_OK    - open() succeeded, write() returned >= 0
 *                         (the byte actually reached the kernel parser)
 *
 * write_fail + write_ok == old per-ARM counter; open_fail is information
 * that was previously dropped on the floor.
 */
enum write_outcome {
	OUTCOME_OPEN_FAIL = 0,
	OUTCOME_WRITE_FAIL,
	OUTCOME_WRITE_OK,
};

enum tracefs_arm {
	ARM_KPROBE = 0,
	ARM_UPROBE,
	ARM_FILTER,
	ARM_EVENT_ENABLE,
	ARM_MISC,
	NR_TRACEFS_ARMS,
};

static void bump_arm_counter(enum tracefs_arm arm, enum write_outcome outcome)
{
	static const size_t offsets[NR_TRACEFS_ARMS][3] = {
		[ARM_KPROBE] = {
			[OUTCOME_OPEN_FAIL]  = offsetof(struct stats_s, tracefs_fuzzer.kprobe_open_fail),
			[OUTCOME_WRITE_FAIL] = offsetof(struct stats_s, tracefs_fuzzer.kprobe_write_fail),
			[OUTCOME_WRITE_OK]   = offsetof(struct stats_s, tracefs_fuzzer.kprobe_write_ok),
		},
		[ARM_UPROBE] = {
			[OUTCOME_OPEN_FAIL]  = offsetof(struct stats_s, tracefs_fuzzer.uprobe_open_fail),
			[OUTCOME_WRITE_FAIL] = offsetof(struct stats_s, tracefs_fuzzer.uprobe_write_fail),
			[OUTCOME_WRITE_OK]   = offsetof(struct stats_s, tracefs_fuzzer.uprobe_write_ok),
		},
		[ARM_FILTER] = {
			[OUTCOME_OPEN_FAIL]  = offsetof(struct stats_s, tracefs_fuzzer.filter_open_fail),
			[OUTCOME_WRITE_FAIL] = offsetof(struct stats_s, tracefs_fuzzer.filter_write_fail),
			[OUTCOME_WRITE_OK]   = offsetof(struct stats_s, tracefs_fuzzer.filter_write_ok),
		},
		[ARM_EVENT_ENABLE] = {
			[OUTCOME_OPEN_FAIL]  = offsetof(struct stats_s, tracefs_fuzzer.event_enable_open_fail),
			[OUTCOME_WRITE_FAIL] = offsetof(struct stats_s, tracefs_fuzzer.event_enable_write_fail),
			[OUTCOME_WRITE_OK]   = offsetof(struct stats_s, tracefs_fuzzer.event_enable_write_ok),
		},
		[ARM_MISC] = {
			[OUTCOME_OPEN_FAIL]  = offsetof(struct stats_s, tracefs_fuzzer.misc_open_fail),
			[OUTCOME_WRITE_FAIL] = offsetof(struct stats_s, tracefs_fuzzer.misc_write_fail),
			[OUTCOME_WRITE_OK]   = offsetof(struct stats_s, tracefs_fuzzer.misc_write_ok),
		},
	};
	unsigned long *p = (unsigned long *)((char *)&shm->stats + offsets[arm][outcome]);

	__atomic_add_fetch(p, 1, __ATOMIC_RELAXED);
}

static enum write_outcome write_text_payload(const char *path, bool *bad)
{
	char buf[256];
	unsigned int len;
	int fd;
	ssize_t ret;

	fd = open_write_target(path, bad);
	if (fd < 0)
		return OUTCOME_OPEN_FAIL;
	len = gen_text_payload(buf, sizeof(buf));
	ret = write(fd, buf, len);
	close(fd);
	return ret < 0 ? OUTCOME_WRITE_FAIL : OUTCOME_WRITE_OK;
}

static enum write_outcome write_str(const char *path, const char *str, bool *bad)
{
	int fd = open_write_target(path, bad);
	ssize_t ret;

	if (fd < 0)
		return OUTCOME_OPEN_FAIL;
	ret = write(fd, str, strlen(str));
	close(fd);
	return ret < 0 ? OUTCOME_WRITE_FAIL : OUTCOME_WRITE_OK;
}


/*
 * Generate a kprobe_events spec string.  Produces four kinds:
 *   - Properly-formed create: "p:trinity_k<N> symbol+offset [arg...]"
 *   - Kretprobe:              "r:trinity_r<N> symbol"
 *   - Delete a named probe:   "-:trinity_k<N>"
 *   - Raw garbage for parser stress
 */
static void do_kprobe_events(void)
{
	char path[TRACEFS_MAX_PATH];
	char spec[256];
	bool *bad = &single_path_inaccessible[SP_KPROBE_EVENTS];
	const char *sym;
	unsigned int probe_num;
	int fd;
	ssize_t ret;

	if (*bad)
		return;

	snprintf(path, sizeof(path), "%s/kprobe_events", tracefs_root);

	probe_num = rnd_modulo_u32(64);
	sym = RAND_ARRAY(kprobe_targets);

	switch (rnd_modulo_u32(5)) {
	case 0:
		/* kprobe create */
		snprintf(spec, sizeof(spec), "p:trinity_k%u %s+%u",
			 probe_num, sym, rnd_modulo_u32(256) & ~3u);
		break;
	case 1:
		/* kretprobe create */
		snprintf(spec, sizeof(spec), "r:trinity_r%u %s",
			 probe_num, sym);
		break;
	case 2:
		/* delete a probe we may have created */
		snprintf(spec, sizeof(spec), "-:trinity_k%u", probe_num);
		break;
	case 3:
		/* kprobe with fetch args -- stresses argument parser */
		snprintf(spec, sizeof(spec),
			 "p:trinity_k%u %s a1=%%ax a2=%%bx a3=+0(%%sp):u64",
			 probe_num, sym);
		break;
	default:
		/*
		 * Content-aware payload: format specifiers, numeric boundaries,
		 * and long strings reach deeper into the parser than random bytes
		 * that fail at the first character.
		 */
		bump_arm_counter(ARM_KPROBE, write_text_payload(path, bad));
		return;
	}

	fd = open_write_target(path, bad);
	if (fd < 0) {
		bump_arm_counter(ARM_KPROBE, OUTCOME_OPEN_FAIL);
		return;
	}
	ret = write(fd, spec, strlen(spec));
	close(fd);

	bump_arm_counter(ARM_KPROBE,
			 ret < 0 ? OUTCOME_WRITE_FAIL : OUTCOME_WRITE_OK);
}

/*
 * Generate an uprobe_events spec string.  Uses /proc/self/exe as the
 * binary path -- it always exists and is a valid ELF target.  The offset
 * will likely miss any symbol, but the parser still runs to completion.
 */
static void do_uprobe_events(void)
{
	char path[TRACEFS_MAX_PATH];
	char spec[256];
	bool *bad = &single_path_inaccessible[SP_UPROBE_EVENTS];
	unsigned int probe_num;
	unsigned long offset;
	int fd;
	ssize_t ret;

	if (*bad)
		return;

	snprintf(path, sizeof(path), "%s/uprobe_events", tracefs_root);

	probe_num = rnd_modulo_u32(64);
	offset = (unsigned long)rnd_modulo_u32(0x100000) & ~0xful;

	switch (rnd_modulo_u32(4)) {
	case 0:
		/* uprobe create */
		snprintf(spec, sizeof(spec),
			 "p:trinity_u%u /proc/self/exe:0x%lx",
			 probe_num, offset);
		break;
	case 1:
		/* uretprobe create */
		snprintf(spec, sizeof(spec),
			 "r:trinity_u%u /proc/self/exe:0x%lx",
			 probe_num, offset);
		break;
	case 2:
		/* delete */
		snprintf(spec, sizeof(spec), "-:trinity_u%u", probe_num);
		break;
	default:
		bump_arm_counter(ARM_UPROBE, write_text_payload(path, bad));
		return;
	}

	fd = open_write_target(path, bad);
	if (fd < 0) {
		bump_arm_counter(ARM_UPROBE, OUTCOME_OPEN_FAIL);
		return;
	}
	ret = write(fd, spec, strlen(spec));
	close(fd);

	bump_arm_counter(ARM_UPROBE,
			 ret < 0 ? OUTCOME_WRITE_FAIL : OUTCOME_WRITE_OK);
}

/*
 * Write to one of the ftrace function-filter files.  Produces glob patterns,
 * known symbol names, wildcards, and occasionally clears the filter.
 */
static void do_ftrace_filter(void)
{
	static const char * const globs[] = {
		"*",
		"schedule*",
		"do_*",
		"sys_*",
		"vfs_*",
		"tcp_*",
		"ip_*",
		"sock_*",
		"security_*",
		"mem*",
		"alloc*",
		"__*",
	};
	const char *path;
	bool *bad;
	unsigned int idx;
	unsigned int attempt;
	char spec[128];
	enum write_outcome outcome;
	int fd;
	ssize_t ret;

	/*
	 * Pick a filter file the child hasn't already latched as denied.
	 * With only three slots we can afford a small bounded retry rather
	 * than scanning the array; if all three are latched, bail this
	 * dispatch.
	 */
	idx = rnd_modulo_u32(ARRAY_SIZE(filter_files));
	for (attempt = 0; attempt < ARRAY_SIZE(filter_files); attempt++) {
		if (!filter_file_inaccessible[idx])
			break;
		idx = (idx + 1) % ARRAY_SIZE(filter_files);
	}
	if (filter_file_inaccessible[idx])
		return;
	path = filter_files[idx];
	bad = &filter_file_inaccessible[idx];

	switch (rnd_modulo_u32(4)) {
	case 0: {
		/* Named glob */
		const char *s = RAND_ARRAY(globs);

		fd = open_write_target(path, bad);
		if (fd < 0) {
			outcome = OUTCOME_OPEN_FAIL;
			break;
		}
		ret = write(fd, s, strlen(s));
		close(fd);
		outcome = ret < 0 ? OUTCOME_WRITE_FAIL : OUTCOME_WRITE_OK;
		break;
	}
	case 1: {
		/* A known symbol from our kprobe target list */
		const char *s = RAND_ARRAY(kprobe_targets);

		fd = open_write_target(path, bad);
		if (fd < 0) {
			outcome = OUTCOME_OPEN_FAIL;
			break;
		}
		ret = write(fd, s, strlen(s));
		close(fd);
		outcome = ret < 0 ? OUTCOME_WRITE_FAIL : OUTCOME_WRITE_OK;
		break;
	}
	case 2:
		/* Clear filter by writing empty string */
		outcome = write_str(path, "", bad);
		break;
	default:
		/*
		 * Alternate between random glob-like strings and content-aware
		 * payloads.  The glob matcher calls into vsnprintf internally,
		 * so format specifiers and long strings are interesting here.
		 */
		if (RAND_BOOL()) {
			snprintf(spec, sizeof(spec), "%c%c%c*",
				 'a' + rnd_modulo_u32(26),
				 'a' + rnd_modulo_u32(26),
				 'a' + rnd_modulo_u32(26));
			outcome = write_str(path, spec, bad);
		} else {
			outcome = write_text_payload(path, bad);
		}
		break;
	}

	bump_arm_counter(ARM_FILTER, outcome);
}

/* Write to an events subsystem enable file -- toggles tracing for a subsystem. */
static void do_event_enable(void)
{
	const char *val;
	unsigned int idx;
	unsigned int attempt;

	if (nr_event_enables == 0)
		return;

	/*
	 * Linear-probe a small bounded window from a random start, skipping
	 * entries the child has latched as denied.  Bounded so a heavily
	 * winnowed table doesn't spin a child loop on each dispatch; if no
	 * accessible slot is found in the window, bail and rely on the next
	 * dispatch to try a fresh start.
	 */
	idx = rnd_modulo_u32(nr_event_enables);
	for (attempt = 0; attempt < 8; attempt++) {
		if (!event_enable_inaccessible[idx])
			break;
		idx = (idx + 1) % nr_event_enables;
	}
	if (event_enable_inaccessible[idx])
		return;

	val = RAND_BOOL() ? "1" : "0";
	bump_arm_counter(ARM_EVENT_ENABLE,
			 write_str(event_enable_paths[idx], val,
				   &event_enable_inaccessible[idx]));
}

/* Write a trace_option name (with optional "no" prefix) to trace_options. */
static void do_trace_options(void)
{
	char path[TRACEFS_MAX_PATH];
	char option[64];
	bool *bad = &single_path_inaccessible[SP_TRACE_OPTIONS];

	if (*bad)
		return;

	snprintf(path, sizeof(path), "%s/trace_options", tracefs_root);

	if (RAND_BOOL())
		snprintf(option, sizeof(option), "%s",
			 RAND_ARRAY(trace_option_names));
	else
		snprintf(option, sizeof(option), "no%s",
			 RAND_ARRAY(trace_option_names));

	bump_arm_counter(ARM_MISC, write_str(path, option, bad));
}

/* Switch the current tracer -- exercises the tracer registration path. */
static void do_current_tracer(void)
{
	char path[TRACEFS_MAX_PATH];
	bool *bad = &single_path_inaccessible[SP_CURRENT_TRACER];
	enum write_outcome outcome;

	if (*bad)
		return;

	snprintf(path, sizeof(path), "%s/current_tracer", tracefs_root);

	if (nr_discovered_tracers > 0 && !ONE_IN(8))
		outcome = write_str(path,
				    discovered_tracers[rnd_modulo_u32(nr_discovered_tracers)],
				    bad);
	else
		outcome = write_str(path, RAND_ARRAY(tracer_names), bad);

	bump_arm_counter(ARM_MISC, outcome);
}

/* Toggle tracing on/off. */
static void do_tracing_on(void)
{
	char path[TRACEFS_MAX_PATH];
	bool *bad = &single_path_inaccessible[SP_TRACING_ON];

	if (*bad)
		return;

	snprintf(path, sizeof(path), "%s/tracing_on", tracefs_root);
	bump_arm_counter(ARM_MISC,
			 write_str(path, RAND_BOOL() ? "1" : "0", bad));
}

/* Resize the ring buffer -- exercises the buffer reallocation path. */
static void do_buffer_size(void)
{
	char path[TRACEFS_MAX_PATH];
	char val[32];
	bool *bad = &single_path_inaccessible[SP_BUFFER_SIZE_KB];
	static const unsigned int sizes[] = {
		0, 1, 4, 16, 64, 128, 256, 512, 1024, 4096,
	};

	if (*bad)
		return;

	snprintf(path, sizeof(path), "%s/buffer_size_kb", tracefs_root);
	snprintf(val, sizeof(val), "%u", RAND_ARRAY(sizes));
	bump_arm_counter(ARM_MISC, write_str(path, val, bad));
}

/*
 * Dispatch table.  Each entry pairs a do_*() handler with the subset bitmask
 * it requires, plus a relative weight controlling pick frequency (matching
 * the prior switch-case slot counts).  The weights mirror the historical
 * dispatch ratios: kprobe/uprobe/ftrace_filter twice as likely as the rest.
 *
 * required == 0 means the op only touches files that exist on every tracefs
 * build (kprobe_events, uprobe_events, trace_options, tracing_on,
 * buffer_size_kb).  REQ_FTRACE entries depend on CONFIG_FTRACE; REQ_EVENTS
 * entries depend on the static event tree under events/.
 */
enum tracefs_subset {
	REQ_FTRACE = 1u << 0,
	REQ_EVENTS = 1u << 1,
};

struct tracefs_op {
	void (*fn)(void);
	unsigned int required;
	unsigned int weight;
};

static const struct tracefs_op tracefs_ops[] = {
	{ do_kprobe_events,  0,          2 },
	{ do_uprobe_events,  0,          2 },
	{ do_ftrace_filter,  REQ_FTRACE, 2 },
	{ do_event_enable,   REQ_EVENTS, 1 },
	{ do_trace_options,  0,          1 },
	{ do_current_tracer, REQ_FTRACE, 1 },
	{ do_tracing_on,     0,          1 },
	{ do_buffer_size,    0,          1 },
};

/*
 * Runtime pick array built once per process from tracefs_ops[], filtered to
 * the entries whose required-subset mask is satisfied by the kernel under
 * test.  Each op is pushed weight-times so rnd_modulo_u32(nr_picks) gives
 * weighted uniform selection without a separate weight-walk on every
 * dispatch.  Sized to comfortably hold the sum of all weights (currently 11).
 */
static const struct tracefs_op *pick_table[16];
static unsigned int nr_picks;

static void build_pick_table(unsigned int avail)
{
	unsigned int i, j;

	for (i = 0; i < ARRAY_SIZE(tracefs_ops); i++) {
		if ((tracefs_ops[i].required & ~avail) != 0)
			continue;
		for (j = 0; j < tracefs_ops[i].weight; j++) {
			if (nr_picks >= ARRAY_SIZE(pick_table))
				return;
			pick_table[nr_picks++] = &tracefs_ops[i];
		}
	}
}

/*
 * One-shot parent init.  Confirms tracefs is mounted, learns which
 * subsets are reachable on this kernel, runs the directory walks for
 * the event-enable cache and the tracer-name cache, and constructs the
 * runtime pick table.  Children inherit tracefs_available, the caches,
 * and pick_table[] via COW so no child re-walks tracefs on first hit.
 *
 * Leaves tracefs_available=false (and nr_picks=0) when tracefs is
 * absent or when both function-tracer and event-tracing subsets are
 * missing -- in those degenerate cases the childop body bails on
 * every call.
 */
void tracefs_fuzzer_init(void)
{
	bool ftrace_subset_present;
	bool events_subset_present;
	char path[TRACEFS_MAX_PATH];
	unsigned int avail = 0;
	size_t r;

	/*
	 * Probe each candidate root in order and latch the first one whose
	 * tracing_on file exists.  Preferring /sys/kernel/tracing means we
	 * actually hit the mount on modern kernels where the legacy debugfs
	 * tracing dir is absent (or just a symlinked-in secondary).
	 */
	for (r = 0; r < ARRAY_SIZE(tracefs_roots); r++) {
		snprintf(path, sizeof(path), "%s/tracing_on",
			 tracefs_roots[r]);
		if (access(path, F_OK) == 0) {
			tracefs_root = tracefs_roots[r];
			break;
		}
	}

	if (tracefs_root == NULL) {
		__atomic_store_n(&shm->stats.childop.latch_reason[CHILD_OP_TRACEFS_FUZZER],
				 CHILDOP_LATCH_UNSUPPORTED, __ATOMIC_RELAXED);
		return;
	}

	snprintf(path, sizeof(path), "%s/current_tracer", tracefs_root);
	ftrace_subset_present = (access(path, F_OK) == 0);
	snprintf(path, sizeof(path), "%s/available_events", tracefs_root);
	events_subset_present = (access(path, F_OK) == 0);

	outputstd("tracefs-fuzzer: root=%s ftrace_subset=%s events_subset=%s\n", /* check-static: child-output-ok */
		  tracefs_root,
		  ftrace_subset_present ? "yes" : "no",
		  events_subset_present ? "yes" : "no");

	if (!ftrace_subset_present && !events_subset_present) {
		__atomic_store_n(&shm->stats.childop.latch_reason[CHILD_OP_TRACEFS_FUZZER],
				 CHILDOP_LATCH_UNSUPPORTED, __ATOMIC_RELAXED);
		return;
	}

	if (ftrace_subset_present) {
		avail |= REQ_FTRACE;
		discover_tracers();
	}
	if (events_subset_present) {
		avail |= REQ_EVENTS;
		discover_event_enables();
	}

	snprintf(filter_files[0], sizeof(filter_files[0]),
		 "%s/set_ftrace_filter", tracefs_root);
	snprintf(filter_files[1], sizeof(filter_files[1]),
		 "%s/set_ftrace_notrace", tracefs_root);
	snprintf(filter_files[2], sizeof(filter_files[2]),
		 "%s/set_graph_function", tracefs_root);

	build_pick_table(avail);

	tracefs_available = true;
}

bool tracefs_fuzzer(struct childdata *child)
{
	if (!tracefs_available)
		return true;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	pick_table[rnd_modulo_u32(nr_picks)]->fn();
	return true;
}
