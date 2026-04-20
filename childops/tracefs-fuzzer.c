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
 * Trinity-todo #2.3.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "random.h"
#include "shm.h"
#include "text-payloads.h"
#include "trinity.h"
#include "utils.h"

#define TRACEFS_ROOT	"/sys/kernel/debug/tracing"
#define MAX_EVENTS	512
#define TRACEFS_MAX_PATH	256

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
 * Per-child event enable-file cache.  Discovered once from
 * TRACEFS_ROOT/events/ at the first invocation.
 */
static char event_enable_paths[MAX_EVENTS][TRACEFS_MAX_PATH];
static unsigned int nr_event_enables;
static bool events_discovered;

/*
 * Available tracers discovered once from available_tracers.
 */
static char discovered_tracers[16][32];
static unsigned int nr_discovered_tracers;
static bool tracers_discovered;

static bool tracefs_available;
static bool tracefs_checked;

/* Check once whether tracefs is mounted and accessible. */
static bool check_tracefs(void)
{
	if (tracefs_checked)
		return tracefs_available;
	tracefs_checked = true;
	tracefs_available = (access(TRACEFS_ROOT "/tracing_on", F_OK) == 0);
	return tracefs_available;
}

/*
 * Recurse into TRACEFS_ROOT/events/ at depth 1-2 and collect paths ending
 * in "/enable".  Depth 1 gives per-subsystem enable; depth 2 gives
 * per-event enable -- both are interesting targets.
 */
static void discover_event_enables(void)
{
	char events_root[TRACEFS_MAX_PATH];
	DIR *d1;
	struct dirent *de1;

	events_discovered = true;

	snprintf(events_root, sizeof(events_root), "%s/events", TRACEFS_ROOT);

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
	FILE *f;
	char word[32];

	tracers_discovered = true;

	snprintf(path, sizeof(path), "%s/available_tracers", TRACEFS_ROOT);
	f = fopen(path, "r");
	if (f == NULL)
		return;

	while (nr_discovered_tracers < 16 && fscanf(f, "%31s", word) == 1) {
		snprintf(discovered_tracers[nr_discovered_tracers],
			 sizeof(discovered_tracers[0]), "%s", word);
		nr_discovered_tracers++;
	}
	fclose(f);
}

static void write_text_payload(const char *path)
{
	char buf[256];
	unsigned int len;
	int fd;
	ssize_t ret __unused__;

	fd = open(path, O_WRONLY | O_NONBLOCK);
	if (fd < 0)
		return;
	len = gen_text_payload(buf, sizeof(buf));
	ret = write(fd, buf, len);
	close(fd);
}

static void write_str(const char *path, const char *str)
{
	int fd = open(path, O_WRONLY | O_NONBLOCK);
	ssize_t ret __unused__;

	if (fd < 0)
		return;
	ret = write(fd, str, strlen(str));
	close(fd);
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
	const char *sym;
	unsigned int probe_num;
	int fd;
	ssize_t ret __unused__;

	snprintf(path, sizeof(path), "%s/kprobe_events", TRACEFS_ROOT);

	probe_num = rand() % 64;
	sym = RAND_ARRAY(kprobe_targets);

	switch (rand() % 5) {
	case 0:
		/* kprobe create */
		snprintf(spec, sizeof(spec), "p:trinity_k%u %s+%u",
			 probe_num, sym, (rand() % 256) & ~3u);
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
		write_text_payload(path);
		__atomic_add_fetch(&shm->stats.tracefs_kprobe_writes,
				   1, __ATOMIC_RELAXED);
		return;
	}

	fd = open(path, O_WRONLY | O_NONBLOCK);
	if (fd < 0)
		return;
	ret = write(fd, spec, strlen(spec));
	close(fd);

	__atomic_add_fetch(&shm->stats.tracefs_kprobe_writes,
			   1, __ATOMIC_RELAXED);
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
	unsigned int probe_num;
	unsigned long offset;
	int fd;
	ssize_t ret __unused__;

	snprintf(path, sizeof(path), "%s/uprobe_events", TRACEFS_ROOT);

	probe_num = rand() % 64;
	offset = (unsigned long)(rand() % 0x100000) & ~0xful;

	switch (rand() % 4) {
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
		write_text_payload(path);
		__atomic_add_fetch(&shm->stats.tracefs_uprobe_writes,
				   1, __ATOMIC_RELAXED);
		return;
	}

	fd = open(path, O_WRONLY | O_NONBLOCK);
	if (fd < 0)
		return;
	ret = write(fd, spec, strlen(spec));
	close(fd);

	__atomic_add_fetch(&shm->stats.tracefs_uprobe_writes,
			   1, __ATOMIC_RELAXED);
}

/*
 * Write to one of the ftrace function-filter files.  Produces glob patterns,
 * known symbol names, wildcards, and occasionally clears the filter.
 */
static void do_ftrace_filter(void)
{
	static const char * const filter_files[] = {
		TRACEFS_ROOT "/set_ftrace_filter",
		TRACEFS_ROOT "/set_ftrace_notrace",
		TRACEFS_ROOT "/set_graph_function",
	};
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
	const char *path = RAND_ARRAY(filter_files);
	char spec[128];
	int fd;
	ssize_t ret __unused__;

	switch (rand() % 4) {
	case 0: {
		/* Named glob */
		const char *s = RAND_ARRAY(globs);

		fd = open(path, O_WRONLY | O_NONBLOCK);
		if (fd < 0)
			break;
		ret = write(fd, s, strlen(s));
		close(fd);
		break;
	}
	case 1: {
		/* A known symbol from our kprobe target list */
		const char *s = RAND_ARRAY(kprobe_targets);

		fd = open(path, O_WRONLY | O_NONBLOCK);
		if (fd < 0)
			break;
		ret = write(fd, s, strlen(s));
		close(fd);
		break;
	}
	case 2:
		/* Clear filter by writing empty string */
		write_str(path, "");
		break;
	default:
		/*
		 * Alternate between random glob-like strings and content-aware
		 * payloads.  The glob matcher calls into vsnprintf internally,
		 * so format specifiers and long strings are interesting here.
		 */
		if (RAND_BOOL()) {
			snprintf(spec, sizeof(spec), "%c%c%c*",
				 'a' + (rand() % 26),
				 'a' + (rand() % 26),
				 'a' + (rand() % 26));
			write_str(path, spec);
		} else {
			write_text_payload(path);
		}
		break;
	}

	__atomic_add_fetch(&shm->stats.tracefs_filter_writes,
			   1, __ATOMIC_RELAXED);
}

/* Write to an events subsystem enable file -- toggles tracing for a subsystem. */
static void do_event_enable(void)
{
	const char *val;

	if (!events_discovered)
		discover_event_enables();
	if (nr_event_enables == 0)
		return;

	val = RAND_BOOL() ? "1" : "0";
	write_str(event_enable_paths[rand() % nr_event_enables], val);

	__atomic_add_fetch(&shm->stats.tracefs_event_enable_writes,
			   1, __ATOMIC_RELAXED);
}

/* Write a trace_option name (with optional "no" prefix) to trace_options. */
static void do_trace_options(void)
{
	char path[TRACEFS_MAX_PATH];
	char option[64];

	snprintf(path, sizeof(path), "%s/trace_options", TRACEFS_ROOT);

	if (RAND_BOOL())
		snprintf(option, sizeof(option), "%s",
			 RAND_ARRAY(trace_option_names));
	else
		snprintf(option, sizeof(option), "no%s",
			 RAND_ARRAY(trace_option_names));

	write_str(path, option);
	__atomic_add_fetch(&shm->stats.tracefs_misc_writes,
			   1, __ATOMIC_RELAXED);
}

/* Switch the current tracer -- exercises the tracer registration path. */
static void do_current_tracer(void)
{
	char path[TRACEFS_MAX_PATH];

	snprintf(path, sizeof(path), "%s/current_tracer", TRACEFS_ROOT);

	if (!tracers_discovered)
		discover_tracers();

	if (nr_discovered_tracers > 0 && !ONE_IN(8))
		write_str(path,
			  discovered_tracers[rand() % nr_discovered_tracers]);
	else
		write_str(path, RAND_ARRAY(tracer_names));

	__atomic_add_fetch(&shm->stats.tracefs_misc_writes,
			   1, __ATOMIC_RELAXED);
}

/* Toggle tracing on/off. */
static void do_tracing_on(void)
{
	char path[TRACEFS_MAX_PATH];

	snprintf(path, sizeof(path), "%s/tracing_on", TRACEFS_ROOT);
	write_str(path, RAND_BOOL() ? "1" : "0");

	__atomic_add_fetch(&shm->stats.tracefs_misc_writes,
			   1, __ATOMIC_RELAXED);
}

/* Resize the ring buffer -- exercises the buffer reallocation path. */
static void do_buffer_size(void)
{
	char path[TRACEFS_MAX_PATH];
	char val[32];
	static const unsigned int sizes[] = {
		0, 1, 4, 16, 64, 128, 256, 512, 1024, 4096,
	};

	snprintf(path, sizeof(path), "%s/buffer_size_kb", TRACEFS_ROOT);
	snprintf(val, sizeof(val), "%u", RAND_ARRAY(sizes));
	write_str(path, val);

	__atomic_add_fetch(&shm->stats.tracefs_misc_writes,
			   1, __ATOMIC_RELAXED);
}

bool tracefs_fuzzer(struct childdata *child)
{
	(void)child;

	if (!check_tracefs())
		return true;

	switch (rand() % 11) {
	case 0: case 1:	do_kprobe_events();	break;
	case 2: case 3:	do_uprobe_events();	break;
	case 4: case 5:	do_ftrace_filter();	break;
	case 6:		do_event_enable();	break;
	case 7:		do_trace_options();	break;
	case 8:		do_current_tracer();	break;
	case 9:		do_tracing_on();	break;
	case 10:	do_buffer_size();	break;
	}

	return true;
}
