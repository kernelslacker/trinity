/*
 * procfs_writer - discover writable nodes under /proc, /sys and
 * /sys/kernel/debug, then write fuzzy payloads to them.
 *
 * These pseudo-filesystems contain hundreds of hand-written kernel parsers
 * (cgroup controllers, PMU event strings, ftrace, kprobe/uprobe, sysctls,
 * per-task knobs) reachable from user space and historically a rich source
 * of bugs.  The default random-write fuzzer aims at fds returned by
 * fd-creating syscalls; it almost never hits these targets because they
 * make up a tiny slice of the total fd space.
 *
 * Discovery runs once in the parent before fork_children: walk a small
 * set of well-known trees with a bounded recursion depth, stat() every
 * regular file, and keep those accessible W_OK by the parent's
 * (higher-privileged) uid.  Children inherit the entries[] table via
 * COW and use a per-child inaccessible[] prune to skip paths the
 * dropped-privilege child cannot open; a lazy in-child fallback re-runs
 * discovery only if the parent init was skipped.  A class/prefix-based
 * deny table (see deny_rules[] below) refuses whole families of host-
 * global control nodes — panic / watchdog / sysrq / core / kexec /
 * module / trace / cgroup-host — so a random write cannot silence the
 * kernel's own crash detectors, mutate policy that later runs inherit,
 * or fire immediate one-shot actions from a stray byte.
 *
 * Each call: pick a random entry, generate a fuzzy payload with the
 * existing rand_bytes generator, open(O_WRONLY|O_NONBLOCK), write, close.
 * Errors are ignored — most writes will EINVAL/EACCES, which is fine; the
 * goal is to exercise the kernel's write handler, not to succeed.
 *
 * One write in four uses gen_text_payload() from rand/text-payloads.c with a
 * 4 KB buffer, exercising long-string, embedded-NUL, format-specifier, and
 * numeric-boundary paths that raw garbage bytes rarely reach.
 */

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>

#include "arch.h"
#include "pids.h"
#include "child.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "text-payloads.h"
#include "trinity.h"
#include "utils.h"

#define MAX_DISCOVERY_ENTRIES	1024
#define MAX_DISCOVERY_DEPTH	3
#define PROCFS_MAX_PATH		256

enum tree_kind {
	TREE_PROC = 0,
	TREE_SYS,
	TREE_DEBUGFS,
};

struct discovered_entry {
	char path[PROCFS_MAX_PATH];
	enum tree_kind tree;
};

static struct discovered_entry *entries;
static unsigned int nr_entries;
static bool discovery_done;

/*
 * Per-child cache of inherited entries that the dropped-privilege child
 * cannot actually open.  Discovery in the parent uses access(W_OK), but
 * childops execute after the uid+caps drop, so the inherited table is
 * dominated by paths the child is forbidden to touch.  Without a child-
 * side prune the draws keep picking those paths for the child's whole
 * lifetime, open() failures dominate, and the existing open/write
 * counters report a write coverage far higher than what reaches a
 * kernel parser.
 *
 * The array is plain process-local memory: fork() gives each child its
 * own COW copy, so a mark made by one child never escapes to a sibling
 * or back to the parent and no locking is required.  Indexing matches
 * entries[]; a torn or missed update only costs one extra open attempt
 * on the next draw.
 */
static unsigned char inaccessible[MAX_DISCOVERY_ENTRIES];
static unsigned int nr_inaccessible;

static void mark_inaccessible(const struct discovered_entry *e)
{
	unsigned int idx = (unsigned int)(e - entries);

	if (idx >= MAX_DISCOVERY_ENTRIES)
		return;
	if (inaccessible[idx])
		return;
	inaccessible[idx] = 1;
	nr_inaccessible++;
}

/*
 * Class-based deny policy.
 *
 * Discovery walks the /proc, /sys and debugfs trees indiscriminately and
 * would happily admit any writable regular file it finds.  Writes to a
 * handful of well-known control nodes have side effects that outlast the
 * fuzzer's run: they silence the kernel's own crash-on-wedge detectors
 * (so real bugs later in the run wedge the box with no panic/kdump), they
 * mutate host-global policy that later trinity runs (or unrelated
 * workloads) inherit, or they fire immediate one-shot actions like sysrq
 * or kexec from a random byte.  Any of those turn "trinity found a bug"
 * into an unattributable outage on the host.
 *
 * The old deny table listed a handful of exact paths and quietly missed
 * newer siblings (e.g. hardlockup_all_cpu_backtrace, panic_on_warn,
 * kexec_load_limit_*, core_pattern, modules_disabled, subtree_control).
 * A class/prefix table catches whole families as the kernel grows and,
 * unlike the old table, still admits the write-fuzz targets that share
 * an ancestor with a denied node (e.g. /proc/sys/kernel/keys/ children
 * are not denied, only /proc/sys/kernel/{panic,watchdog,...}).
 *
 * Every rule carries a class tag; the tags are emitted in the run-id
 * provenance block so a crash triage can immediately see which classes
 * were withheld from mutation and rule the fuzzer in or out.
 */
enum deny_match {
	DENY_PREFIX,	/* pattern is a leading substring of path */
	DENY_EXACT,	/* pattern equals path */
	DENY_SUFFIX, /* path lives under a discovery root AND ends with pattern */
};

struct deny_rule {
	const char *pattern;
	enum deny_match kind;
	const char *class;
};

static const struct deny_rule deny_rules[] = {
	/*
	 * panic policy — random writes (often a zero byte) disable the
	 * kernel's crash-on-condition triggers, so a later real bug wedges
	 * the box silently with no panic / kdump / netconsole output.
	 */
	{ "/proc/sys/kernel/panic",           DENY_PREFIX, "panic" },
	{ "/proc/sys/kernel/softlockup_",     DENY_PREFIX, "panic" },
	{ "/proc/sys/kernel/hardlockup_",     DENY_PREFIX, "panic" },
	{ "/proc/sys/kernel/hung_task_",      DENY_PREFIX, "panic" },
	{ "/proc/sys/kernel/oops_",           DENY_PREFIX, "panic" },
	{ "/proc/sys/kernel/unknown_nmi_panic",     DENY_EXACT, "panic" },
	{ "/proc/sys/kernel/max_rcu_stall_to_panic", DENY_EXACT, "panic" },
	{ "/proc/sys/kernel/print-fatal-signals",   DENY_EXACT, "panic" },

	/*
	 * watchdog — same failure mode as the panic class: mutating any of
	 * these turns the on-CPU / hung-task watchdogs off and future real
	 * hangs stop being observable.
	 */
	{ "/proc/sys/kernel/watchdog",     DENY_PREFIX, "watchdog" },
	{ "/proc/sys/kernel/nmi_watchdog", DENY_EXACT,  "watchdog" },
	{ "/proc/sys/kernel/soft_watchdog", DENY_EXACT, "watchdog" },

	/*
	 * sysrq — fires immediate one-shot actions (reboot, sync, oom-kill,
	 * emergency-sync) from any random byte, ending the run.
	 */
	{ "/proc/sysrq-trigger",     DENY_EXACT, "sysrq" },
	{ "/proc/sys/kernel/sysrq",  DENY_EXACT, "sysrq" },

	/*
	 * core-dump policy — per-pid mem and coredump_filter cover both
	 * /proc/self/ and /proc/<pid>/ siblings via the /proc-anchored
	 * suffix.  core_pattern and core_uses_pid rewrite the system-wide
	 * dump handler that kdump and bandicoot rely on.
	 */
	{ "/proc/sys/kernel/core_", DENY_PREFIX,      "core" },
	{ "/mem",                   DENY_SUFFIX, "core" },
	{ "/coredump_filter",       DENY_SUFFIX, "core" },

	/*
	 * kexec — a mutated crashkernel image or load-limit is either an
	 * unreproducible boot at the next reset or a silent regression of
	 * the crash-dump path.
	 */
	{ "/proc/sys/kernel/kexec_", DENY_PREFIX, "kexec" },
	{ "/sys/kernel/kexec_",      DENY_PREFIX, "kexec" },

	/*
	 * module loading policy — modules_disabled is a one-way latch and
	 * modprobe is executed by the kernel with root creds.
	 */
	{ "/proc/sys/kernel/modprobe",         DENY_EXACT, "module" },
	{ "/proc/sys/kernel/modules_disabled", DENY_EXACT, "module" },

	/*
	 * tracing / dynamic-debug control — mutating filter, enable or
	 * dynamic_debug/control nodes globally reprograms the host tracers
	 * and drowns dmesg for every workload on the box.  The dedicated
	 * tracefs_fuzzer childop drives these deliberately from a curated
	 * list; procfs_writer stumbling into the same tree at random
	 * poisons that fuzzer's signal and the host's tracing.
	 */
	{ "/sys/kernel/debug/dynamic_debug/", DENY_PREFIX, "trace" },
	{ "/sys/kernel/tracing/",             DENY_PREFIX, "trace" },
	{ "/sys/kernel/debug/tracing/",       DENY_PREFIX, "trace" },
	{ "/proc/sys/kernel/ftrace_",         DENY_PREFIX, "trace" },
	{ "/proc/sys/kernel/traceoff_on_warning", DENY_EXACT, "trace" },

	/*
	 * host-global cgroup controls — cgroup.subtree_control /
	 * cgroup.procs / cgroup.max.* at any level can reparent or throttle
	 * whole slices, including trinity's own children and unrelated host
	 * workloads.  Deny the class by filename anywhere in the tree.
	 */
	{ "/cgroup.subtree_control", DENY_SUFFIX, "cgroup-host" },
	{ "/cgroup.procs",           DENY_SUFFIX, "cgroup-host" },
	{ "/cgroup.threads",         DENY_SUFFIX, "cgroup-host" },
	{ "/cgroup.max.depth",       DENY_SUFFIX, "cgroup-host" },
	{ "/cgroup.max.descendants", DENY_SUFFIX, "cgroup-host" },
};

/*
 * DENY_SUFFIX fires when the path lives under a discovery root — cgroup
 * v2 controls sit under /sys/fs/cgroup and per-pid /mem / coredump_filter
 * under /proc/, so the reachable set spans both trees.
 */
static bool path_under_discovery_root(const char *path)
{
	return strncmp(path, "/proc/", 6) == 0 ||
	       strncmp(path, "/sys/", 5) == 0;
}

static bool path_denied(const char *path)
{
	size_t path_len = strlen(path);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(deny_rules); i++) {
		const struct deny_rule *r = &deny_rules[i];
		size_t plen;

		switch (r->kind) {
		case DENY_EXACT:
			if (strcmp(path, r->pattern) == 0)
				return true;
			break;
		case DENY_PREFIX:
			plen = strlen(r->pattern);
			if (path_len >= plen &&
			    strncmp(path, r->pattern, plen) == 0)
				return true;
			break;
		case DENY_SUFFIX:
			plen = strlen(r->pattern);
			if (!path_under_discovery_root(path))
				break;
			if (path_len >= plen &&
			    strcmp(path + path_len - plen, r->pattern) == 0)
				return true;
			break;
		}
	}

	return false;
}

/*
 * Build a comma-separated list of the distinct deny classes, preserving
 * the order in which each class first appears in deny_rules[].  Emitted
 * once from stats_runid_render() as part of the run-identity block so a
 * crash triage can attribute (or rule out) mutation of a host-global
 * knob without reading source.
 *
 * Cached on first call — the deny table is compile-time constant.
 */
const char *procfs_writer_deny_policy_summary(void)
{
	static char summary[128];
	static bool built;
	size_t off = 0;
	unsigned int i, j;

	if (built)
		return summary;

	summary[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(deny_rules); i++) {
		const char *cls = deny_rules[i].class;
		bool seen = false;
		int n;

		for (j = 0; j < i; j++) {
			if (strcmp(deny_rules[j].class, cls) == 0) {
				seen = true;
				break;
			}
		}
		if (seen)
			continue;

		if (off >= sizeof(summary))
			break;
		n = snprintf(summary + off, sizeof(summary) - off,
			     "%s%s", off > 0 ? "," : "", cls);
		if (n < 0 || (size_t)n >= sizeof(summary) - off) {
			summary[off] = '\0';
			break;
		}
		off += (size_t)n;
	}

	built = true;
	return summary;
}

static enum tree_kind tree_for_path(const char *path)
{
	if (strncmp(path, "/sys/kernel/debug", 17) == 0)
		return TREE_DEBUGFS;
	if (strncmp(path, "/sys/", 5) == 0)
		return TREE_SYS;
	return TREE_PROC;
}

static void add_entry(const char *path)
{
	if (nr_entries >= MAX_DISCOVERY_ENTRIES)
		return;
	if (strlen(path) >= PROCFS_MAX_PATH)
		return;
	if (path_denied(path))
		return;
	if (access(path, W_OK) != 0)
		return;

	strcpy(entries[nr_entries].path, path);
	entries[nr_entries].tree = tree_for_path(path);
	nr_entries++;
}

/*
 * Recursive descent with bounded depth.  We use lstat() so we can refuse
 * to follow symlinks — /sys is full of them and they readily form loops
 * or escape into uninteresting territory.
 */
static void walk_dir(const char *root, unsigned int depth_left)
{
	DIR *dir;
	struct dirent *de;

	if (nr_entries >= MAX_DISCOVERY_ENTRIES)
		return;

	dir = opendir(root);
	if (dir == NULL)
		return;

	while ((de = readdir(dir)) != NULL) {
		char child[PROCFS_MAX_PATH];
		struct stat st;

		if (de->d_name[0] == '.')
			continue;

		if ((size_t)snprintf(child, sizeof(child), "%s/%s",
				     root, de->d_name) >= sizeof(child))
			continue;

		if (lstat(child, &st) != 0)
			continue;
		if (S_ISLNK(st.st_mode))
			continue;

		if (S_ISDIR(st.st_mode)) {
			if (depth_left > 0)
				walk_dir(child, depth_left - 1);
		} else if (S_ISREG(st.st_mode)) {
			add_entry(child);
		}

		if (nr_entries >= MAX_DISCOVERY_ENTRIES)
			break;
	}

	closedir(dir);
}

/*
 * Per-task interfaces are added by explicit allowlist rather than by
 * walking /proc/<pid>/, so we don't accidentally pick up dangerous nodes
 * such as /proc/<pid>/mem or /proc/<pid>/clear_refs side effects.
 */
static void add_per_task_files(const char *base)
{
	static const char * const names[] = {
		"oom_score_adj",
		"comm",
		"projid_map",
		"gid_map",
		"uid_map",
		"setgroups",
		"loginuid",
		"sessionid",
		"timerslack_ns",
		"autogroup",
	};
	char path[PROCFS_MAX_PATH];
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		if ((size_t)snprintf(path, sizeof(path), "%s/%s",
				     base, names[i]) >= sizeof(path))
			continue;
		add_entry(path);
	}
}

static void discover_targets(void)
{
	char per_pid[PROCFS_MAX_PATH];

	entries = zmalloc(MAX_DISCOVERY_ENTRIES * sizeof(*entries));

	walk_dir("/sys/kernel/debug", MAX_DISCOVERY_DEPTH);
	walk_dir("/sys/kernel", MAX_DISCOVERY_DEPTH);
	walk_dir("/sys/module", MAX_DISCOVERY_DEPTH);
	walk_dir("/sys/class", MAX_DISCOVERY_DEPTH);
	walk_dir("/sys/fs/cgroup", MAX_DISCOVERY_DEPTH);
	walk_dir("/proc/sys", MAX_DISCOVERY_DEPTH);

	add_per_task_files("/proc/self");
	snprintf(per_pid, sizeof(per_pid), "/proc/%d", mypid());
	add_per_task_files(per_pid);
}

/*
 * Per-tree write outcomes.  Discovery in the parent walks under root and
 * keeps every node access(W_OK) accepts, but writes happen in the child
 * after uid+caps drop, so many opens and writes fail.  Counting these
 * separately turns the dump from "attempts" into "did we actually land
 * any bytes in the kernel parser, and where did the rest fall off?"
 */
enum write_outcome {
	OUTCOME_OPEN_FAIL = 0,
	OUTCOME_WRITE_FAIL,
	OUTCOME_WRITE_OK,
};

static void bump_tree_counter(enum tree_kind tree, enum write_outcome outcome)
{
	static const size_t offsets[3][3] = {
		[TREE_PROC] = {
			[OUTCOME_OPEN_FAIL]  = offsetof(struct stats_s, procfs_writer.procfs_open_fail),
			[OUTCOME_WRITE_FAIL] = offsetof(struct stats_s, procfs_writer.procfs_write_fail),
			[OUTCOME_WRITE_OK]   = offsetof(struct stats_s, procfs_writer.procfs_write_ok),
		},
		[TREE_SYS] = {
			[OUTCOME_OPEN_FAIL]  = offsetof(struct stats_s, procfs_writer.sysfs_open_fail),
			[OUTCOME_WRITE_FAIL] = offsetof(struct stats_s, procfs_writer.sysfs_write_fail),
			[OUTCOME_WRITE_OK]   = offsetof(struct stats_s, procfs_writer.sysfs_write_ok),
		},
		[TREE_DEBUGFS] = {
			[OUTCOME_OPEN_FAIL]  = offsetof(struct stats_s, procfs_writer.debugfs_open_fail),
			[OUTCOME_WRITE_FAIL] = offsetof(struct stats_s, procfs_writer.debugfs_write_fail),
			[OUTCOME_WRITE_OK]   = offsetof(struct stats_s, procfs_writer.debugfs_write_ok),
		},
	};
	unsigned long *p = (unsigned long *)((char *)&shm->stats + offsets[tree][outcome]);

	__atomic_add_fetch(p, 1, __ATOMIC_RELAXED);
}

static void do_one_write(const struct discovered_entry *e)
{
	unsigned char buf[256];
	/*
	 * Larger buffer for text payloads: kernel sysfs/procfs parsers read up
	 * to PAGE_SIZE, so 4 KB gives long-string generators room to exercise
	 * the buffer-length checks that 256-byte writes never reach.
	 */
	char text_buf[4096];
	unsigned int len;
	ssize_t ret;
	int fd;

	fd = open(e->path, O_WRONLY | O_NONBLOCK);
	if (fd < 0) {
		/*
		 * EACCES/EPERM here are the steady-state signal that the
		 * dropped-privilege child can never open this path, so
		 * remember it and let future draws skip past.  Transient
		 * errors (ENOENT from a vanishing /proc/<pid>/ entry,
		 * EBUSY from an in-flight handler) are NOT cached — those
		 * paths may succeed on the next attempt.
		 */
		if (errno == EACCES || errno == EPERM)
			mark_inaccessible(e);
		bump_tree_counter(e->tree, OUTCOME_OPEN_FAIL);
		return;
	}

	if (ONE_IN(4)) {
		len = gen_text_payload(text_buf, sizeof(text_buf));
		ret = write(fd, text_buf, len);
	} else {
		len = 1 + rnd_modulo_u32(sizeof(buf));
		generate_rand_bytes(buf, len);
		ret = write(fd, buf, len);
	}

	close(fd);

	bump_tree_counter(e->tree,
			  ret < 0 ? OUTCOME_WRITE_FAIL : OUTCOME_WRITE_OK);
}

/*
 * Walk the discovery trees once in the parent, before fork_children.
 * Each child inherits the entries[] table and discovery_done=true via
 * the fork's COW pages, so no child has to repeat the ~thousands of
 * lstat()+access() syscalls the discovery walk costs.  Without this
 * pre-init, every freshly-forked child that picked PROCFS_WRITER on
 * its first iteration would block for hundreds of ms re-walking the
 * same six sysfs/proc trees, which dropped iters/s by an order of
 * magnitude under realistic dispatch ratios.
 */
void procfs_writer_init(void)
{
	if (discovery_done == false) {
		discover_targets();
		discovery_done = true;
	}
}

bool procfs_writer(struct childdata *child)
{
	/* discover_targets() should have been called from the parent, but
	 * keep the lazy fallback so a missing init does not break the op. */
	if (discovery_done == false) {
		discover_targets();
		discovery_done = true;
	}

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (nr_entries == 0) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_INIT_FAILED,
					 __ATOMIC_RELAXED);
		return true;
	}

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	/*
	 * Draw a target the child believes it can still open.  Bounded
	 * retries — if every draw lands on a cached-inaccessible entry we
	 * fall through to whatever the last draw produced; the open will
	 * fail and bump OUTCOME_OPEN_FAIL, which keeps the existing
	 * accounting honest when nr_inaccessible has saturated.
	 */
	unsigned int idx = rnd_modulo_u32(nr_entries);
	if (inaccessible[idx]) {
		unsigned int attempts;

		for (attempts = 0; attempts < 8; attempts++) {
			idx = rnd_modulo_u32(nr_entries);
			if (!inaccessible[idx])
				break;
		}
	}
	do_one_write(&entries[idx]);
	return true;
}
