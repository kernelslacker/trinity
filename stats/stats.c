#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "arg-len-semantics.h"
#include "breadcrumb_ring.h"
#include "child.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "reach-band.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "version.h"

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

/*
 * Aggregate-stats table column widths. Header + every row uses the same
 * format string so output is greppable (grep '^fd_lifecycle ') and
 * human-scannable (columns line up).
 */
static void stats_emit_header(void)
{
	output(0, "\n");
	output(0, STATS_HDR_FMT, "CATEGORY", "METRIC", "VALUE");
	output(0, STATS_HDR_FMT,
	       "----------------------",
	       "--------------------------------",
	       "-----");
}

void stat_row(const char *category, const char *metric, unsigned long value)
{
	output(0, STATS_ROW_FMT, category, metric, value);
}

/*
 * Mechanical name-prefix → category lookup.  The table is ordered so that
 * longer prefixes shadow shorter ones for the same head ("readlink" before
 * "read", "sendfile" before "send"); first match wins.  Operator-grade
 * categorisation, not a taxonomy — anything not listed lands in OTHER.
 */
unsigned int stats_syscall_category(const char *name)
{
	static const struct { const char *p; unsigned char cat; } tab[] = {
		{ "readlink", SYSCAT_FILE },   { "preadv",   SYSCAT_READ },
		{ "pread",    SYSCAT_READ },   { "read",     SYSCAT_READ },
		{ "pwritev",  SYSCAT_WRITE },  { "pwrite",   SYSCAT_WRITE },
		{ "writev",   SYSCAT_WRITE },  { "write",    SYSCAT_WRITE },
		{ "open",     SYSCAT_OPEN },   { "creat",    SYSCAT_OPEN },
		{ "mmap",     SYSCAT_MMAP },   { "munmap",   SYSCAT_MMAP },
		{ "mremap",   SYSCAT_MMAP },   { "mprotect", SYSCAT_MMAP },
		{ "madvise",  SYSCAT_MMAP },   { "msync",    SYSCAT_MMAP },
		{ "mbind",    SYSCAT_MMAP },   { "mlock",    SYSCAT_MMAP },
		{ "munlock",  SYSCAT_MMAP },   { "mincore",  SYSCAT_MMAP },
		{ "brk",      SYSCAT_MMAP },
		{ "sendfile", SYSCAT_FILE },
		{ "socket",   SYSCAT_SOCKET }, { "bind",     SYSCAT_SOCKET },
		{ "listen",   SYSCAT_SOCKET }, { "accept",   SYSCAT_SOCKET },
		{ "connect",  SYSCAT_SOCKET }, { "send",     SYSCAT_SOCKET },
		{ "recv",     SYSCAT_SOCKET }, { "shutdown", SYSCAT_SOCKET },
		{ "getsock",  SYSCAT_SOCKET }, { "setsock",  SYSCAT_SOCKET },
		{ "getpeer",  SYSCAT_SOCKET },
		{ "fork",     SYSCAT_PROCESS },{ "vfork",    SYSCAT_PROCESS },
		{ "clone",    SYSCAT_PROCESS },{ "exec",     SYSCAT_PROCESS },
		{ "exit",     SYSCAT_PROCESS },{ "wait",     SYSCAT_PROCESS },
		{ "kill",     SYSCAT_PROCESS },{ "tkill",    SYSCAT_PROCESS },
		{ "tgkill",   SYSCAT_PROCESS },{ "pidfd",    SYSCAT_PROCESS },
		{ "futex",    SYSCAT_IPC },    { "mq_",      SYSCAT_IPC },
		{ "msg",      SYSCAT_IPC },    { "sem",      SYSCAT_IPC },
		{ "shm",      SYSCAT_IPC },    { "pipe",     SYSCAT_IPC },
		{ "eventfd",  SYSCAT_IPC },    { "signalfd", SYSCAT_IPC },
		{ "rt_sig",   SYSCAT_IPC },    { "sigaction",SYSCAT_IPC },
		{ "stat",     SYSCAT_FILE },   { "fstat",    SYSCAT_FILE },
		{ "lstat",    SYSCAT_FILE },   { "access",   SYSCAT_FILE },
		{ "chmod",    SYSCAT_FILE },   { "chown",    SYSCAT_FILE },
		{ "fchmod",   SYSCAT_FILE },   { "fchown",   SYSCAT_FILE },
		{ "lchown",   SYSCAT_FILE },   { "link",     SYSCAT_FILE },
		{ "unlink",   SYSCAT_FILE },   { "symlink",  SYSCAT_FILE },
		{ "rename",   SYSCAT_FILE },   { "mkdir",    SYSCAT_FILE },
		{ "rmdir",    SYSCAT_FILE },   { "close",    SYSCAT_FILE },
		{ "dup",      SYSCAT_FILE },   { "fcntl",    SYSCAT_FILE },
		{ "ioctl",    SYSCAT_FILE },   { "lseek",    SYSCAT_FILE },
		{ "truncate", SYSCAT_FILE },   { "ftruncate",SYSCAT_FILE },
		{ "fsync",    SYSCAT_FILE },   { "fdatasync",SYSCAT_FILE },
		{ "sync",     SYSCAT_FILE },
	};
	unsigned int i;

	if (name == NULL)
		return SYSCAT_OTHER;
	for (i = 0; i < ARRAY_SIZE(tab); i++)
		if (strncmp(name, tab[i].p, strlen(tab[i].p)) == 0)
			return tab[i].cat;
	return SYSCAT_OTHER;
}

static void dump_syscall_category_histogram(void)
{
	static const char * const cat_names[NR_SYSCAT] = {
		"read", "write", "open", "mmap", "socket",
		"process", "file", "ipc", "other",
	};
	unsigned long total = 0;
	unsigned int i;

	for (i = 0; i < NR_SYSCAT; i++)
		total += parent_stats.syscall_category_count[i];
	if (total == 0)
		return;

	output(0, "Syscall category histogram (total: %lu):\n", total);
	for (i = 0; i < NR_SYSCAT; i++) {
		unsigned long c = parent_stats.syscall_category_count[i];
		unsigned long pct10 = total ? (c * 1000UL / total) : 0UL;

		output(0, "  %-8s %10lu  (%lu.%lu%%)\n",
		       cat_names[i], c, pct10 / 10, pct10 % 10);
	}
}

static void dump_entry(const struct syscalltable *table, unsigned int i)
{
	struct syscallentry *entry;
	unsigned int j;

	entry = table[i].entry;
	if (entry == NULL)
		return;

	if (entry->attempted == 0)
		return;

	output(0, "%s: (attempted:%u. success:%u. failures:%u.\n", entry->name, entry->attempted, entry->successes, entry->failures);

	for (j = 0; j <= NR_ERRNOS; j++) {
		if (entry->errnos[j] != 0) {
			output(0, "    %s: %d\n", strerror(j), entry->errnos[j]);
		}
	}
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


/*
 * Descriptor-table form for stat categories whose JSON / text emit shape
 * is "object name + N (field, value) scalar pairs".  Each category lists
 * its fields once; the JSON walker and the text walker iterate the same
 * descriptor so a new counter is added by declaring the struct member and
 * appending one STAT_FIELD() row -- the JSON key is derived from the
 * field-name suffix so the schema cannot drift from the struct.
 *
 * Generalises the in-tree pattern already used by defense_counters[] for
 * the periodic-window dump; here it replaces correlated edits in
 * struct stats_s + dump_stats_json() + dump_stats() with a single edit
 * site per counter.
 */
unsigned long stat_field_load(const struct stat_field *f)
{
	unsigned long *p = (unsigned long *)((char *)&shm->stats + f->offset);
	return __atomic_load_n(p, __ATOMIC_RELAXED);
}

static unsigned long stat_gate_load(const struct stat_category *cat)
{
	unsigned long *p = (unsigned long *)((char *)&shm->stats + cat->gate_offset);
	return __atomic_load_n(p, __ATOMIC_RELAXED);
}


/*
 * Emit one category as text rows.  Mirrors the existing
 * "if (shm->stats.<gate>) { stat_row(...); ... }" idiom: when the gate
 * counter is zero the whole block is suppressed so quiet runs stay terse.
 */
void stat_category_emit_text(const struct stat_category *cat)
{
	size_t i;

	if (stat_gate_load(cat) == 0)
		return;
	for (i = 0; i < cat->n_fields; i++)
		stat_row(cat->name, cat->fields[i].name,
		         stat_field_load(&cat->fields[i]));
}

/* --blob-mutator (default off): A/B observability for the ARG_BUF_SIZED
 * content-authoring lane.  fills is the gate (total invocations that
 * authored content), havoc_ops is the count of bounded byte-mutation
 * ops applied on top of the FILL floor, havoc_prefix_len_ops is the
 * subset of havoc ops the prefix-len arm was picked for (stamp a
 * plausible length / size value at buffer offset 0 to reach length-
 * gated parsers -- TLV entry length, netlink attr nla_len, on-wire
 * header size fields -- its ratio to havoc_ops is the observable per-
 * arm selection rate), dict_inserts is the count of
 * committed cmp-pool splats the CMPDICT rung applied from the learned
 * per-nr cmp_hints pool (one bump per successful cmp_hints_try_get
 * pull + splat; pool misses are silent), static_magic_inserts is the
 * count of committed splats the CMPDICT rung applied from the built-
 * in well-known-magic table (ext4 / XFS / BTRFS / squashfs / ELF /
 * gzip) -- the ratio to dict_inserts is the observable static-vs-
 * learned A/B split.  dict_transform_inserts is the count of
 * committed splats (across both sources) that applied a non-plain
 * splat form -- big-endian byte-swap or value ± 1 at width -- for
 * endian and off-by-one boundary coverage; the ratio to
 * (dict_inserts + static_magic_inserts) is the transform-vs-plain
 * split.  All five are bumped only by CMPDICT, so the per-rung
 * contribution is isolated across an off / fill / havoc / cmpdict
 * A/B.  When the mode is OFF the gate counter stays at zero so
 * stat_category_emit_text suppresses the whole block (render-gap-
 * aware). */
static const struct stat_field blob_mutator_fields[] = {
	STAT_FIELD(blob, fills),
	STAT_FIELD(blob, havoc_ops),
	STAT_FIELD(blob, havoc_prefix_len_ops),
	STAT_FIELD(blob, dict_inserts),
	STAT_FIELD(blob, static_magic_inserts),
	STAT_FIELD(blob, dict_transform_inserts),
	STAT_FIELD(blob, base_from_corpus),
	STAT_FIELD(blob, base_from_random),
};

const struct stat_category blob_mutator_category =
	STAT_CATEGORY("blob_mutator",
	              blob_fills,
	              blob_mutator_fields);

static const struct stat_field msg_zerocopy_churn_fields[] = {
	STAT_FIELD(msg_zerocopy_churn, runs),
	STAT_FIELD(msg_zerocopy_churn, setup_failed),
	STAT_FIELD(msg_zerocopy_churn, sends_ok),
	STAT_FIELD(msg_zerocopy_churn, sends_efault),
	STAT_FIELD(msg_zerocopy_churn, sends_eagain),
	STAT_FIELD(msg_zerocopy_churn, errqueue_drained),
	STAT_FIELD(msg_zerocopy_churn, errqueue_empty),
	STAT_FIELD(msg_zerocopy_churn, munmap_ok),
	STAT_FIELD(msg_zerocopy_churn, send_after_munmap_caught),
	STAT_FIELD(msg_zerocopy_churn, sndzc_disable_ok),
};

const struct stat_category msg_zerocopy_churn_category =
	STAT_CATEGORY("msg_zerocopy_churn",
	              msg_zerocopy_churn_runs,
	              msg_zerocopy_churn_fields);

static const struct stat_field tcp_ulp_swap_churn_fields[] = {
	STAT_FIELD(tcp_ulp_swap_churn, runs),
	STAT_FIELD(tcp_ulp_swap_churn, setup_failed),
	STAT_FIELD(tcp_ulp_swap_churn, install_tls_ok),
	STAT_FIELD(tcp_ulp_swap_churn, tx_install_ok),
	STAT_FIELD(tcp_ulp_swap_churn, send_ok),
	STAT_FIELD(tcp_ulp_swap_churn, swap_rejected_ok),
	STAT_FIELD(tcp_ulp_swap_churn, ifname_probe_ok),
	STAT_FIELD(tcp_ulp_swap_churn, uninstall_ok),
	STAT_FIELD(tcp_ulp_swap_churn, reinstall_ok),
	STAT_FIELD(tcp_ulp_swap_churn, install_failed),
};

const struct stat_category tcp_ulp_swap_churn_category =
	STAT_CATEGORY("tcp_ulp_swap_churn",
	              tcp_ulp_swap_churn_runs,
	              tcp_ulp_swap_churn_fields);

static const struct stat_field tls_rotate_fields[] = {
	STAT_FIELD(tls_rotate, runs),
	STAT_FIELD(tls_rotate, setup_failed),
	STAT_FIELD(tls_rotate, ulp_failed),
	STAT_FIELD(tls_rotate, ulp_asymmetric),
	STAT_FIELD(tls_rotate, installs),
	STAT_FIELD(tls_rotate, rekeys_ok),
	STAT_FIELD(tls_rotate, rekeys_rejected),
};

const struct stat_category tls_rotate_category =
	STAT_CATEGORY("tls_rotate",
	              tls_rotate_runs,
	              tls_rotate_fields);

static const struct stat_field cred_transition_fields[] = {
	STAT_FIELD(cred_transition, runs),
	STAT_FIELD(cred_transition, setup_failed),
	STAT_FIELD(cred_transition, capset_ok),
	STAT_FIELD(cred_transition, capset_failed),
	STAT_FIELD(cred_transition, op_ok),
	STAT_FIELD(cred_transition, op_failed),
	STAT_FIELD(cred_transition, keyctl_ok),
	STAT_FIELD(cred_transition, keyctl_failed),
};

const struct stat_category cred_transition_category =
	STAT_CATEGORY("cred_transition",
	              cred_transition_runs,
	              cred_transition_fields);

static const struct stat_field netns_teardown_fields[] = {
	STAT_FIELD(netns_teardown, runs),
	STAT_FIELD(netns_teardown, setup_failed),
	STAT_FIELD(netns_teardown, unshare_ok),
	STAT_FIELD(netns_teardown, socket_pair_ok),
	STAT_FIELD(netns_teardown, fork_ok),
	STAT_FIELD(netns_teardown, setns_ok),
	STAT_FIELD(netns_teardown, kill_ok),
	STAT_FIELD(netns_teardown, completed_ok),
};

const struct stat_category netns_teardown_category =
	STAT_CATEGORY("netns_teardown",
	              netns_teardown_runs,
	              netns_teardown_fields);

static const struct stat_field deep_path_nesting_fields[] = {
	STAT_FIELD(deep_path, runs),
	STAT_FIELD(deep_path, setup_failed),
	STAT_FIELD(deep_path, max_depth_reached),
	STAT_FIELD(deep_path, reader_ok),
	STAT_FIELD(deep_path, reader_failed),
};

const struct stat_category deep_path_nesting_category =
	STAT_CATEGORY("deep_path_nesting",
	              deep_path_runs,
	              deep_path_nesting_fields);

static const struct stat_field espintcp_coalesce_fields[] = {
	STAT_FIELD(espintcp_coalesce, runs),
	STAT_FIELD(espintcp_coalesce, setup_failed),
	STAT_FIELD(espintcp_coalesce, ulp_install_ok),
	STAT_FIELD(espintcp_coalesce, ulp_install_failed),
	STAT_FIELD(espintcp_coalesce, send_ok),
	STAT_FIELD(espintcp_coalesce, keepalive_ok),
};

const struct stat_category espintcp_coalesce_category =
	STAT_CATEGORY("espintcp_coalesce_churn",
	              espintcp_coalesce_runs,
	              espintcp_coalesce_fields);

static const struct stat_field netns_mountns_setup_fields[] = {
	STAT_FIELD(netns_mountns_setup, runs),
	STAT_FIELD(netns_mountns_setup, setup_failed),
	STAT_FIELD(netns_mountns_setup, unshare_ok),
	STAT_FIELD(netns_mountns_setup, mount_private_ok),
	STAT_FIELD(netns_mountns_setup, loopback_ok),
	STAT_FIELD(netns_mountns_setup, socket_ok),
	STAT_FIELD(netns_mountns_setup, completed_ok),
};

const struct stat_category netns_mountns_setup_category =
	STAT_CATEGORY("netns_mountns_setup",
	              netns_mountns_setup_runs,
	              netns_mountns_setup_fields);

static const struct stat_field setsockopt_pairing_fields[] = {
	STAT_FIELD(setsockopt_pairing, paired_emitted),
};

const struct stat_category setsockopt_pairing_category =
	STAT_CATEGORY("setsockopt_pairing",
	              setsockopt_pairing_paired_emitted,
	              setsockopt_pairing_fields);

static const struct stat_field sched_cycler_fields[] = {
	STAT_FIELD(sched_cycler, runs),
	STAT_FIELD(sched_cycler, eperm),
};

const struct stat_category sched_cycler_category =
	STAT_CATEGORY("sched_cycler",
	              sched_cycler_runs,
	              sched_cycler_fields);

static const struct stat_field userns_fuzzer_fields[] = {
	STAT_FIELD(userns, runs),
	STAT_FIELD(userns, inner_crashed),
	STAT_FIELD(userns, unsupported),
};

const struct stat_category userns_fuzzer_category =
	STAT_CATEGORY("userns_fuzzer",
	              userns_runs,
	              userns_fuzzer_fields);

static const struct stat_field userns_bootstrap_fields[] = {
	STAT_FIELD(userns_bootstrap, runs),
	STAT_FIELD(userns_bootstrap, ran),
	STAT_FIELD(userns_bootstrap, eperm),
	STAT_FIELD(userns_bootstrap, userns_other),
	STAT_FIELD(userns_bootstrap, map_write_fail),
	STAT_FIELD(userns_bootstrap, map_write_fail_eperm),
	STAT_FIELD(userns_bootstrap, map_write_fail_einval),
	STAT_FIELD(userns_bootstrap, map_write_fail_other),
	STAT_FIELD(userns_bootstrap, target_unshare),
	STAT_FIELD(userns_bootstrap, fork_fail),
	STAT_FIELD(userns_bootstrap, signalled),
};

const struct stat_category userns_bootstrap_category =
	STAT_CATEGORY("userns_bootstrap",
	              userns_bootstrap_runs,
	              userns_bootstrap_fields);

static const struct stat_field barrier_racer_fields[] = {
	STAT_FIELD(barrier_racer, runs),
	STAT_FIELD(barrier_racer, inner_crashed),
};

const struct stat_category barrier_racer_category =
	STAT_CATEGORY("barrier_racer",
	              barrier_racer_runs,
	              barrier_racer_fields);

static const struct stat_field perf_event_chains_fields[] = {
	STAT_FIELD(perf_chains, runs),
	STAT_FIELD(perf_chains, groups_created),
	STAT_FIELD(perf_chains, ioctl_ops),
};

const struct stat_category perf_event_chains_category =
	STAT_CATEGORY("perf_event_chains",
	              perf_chains_runs,
	              perf_event_chains_fields);

static const struct stat_field bpf_lifecycle_fields[] = {
	STAT_FIELD(bpf_lifecycle, runs),
	STAT_FIELD(bpf_lifecycle, progs_loaded),
	STAT_FIELD(bpf_lifecycle, attached),
	STAT_FIELD(bpf_lifecycle, triggered),
	STAT_FIELD(bpf_lifecycle, verifier_rejects),
	STAT_FIELD(bpf_lifecycle, attach_failed),
	STAT_FIELD(bpf_lifecycle, eperm),
};

const struct stat_category bpf_lifecycle_category =
	STAT_CATEGORY("bpf_lifecycle",
	              bpf_lifecycle_runs,
	              bpf_lifecycle_fields);

static const struct stat_field signal_storm_fields[] = {
	STAT_FIELD(signal_storm, runs),
	STAT_FIELD(signal_storm, kill),
	STAT_FIELD(signal_storm, probe),
	STAT_FIELD(signal_storm, sigqueue),
	STAT_FIELD(signal_storm, no_targets),
};

const struct stat_category signal_storm_category =
	STAT_CATEGORY("signal_storm",
	              signal_storm_runs,
	              signal_storm_fields);

static const struct stat_field socket_family_chain_fields[] = {
	STAT_FIELD(socket_family_chain, runs),
	STAT_FIELD(socket_family_chain, completed),
	STAT_FIELD(socket_family_chain, failed),
	STAT_FIELD(socket_family_chain, authencesn_attempts),
	STAT_FIELD(socket_family_chain, splice_attempts),
};

const struct stat_category socket_family_chain_category =
	STAT_CATEGORY("socket_family_chain",
	              socket_family_chain_runs,
	              socket_family_chain_fields);

static const struct stat_field socket_family_grammar_fields[] = {
	STAT_FIELD(socket_family_grammar, runs),
	STAT_FIELD(socket_family_grammar, completed),
	STAT_FIELD(socket_family_grammar, distinct_seq),
	STAT_FIELD(socket_family_grammar, reward),
	STAT_FIELD(socket_family_grammar, feedback_picks),
};

const struct stat_category socket_family_grammar_category =
	STAT_CATEGORY("socket_family_grammar",
	              socket_family_grammar_runs,
	              socket_family_grammar_fields);

static const struct stat_field tcp_ao_rotate_fields[] = {
	STAT_FIELD(tcp_ao_rotate, runs),
	STAT_FIELD(tcp_ao_rotate, setup_failed),
	STAT_FIELD(tcp_ao_rotate, addkey_rejected),
	STAT_FIELD(tcp_ao_rotate, keys_added),
	STAT_FIELD(tcp_ao_rotate, connect_failed),
	STAT_FIELD(tcp_ao_rotate, connected),
	STAT_FIELD(tcp_ao_rotate, packets_sent),
	STAT_FIELD(tcp_ao_rotate, key_rotations),
	STAT_FIELD(tcp_ao_rotate, info_rejected),
	STAT_FIELD(tcp_ao_rotate, key_dels),
	STAT_FIELD(tcp_ao_rotate, delkey_rejected),
	STAT_FIELD(tcp_ao_rotate, cycles),
};

const struct stat_category tcp_ao_rotate_category =
	STAT_CATEGORY("tcp_ao_rotate",
	              tcp_ao_rotate_runs,
	              tcp_ao_rotate_fields);

static const struct stat_field tcp_md5_listener_race_fields[] = {
	STAT_FIELD(tcp_md5_listener_race, runs),
	STAT_FIELD(tcp_md5_listener_race, setup_failed),
	STAT_FIELD(tcp_md5_listener_race, md5_set_ok),
	STAT_FIELD(tcp_md5_listener_race, md5_set_failed),
	STAT_FIELD(tcp_md5_listener_race, connect_ok),
	STAT_FIELD(tcp_md5_listener_race, rst_sent_ok),
	STAT_FIELD(tcp_md5_listener_race, completed_ok),
};

const struct stat_category tcp_md5_listener_race_category =
	STAT_CATEGORY("tcp_md5_listener_race",
	              tcp_md5_listener_race_runs,
	              tcp_md5_listener_race_fields);

static const struct stat_field ipv6_pmtu_race_fields[] = {
	STAT_FIELD(ipv6_pmtu_race, runs),
	STAT_FIELD(ipv6_pmtu_race, setup_failed),
	STAT_FIELD(ipv6_pmtu_race, ptb_sent_ok),
	STAT_FIELD(ipv6_pmtu_race, dellink_ok),
	STAT_FIELD(ipv6_pmtu_race, completed_ok),
};

const struct stat_category ipv6_pmtu_race_category =
	STAT_CATEGORY("ipv6_pmtu_race",
	              ipv6_pmtu_race_runs,
	              ipv6_pmtu_race_fields);

static const struct stat_field vrf_fib_churn_fields[] = {
	STAT_FIELD(vrf_fib_churn, runs),
	STAT_FIELD(vrf_fib_churn, setup_failed),
	STAT_FIELD(vrf_fib_churn, link_ok),
	STAT_FIELD(vrf_fib_churn, addr_ok),
	STAT_FIELD(vrf_fib_churn, up_ok),
	STAT_FIELD(vrf_fib_churn, rule_added),
	STAT_FIELD(vrf_fib_churn, bound),
	STAT_FIELD(vrf_fib_churn, sendto_ok),
	STAT_FIELD(vrf_fib_churn, rule2_added),
	STAT_FIELD(vrf_fib_churn, rule_removed),
	STAT_FIELD(vrf_fib_churn, link_removed),
};

const struct stat_category vrf_fib_churn_category =
	STAT_CATEGORY("vrf_fib_churn",
	              vrf_fib_churn_runs,
	              vrf_fib_churn_fields);

static const struct stat_field ip6_udp_cork_splice_fields[] = {
	STAT_FIELD(ip6_udp_cork_splice, runs),
	STAT_FIELD(ip6_udp_cork_splice, setup_failed),
	STAT_FIELD(ip6_udp_cork_splice, mtu_set),
	STAT_FIELD(ip6_udp_cork_splice, p1_ok),
	STAT_FIELD(ip6_udp_cork_splice, p1_rejected),
	STAT_FIELD(ip6_udp_cork_splice, p2_ok),
};

const struct stat_category ip6_udp_cork_splice_category =
	STAT_CATEGORY("ip6_udp_cork_splice",
	              ip6_udp_cork_splice_runs,
	              ip6_udp_cork_splice_fields);

static const struct stat_field mpls_route_churn_fields[] = {
	STAT_FIELD(mpls_route_churn, runs),
	STAT_FIELD(mpls_route_churn, label_install_ok),
	STAT_FIELD(mpls_route_churn, iptunnel_install_ok),
	STAT_FIELD(mpls_route_churn, delete_ok),
	STAT_FIELD(mpls_route_churn, ns_unsupported),
};

const struct stat_category mpls_route_churn_category =
	STAT_CATEGORY("mpls_route_churn",
	              mpls_route_churn_runs,
	              mpls_route_churn_fields);

static const struct stat_field tls_ulp_churn_fields[] = {
	STAT_FIELD(tls_ulp_churn, runs),
	STAT_FIELD(tls_ulp_churn, setup_failed),
	STAT_FIELD(tls_ulp_churn, ulp_install_ok),
	STAT_FIELD(tls_ulp_churn, tx_install_ok),
	STAT_FIELD(tls_ulp_churn, send_ok),
	STAT_FIELD(tls_ulp_churn, splice_ok),
	STAT_FIELD(tls_ulp_churn, rekey_ok),
	STAT_FIELD(tls_ulp_churn, recv_ok),
};

const struct stat_category tls_ulp_churn_category =
	STAT_CATEGORY("tls_ulp_churn",
	              tls_ulp_churn_runs,
	              tls_ulp_churn_fields);

static const struct stat_field ip6gre_bond_lapb_stack_fields[] = {
	STAT_FIELD(ip6gre_lapb, runs),
	STAT_FIELD(ip6gre_lapb, setup_failed),
	STAT_FIELD(ip6gre_lapb, flag_toggles),
};

const struct stat_category ip6gre_bond_lapb_stack_category =
	STAT_CATEGORY("ip6gre_bond_lapb_stack",
	              ip6gre_lapb_runs,
	              ip6gre_bond_lapb_stack_fields);

static const struct stat_field vxlan_encap_churn_fields[] = {
	STAT_FIELD(vxlan_encap_churn, runs),
	STAT_FIELD(vxlan_encap_churn, setup_failed),
	STAT_FIELD(vxlan_encap_churn, link_create_ok),
	STAT_FIELD(vxlan_encap_churn, fdb_add_ok),
	STAT_FIELD(vxlan_encap_churn, link_up_ok),
	STAT_FIELD(vxlan_encap_churn, packet_sent_ok),
	STAT_FIELD(vxlan_encap_churn, link_del_ok),
};

const struct stat_category vxlan_encap_churn_category =
	STAT_CATEGORY("vxlan_encap_churn",
	              vxlan_encap_churn_runs,
	              vxlan_encap_churn_fields);

static const struct stat_field ip_gre_churn_fields[] = {
	STAT_FIELD(ip_gre_churn, runs),
	STAT_FIELD(ip_gre_churn, setup_failed),
	STAT_FIELD(ip_gre_churn, link_create_ok),
	STAT_FIELD(ip_gre_churn, link_up_ok),
	STAT_FIELD(ip_gre_churn, packet_sent_ok),
	STAT_FIELD(ip_gre_churn, link_del_ok),
};

const struct stat_category ip_gre_churn_category =
	STAT_CATEGORY("ip_gre_churn",
	              ip_gre_churn_runs,
	              ip_gre_churn_fields);

static const struct stat_field ovs_tunnel_vport_churn_fields[] = {
	STAT_FIELD(ovs_tunnel_vport_churn, runs),
	STAT_FIELD(ovs_tunnel_vport_churn, setup_failed),
	STAT_FIELD(ovs_tunnel_vport_churn, create_ok),
	STAT_FIELD(ovs_tunnel_vport_churn, delete_ok),
	STAT_FIELD(ovs_tunnel_vport_churn, race_dellink_attempted),
};

const struct stat_category ovs_tunnel_vport_churn_category =
	STAT_CATEGORY("ovs_tunnel_vport_churn",
	              ovs_tunnel_vport_churn_runs,
	              ovs_tunnel_vport_churn_fields);

static const struct stat_field netlink_monitor_race_fields[] = {
	STAT_FIELD(netlink_monitor_race, runs),
	STAT_FIELD(netlink_monitor_race, setup_failed),
	STAT_FIELD(netlink_monitor_race, mon_open),
	STAT_FIELD(netlink_monitor_race, mut_open),
	STAT_FIELD(netlink_monitor_race, mut_op_ok),
	STAT_FIELD(netlink_monitor_race, recv_drained),
	STAT_FIELD(netlink_monitor_race, group_drop),
	STAT_FIELD(netlink_monitor_race, group_add),
};

const struct stat_category netlink_monitor_race_category =
	STAT_CATEGORY("netlink_monitor_race",
	              netlink_monitor_race_runs,
	              netlink_monitor_race_fields);

static const struct stat_field tipc_link_churn_fields[] = {
	STAT_FIELD(tipc_link_churn, runs),
	STAT_FIELD(tipc_link_churn, setup_failed),
	STAT_FIELD(tipc_link_churn, bearer_enable_ok),
	STAT_FIELD(tipc_link_churn, sock_rdm_ok),
	STAT_FIELD(tipc_link_churn, topsrv_connect_ok),
	STAT_FIELD(tipc_link_churn, sub_ports_sent),
	STAT_FIELD(tipc_link_churn, publish_ok),
	STAT_FIELD(tipc_link_churn, bearer_disable_ok),
};

const struct stat_category tipc_link_churn_category =
	STAT_CATEGORY("tipc_link_churn",
	              tipc_link_churn_runs,
	              tipc_link_churn_fields);

static const struct stat_field igmp_mld_source_churn_fields[] = {
	STAT_FIELD(igmp_mld_source_churn, runs),
	STAT_FIELD(igmp_mld_source_churn, setup_failed),
	STAT_FIELD(igmp_mld_source_churn, join_ok),
	STAT_FIELD(igmp_mld_source_churn, leave_ok),
	STAT_FIELD(igmp_mld_source_churn, block_ok),
	STAT_FIELD(igmp_mld_source_churn, msfilter_ok),
	STAT_FIELD(igmp_mld_source_churn, drop_ok),
	STAT_FIELD(igmp_mld_source_churn, send_ok),
};

const struct stat_category igmp_mld_source_churn_category =
	STAT_CATEGORY("igmp_mld_source_churn",
	              igmp_mld_source_churn_runs,
	              igmp_mld_source_churn_fields);

static const struct stat_field bridge_vlan_churn_fields[] = {
	STAT_FIELD(bridge_vlan_churn, runs),
	STAT_FIELD(bridge_vlan_churn, setup_failed),
	STAT_FIELD(bridge_vlan_churn, bridge_create_ok),
	STAT_FIELD(bridge_vlan_churn, veth_create_ok),
	STAT_FIELD(bridge_vlan_churn, vlan_add_ok),
	STAT_FIELD(bridge_vlan_churn, vlan_del_ok),
	STAT_FIELD(bridge_vlan_churn, tunnel_add_ok),
	STAT_FIELD(bridge_vlan_churn, mst_set_ok),
	STAT_FIELD(bridge_vlan_churn, raw_send_ok),
};

const struct stat_category bridge_vlan_churn_category =
	STAT_CATEGORY("bridge_vlan_churn",
	              bridge_vlan_churn_runs,
	              bridge_vlan_churn_fields);

static const struct stat_field pkt_builder_fields[] = {
	STAT_FIELD(pkt_builder, runs),
	STAT_FIELD(pkt_builder, setup_failed),
	STAT_FIELD(pkt_builder, built_ok),
	STAT_FIELD(pkt_builder, build_failed),
	STAT_FIELD(pkt_builder, mutated),
	STAT_FIELD(pkt_builder, truncated),
	STAT_FIELD(pkt_builder, delivered_ok),
	STAT_FIELD(pkt_builder, delivery_failed),
	STAT_FIELD(pkt_builder, delivery_disabled),
	{ .name = "recipe_vxlan_eth_ip4",
	  .offset = offsetof(struct stats_s, pkt_builder_per_recipe[0]) },
	{ .name = "recipe_gretap_eth_ip4",
	  .offset = offsetof(struct stats_s, pkt_builder_per_recipe[1]) },
	{ .name = "recipe_raw_ip4_gretap_ip4",
	  .offset = offsetof(struct stats_s, pkt_builder_per_recipe[2]) },
	{ .name = "recipe_qinq_ip4",
	  .offset = offsetof(struct stats_s, pkt_builder_per_recipe[3]) },
	{ .name = "recipe_geneve_v6_eth_ip6",
	  .offset = offsetof(struct stats_s, pkt_builder_per_recipe[4]) },
	{ .name = "recipe_mpls_ip4",
	  .offset = offsetof(struct stats_s, pkt_builder_per_recipe[5]) },
};

const struct stat_category pkt_builder_category =
	STAT_CATEGORY("pkt_builder",
	              pkt_builder_runs,
	              pkt_builder_fields);

static const struct stat_field vlan_filter_churn_fields[] = {
	STAT_FIELD(vlan_filter_churn, runs),
	STAT_FIELD(vlan_filter_churn, setup_failed),
	STAT_FIELD(vlan_filter_churn, veth_create_ok),
	STAT_FIELD(vlan_filter_churn, vlan_add_ok),
	STAT_FIELD(vlan_filter_churn, vlan_del_ok),
};

const struct stat_category vlan_filter_churn_category =
	STAT_CATEGORY("vlan_filter_churn",
	              vlan_filter_churn_runs,
	              vlan_filter_churn_fields);

static const struct stat_field iscsi_target_probe_fields[] = {
	STAT_FIELD(iscsi_target_probe, runs),
	STAT_FIELD(iscsi_target_probe, setup_failed),
	STAT_FIELD(iscsi_target_probe, no_target),
	STAT_FIELD(iscsi_target_probe, connected),
	STAT_FIELD(iscsi_target_probe, login_sent),
	STAT_FIELD(iscsi_target_probe, login_replies),
	STAT_FIELD(iscsi_target_probe, scsi_cmd_sent),
	STAT_FIELD(iscsi_target_probe, bytes_out),
	STAT_FIELD(iscsi_target_probe, bytes_in),
	STAT_FIELD(iscsi_target_probe, length_decoupled),
};

const struct stat_category iscsi_target_probe_category =
	STAT_CATEGORY("iscsi_target_probe",
	              iscsi_target_probe_runs,
	              iscsi_target_probe_fields);

static const struct stat_field iscsi_login_walker_fields[] = {
	STAT_FIELD(iscsi_walker, runs),
	STAT_FIELD(iscsi_walker, setup_failed),
	STAT_FIELD(iscsi_walker, no_target),
	STAT_FIELD(iscsi_walker, connected),
	STAT_FIELD(iscsi_walker, state_init_sent),
	STAT_FIELD(iscsi_walker, state_security_sent),
	STAT_FIELD(iscsi_walker, state_op_neg_sent),
	STAT_FIELD(iscsi_walker, ffp_iters),
	STAT_FIELD(iscsi_walker, ffp_pdus),
	STAT_FIELD(iscsi_walker, chaos_runs),
	STAT_FIELD(iscsi_walker, chaos_pdus),
	STAT_FIELD(iscsi_walker, bytes_out),
	STAT_FIELD(iscsi_walker, bytes_in),
};

const struct stat_category iscsi_login_walker_category =
	STAT_CATEGORY("iscsi_login_walker",
	              iscsi_walker_runs,
	              iscsi_login_walker_fields);

static const struct stat_field ipv6_ndisc_proxy_fields[] = {
	STAT_FIELD(ipv6_ndisc_proxy, runs),
	STAT_FIELD(ipv6_ndisc_proxy, ns_sent_ok),
	STAT_FIELD(ipv6_ndisc_proxy, setup_failed),
	STAT_FIELD(ipv6_ndisc_proxy, proxy_enable_ok),
};

const struct stat_category ipv6_ndisc_proxy_category =
	STAT_CATEGORY("ipv6_ndisc_proxy",
	              ipv6_ndisc_proxy_runs,
	              ipv6_ndisc_proxy_fields);

static const struct stat_field rxrpc_key_install_fields[] = {
	STAT_FIELD(rxrpc_key_install, runs),
	STAT_FIELD(rxrpc_key_install, calls),
	STAT_FIELD(rxrpc_key_install, revokes),
	STAT_FIELD(rxrpc_key_install, quota_hits),
	STAT_FIELD(rxrpc_key_install, unsupported),
	STAT_FIELD(rxrpc_key_install, xrxgk_accepted),
};

const struct stat_category rxrpc_key_install_category =
	STAT_CATEGORY("rxrpc_key_install",
	              rxrpc_key_install_runs,
	              rxrpc_key_install_fields);

static const struct stat_field af_alg_weak_cipher_probe_fields[] = {
	STAT_FIELD(af_alg_weak_cipher_probe, runs),
	STAT_FIELD(af_alg_weak_cipher_probe, socket_failed),
	STAT_FIELD(af_alg_weak_cipher_probe, total_bind_attempts),
	STAT_FIELD(af_alg_weak_cipher_probe, total_bind_accepted),
	STAT_FIELD(af_alg_weak_cipher_probe, weak_accepted_total),
	STAT_FIELD(af_alg_weak_cipher_probe, setkey_accepted_total),
	STAT_FIELD(af_alg_weak_cipher_probe, skcipher_weak_accepted),
	STAT_FIELD(af_alg_weak_cipher_probe, aead_weak_accepted),
	STAT_FIELD(af_alg_weak_cipher_probe, hash_weak_accepted),
	STAT_FIELD(af_alg_weak_cipher_probe, strong_rejected),
};

const struct stat_category af_alg_weak_cipher_probe_category =
	STAT_CATEGORY("af_alg_weak_cipher_probe",
	              af_alg_weak_cipher_probe_runs,
	              af_alg_weak_cipher_probe_fields);

static const struct stat_field bridge_conntrack_churn_fields[] = {
	STAT_FIELD(bridge_ct, runs),
	STAT_FIELD(bridge_ct, flushes),
	STAT_FIELD(bridge_ct, pkts_sent),
};

const struct stat_category bridge_conntrack_churn_category =
	STAT_CATEGORY("bridge_conntrack_churn",
	              bridge_ct_runs,
	              bridge_conntrack_churn_fields);

static const struct stat_field blkdev_lifecycle_race_fields[] = {
	STAT_FIELD(blkdev_lifecycle, runs),
	STAT_FIELD(blkdev_lifecycle, setup_failed),
	STAT_FIELD(blkdev_lifecycle, set_fd_ok),
	STAT_FIELD(blkdev_lifecycle, clr_fd),
	STAT_FIELD(blkdev_lifecycle, ebusy),
	STAT_FIELD(blkdev_lifecycle, rescans),
};

const struct stat_category blkdev_lifecycle_race_category =
	STAT_CATEGORY("blkdev_lifecycle_race",
	              blkdev_lifecycle_runs,
	              blkdev_lifecycle_race_fields);

static const struct stat_field veth_asymmetric_xdp_fields[] = {
	STAT_FIELD(veth_asym, iters),
	STAT_FIELD(veth_asym, eperm),
	STAT_FIELD(veth_asym, unsupported),
	STAT_FIELD(veth_asym, pair_ok),
	STAT_FIELD(veth_asym, xdp_attach_ok),
	STAT_FIELD(veth_asym, send_ok),
};

const struct stat_category veth_asymmetric_xdp_category =
	STAT_CATEGORY("veth_asymmetric_xdp",
	              veth_asym_iters,
	              veth_asymmetric_xdp_fields);

static const struct stat_field ip6erspan_netns_migrate_fields[] = {
	STAT_FIELD(inm, iters),
	STAT_FIELD(inm, eperm),
	STAT_FIELD(inm, unsupported),
	STAT_FIELD(inm, link_create_ok),
	STAT_FIELD(inm, netns_migrate_ok),
	STAT_FIELD(inm, changelink_ok),
	STAT_FIELD(inm, ip6erspan_unsupported_observed),
	STAT_FIELD(inm, changelink_unsupported_observed),
};

const struct stat_category ip6erspan_netns_migrate_category =
	STAT_CATEGORY("ip6erspan_netns_migrate",
	              inm_iters,
	              ip6erspan_netns_migrate_fields);

static const struct stat_field flowtable_encap_vlan_fields[] = {
	STAT_FIELD(flowtable_vlan, runs),
	STAT_FIELD(flowtable_vlan, setup_ok),
	STAT_FIELD(flowtable_vlan, setup_failed),
	STAT_FIELD(flowtable_vlan, offloaded_pkts),
	STAT_FIELD(flowtable_vlan, gso_sends),
	STAT_FIELD(flowtable_vlan, vlan_teardown_races),
	STAT_FIELD(flowtable_vlan, unsupported_latched),
};

const struct stat_category flowtable_encap_vlan_category =
	STAT_CATEGORY("flowtable_encap_vlan",
	              flowtable_vlan_runs,
	              flowtable_encap_vlan_fields);

static const struct stat_field splice_protocols_fields[] = {
	STAT_FIELD(splice_protocols, runs),
	STAT_FIELD(splice_protocols, setup_failed),
	STAT_FIELD(splice_protocols, chain_ok),
	STAT_FIELD(splice_protocols, in_bytes),
	STAT_FIELD(splice_protocols, out_bytes),
	STAT_FIELD(splice_protocols, udp_encap_attempted),
	STAT_FIELD(splice_protocols, tcp_repair_attempted),
	STAT_FIELD(splice_protocols, packet_ring_attempted),
	STAT_FIELD(splice_protocols, alg_attempted),
	STAT_FIELD(splice_protocols, rxrpc_attempted),
	STAT_FIELD(splice_protocols, msg_splice_pages_attempted),
	STAT_FIELD(splice_protocols, msg_splice_pages_path_taken_inferred),
};

const struct stat_category splice_protocols_category =
	STAT_CATEGORY("splice_protocols",
	              splice_protocols_runs,
	              splice_protocols_fields);

static const struct stat_field wireguard_decrypt_flood_fields[] = {
	STAT_FIELD(wgdf, runs),
	STAT_FIELD(wgdf, setup_failed),
	STAT_FIELD(wgdf, packets_sent),
	STAT_FIELD(wgdf, unsupported_latched),
};

const struct stat_category wireguard_decrypt_flood_category =
	STAT_CATEGORY("wireguard_decrypt_flood",
	              wgdf_runs,
	              wireguard_decrypt_flood_fields);

static const struct stat_field rtnl_vf_broadcast_getlink_fields[] = {
	STAT_FIELD(rtnl_vf_broadcast, runs),
	STAT_FIELD(rtnl_vf_broadcast, setup_ok),
	STAT_FIELD(rtnl_vf_broadcast, setup_failed),
	STAT_FIELD(rtnl_vf_broadcast, getlink_ok),
};

const struct stat_category rtnl_vf_broadcast_getlink_category =
	STAT_CATEGORY("rtnl_vf_broadcast_getlink",
	              rtnl_vf_broadcast_runs,
	              rtnl_vf_broadcast_getlink_fields);

static const struct stat_field pci_bind_fields[] = {
	STAT_FIELD(pci_bind, runs),
	STAT_FIELD(pci_bind, drivers_available),
	STAT_FIELD(pci_bind, no_devices),
	STAT_FIELD(pci_bind, unbind_ok),
	STAT_FIELD(pci_bind, unbind_enodev),
	STAT_FIELD(pci_bind, unbind_failed),
	STAT_FIELD(pci_bind, bind_ok),
	STAT_FIELD(pci_bind, bind_enodev),
	STAT_FIELD(pci_bind, bind_failed),
};

const struct stat_category pci_bind_category =
	STAT_CATEGORY("pci_bind",
	              pci_bind_runs,
	              pci_bind_fields);

static const struct stat_field ublk_lifecycle_fields[] = {
	STAT_FIELD(ublk_lifecycle, iters),
	STAT_FIELD(ublk_lifecycle, eperm),
	STAT_FIELD(ublk_lifecycle, add_ok),
	STAT_FIELD(ublk_lifecycle, fetch_ok),
	STAT_FIELD(ublk_lifecycle, del_ok),
	STAT_FIELD(ublk_lifecycle, race_observed),
};

const struct stat_category ublk_lifecycle_category =
	STAT_CATEGORY("ublk_lifecycle",
	              ublk_lifecycle_iters,
	              ublk_lifecycle_fields);

static const struct stat_field handshake_req_abort_fields[] = {
	STAT_FIELD(handshake_req_abort, runs),
	STAT_FIELD(handshake_req_abort, setup_failed),
	STAT_FIELD(handshake_req_abort, accept_ok),
	STAT_FIELD(handshake_req_abort, done_ok),
	STAT_FIELD(handshake_req_abort, abort_ok),
	STAT_FIELD(handshake_req_abort, orphan_close),
};

const struct stat_category handshake_req_abort_category =
	STAT_CATEGORY("handshake_req_abort",
	              handshake_req_abort_runs,
	              handshake_req_abort_fields);

static const struct stat_field nf_conntrack_helper_churn_fields[] = {
	STAT_FIELD(nf_conntrack_helper_churn, runs),
	STAT_FIELD(nf_conntrack_helper_churn, setup_failed),
	STAT_FIELD(nf_conntrack_helper_churn, no_helper),
	STAT_FIELD(nf_conntrack_helper_churn, attach_ok),
	STAT_FIELD(nf_conntrack_helper_churn, attach_fail),
	STAT_FIELD(nf_conntrack_helper_churn, exp_ok),
	STAT_FIELD(nf_conntrack_helper_churn, packet_sent),
	STAT_FIELD(nf_conntrack_helper_churn, delete_ok),
	STAT_FIELD(nf_conntrack_helper_churn, zone_swap),
	STAT_FIELD(nf_conntrack_helper_churn, detach_ok),
};

const struct stat_category nf_conntrack_helper_churn_category =
	STAT_CATEGORY("nf_conntrack_helper_churn",
	              nf_conntrack_helper_churn_runs,
	              nf_conntrack_helper_churn_fields);

static const struct stat_field af_unix_scm_rights_gc_fields[] = {
	STAT_FIELD(af_unix_scm_rights_gc, runs),
	STAT_FIELD(af_unix_scm_rights_gc, setup_failed),
	STAT_FIELD(af_unix_scm_rights_gc, cycle_built_ok),
	STAT_FIELD(af_unix_scm_rights_gc, close_ok),
	STAT_FIELD(af_unix_scm_rights_gc, trigger_ok),
	STAT_FIELD(af_unix_scm_rights_gc, recv_ok),
	STAT_FIELD(af_unix_scm_rights_gc, peek_ok),
	STAT_FIELD(af_unix_scm_rights_gc, iouring_variant_ok),
	STAT_FIELD(af_unix_scm_rights_gc, sibling_spawn_ok),
	STAT_FIELD(af_unix_scm_rights_gc, sibling_spawn_failed),
	STAT_FIELD(af_unix_scm_rights_gc, sibling_reaped_ok),
	STAT_FIELD(af_unix_scm_rights_gc, sibling_crashed),
};

const struct stat_category af_unix_scm_rights_gc_category =
	STAT_CATEGORY("af_unix_scm_rights_gc",
	              af_unix_scm_rights_gc_runs,
	              af_unix_scm_rights_gc_fields);

static const struct stat_field af_unix_peek_race_fields[] = {
	STAT_FIELD(af_unix_peek_race, runs),
	STAT_FIELD(af_unix_peek_race, setup_failed),
	STAT_FIELD(af_unix_peek_race, pair_open_ok),
	STAT_FIELD(af_unix_peek_race, peek_off_armed),
	STAT_FIELD(af_unix_peek_race, peek_off_rejected),
	STAT_FIELD(af_unix_peek_race, send_ok),
	STAT_FIELD(af_unix_peek_race, shutdown_ok),
	STAT_FIELD(af_unix_peek_race, pair_rebuilds),
	STAT_FIELD(af_unix_peek_race, sibling_spawn_ok),
	STAT_FIELD(af_unix_peek_race, sibling_spawn_failed),
	STAT_FIELD(af_unix_peek_race, sibling_reaped_ok),
	STAT_FIELD(af_unix_peek_race, sibling_crashed),
};

const struct stat_category af_unix_peek_race_category =
	STAT_CATEGORY("af_unix_peek_race",
		af_unix_peek_race_runs,
		af_unix_peek_race_fields);

static const struct stat_field sysv_shm_orphan_race_fields[] = {
	STAT_FIELD(sysv_shm_orphan_race, runs),
	STAT_FIELD(sysv_shm_orphan_race, setup_failed),
	STAT_FIELD(sysv_shm_orphan_race, shmget_ok),
	STAT_FIELD(sysv_shm_orphan_race, shmget_failed),
	STAT_FIELD(sysv_shm_orphan_race, attach_ok),
	STAT_FIELD(sysv_shm_orphan_race, attach_failed),
	STAT_FIELD(sysv_shm_orphan_race, rmid_ok),
	STAT_FIELD(sysv_shm_orphan_race, rmid_failed),
	STAT_FIELD(sysv_shm_orphan_race, sibling_spawn_ok),
	STAT_FIELD(sysv_shm_orphan_race, sibling_spawn_failed),
	STAT_FIELD(sysv_shm_orphan_race, sibling_reaped_ok),
	STAT_FIELD(sysv_shm_orphan_race, sibling_crashed),
};

const struct stat_category sysv_shm_orphan_race_category =
	STAT_CATEGORY("sysv_shm_orphan_race",
		sysv_shm_orphan_race_runs,
		sysv_shm_orphan_race_fields);

static const struct stat_field qrtr_bind_race_fields[] = {
	STAT_FIELD(qrtr_bind_race, runs),
	STAT_FIELD(qrtr_bind_race, setup_failed),
	STAT_FIELD(qrtr_bind_race, iter),
	STAT_FIELD(qrtr_bind_race, fork_failed),
	STAT_FIELD(qrtr_bind_race, spawn_pair_ok),
	STAT_FIELD(qrtr_bind_race, sibling_reaped_ok),
	STAT_FIELD(qrtr_bind_race, sibling_crashed),
	STAT_FIELD(qrtr_bind, setup_fail),
};

const struct stat_category qrtr_bind_race_category =
	STAT_CATEGORY("qrtr_bind_race",
		qrtr_bind_race_runs,
		qrtr_bind_race_fields);

static const struct stat_field pfkey_spd_walk_fields[] = {
	STAT_FIELD(pfkey_spd_walk, runs),
	STAT_FIELD(pfkey_spd_walk, setup_failed),
	STAT_FIELD(pfkey_spd_walk, iter),
	STAT_FIELD(pfkey_spd_walk, fork_failed),
	STAT_FIELD(pfkey_spd_walk, spawn_pair_ok),
	STAT_FIELD(pfkey_spd_walk, sibling_reaped_ok),
	STAT_FIELD(pfkey_spd_walk, sibling_crashed),
	STAT_FIELD(pfkey, spdget_resolved),
	STAT_FIELD(pfkey, spdget_missed),
};

const struct stat_category pfkey_spd_walk_category =
	STAT_CATEGORY("pfkey_spd_walk",
		pfkey_spd_walk_runs,
		pfkey_spd_walk_fields);

static const struct stat_field l2tp_ifname_race_fields[] = {
	STAT_FIELD(l2tp_ifname_race, runs),
	STAT_FIELD(l2tp_ifname_race, setup_failed),
	STAT_FIELD(l2tp_ifname_race, iter),
	STAT_FIELD(l2tp_ifname_race, tunnel_ok),
	STAT_FIELD(l2tp_ifname_race, tunnel_fail),
	STAT_FIELD(l2tp_ifname_race, fork_failed),
	STAT_FIELD(l2tp_ifname_race, spawn_pair_ok),
	STAT_FIELD(l2tp_ifname_race, sibling_reaped_ok),
	STAT_FIELD(l2tp_ifname_race, sibling_crashed),
};

const struct stat_category l2tp_ifname_race_category =
	STAT_CATEGORY("l2tp_ifname_race",
		l2tp_ifname_race_runs,
		l2tp_ifname_race_fields);

static const struct stat_field bpf_cgroup_attach_fields[] = {
	STAT_FIELD(bpf_cgroup_attach, runs),
	STAT_FIELD(bpf_cgroup_attach, setup_failed),
	STAT_FIELD(bpf_cgroup_attach, prog_loaded),
	STAT_FIELD(bpf_cgroup_attach, attached),
	STAT_FIELD(bpf_cgroup_attach, attach_rejected),
	STAT_FIELD(bpf_cgroup_attach, packets_sent),
	STAT_FIELD(bpf_cgroup_attach, detached),
	STAT_FIELD(bpf_cgroup_attach, post_detach_sent),
};

const struct stat_category bpf_cgroup_attach_category =
	STAT_CATEGORY("bpf_cgroup_attach",
	              bpf_cgroup_attach_runs,
	              bpf_cgroup_attach_fields);

static const struct stat_field pipe_thrash_fields[] = {
	STAT_FIELD(pipe_thrash, runs),
	STAT_FIELD(pipe_thrash, pipes),
	STAT_FIELD(pipe_thrash, socketpairs),
	STAT_FIELD(pipe_thrash, alloc_failed),
};

const struct stat_category pipe_thrash_category =
	STAT_CATEGORY("pipe_thrash",
	              pipe_thrash_runs,
	              pipe_thrash_fields);

static const struct stat_field fork_storm_fields[] = {
	STAT_FIELD(fork_storm, runs),
	STAT_FIELD(fork_storm, forks),
	STAT_FIELD(fork_storm, failed),
	STAT_FIELD(fork_storm, nested),
	STAT_FIELD(fork_storm, reaped_signal),
};

const struct stat_category fork_storm_category =
	STAT_CATEGORY("fork_storm",
	              fork_storm_runs,
	              fork_storm_fields);

static const struct stat_field cpu_hotplug_rider_fields[] = {
	STAT_FIELD(cpu_hotplug, runs),
	STAT_FIELD(cpu_hotplug, affinity_calls),
	STAT_FIELD(cpu_hotplug, sysfs_writes),
	STAT_FIELD(cpu_hotplug, open_eperm),
	STAT_FIELD(cpu_hotplug, write_eperm),
	STAT_FIELD(cpu_hotplug, write_ok),
	STAT_FIELD(cpu_hotplug, actual_offlines),
};

const struct stat_category cpu_hotplug_rider_category =
	STAT_CATEGORY("cpu_hotplug_rider",
	              cpu_hotplug_runs,
	              cpu_hotplug_rider_fields);

static const struct stat_field pidfd_storm_fields[] = {
	STAT_FIELD(pidfd_storm, runs),
	STAT_FIELD(pidfd_storm, signals),
	STAT_FIELD(pidfd_storm, getfds),
	STAT_FIELD(pidfd_storm, failed),
	STAT_FIELD(pidfd_storm, iters),
	STAT_FIELD(pidfd_storm, reap_slow),
	STAT_FIELD(pidfd_storm, reap_zombies),
};

const struct stat_category pidfd_storm_category =
	STAT_CATEGORY("pidfd_storm",
	              pidfd_storm_runs,
	              pidfd_storm_fields);

static const struct stat_field madvise_cycler_fields[] = {
	STAT_FIELD(madvise_cycler, runs),
	STAT_FIELD(madvise_cycler, calls),
	STAT_FIELD(madvise_cycler, failed),
};

const struct stat_category madvise_cycler_category =
	STAT_CATEGORY("madvise_cycler",
	              madvise_cycler_runs,
	              madvise_cycler_fields);

static const struct stat_field keyring_spam_fields[] = {
	STAT_FIELD(keyring_spam, runs),
	STAT_FIELD(keyring_spam, calls),
	STAT_FIELD(keyring_spam, failed),
};

const struct stat_category keyring_spam_category =
	STAT_CATEGORY("keyring_spam",
	              keyring_spam_runs,
	              keyring_spam_fields);

static const struct stat_field vdso_mremap_race_fields[] = {
	STAT_FIELD(vdso_race, runs),
	STAT_FIELD(vdso_race, mutations),
	STAT_FIELD(vdso_race, helper_segvs),
};

const struct stat_category vdso_mremap_race_category =
	STAT_CATEGORY("vdso_mremap_race",
	              vdso_race_runs,
	              vdso_mremap_race_fields);

static const struct stat_field flock_thrash_fields[] = {
	STAT_FIELD(flock_thrash, runs),
	STAT_FIELD(flock_thrash, locks),
	STAT_FIELD(flock_thrash, failed),
};

const struct stat_category flock_thrash_category =
	STAT_CATEGORY("flock_thrash",
	              flock_thrash_runs,
	              flock_thrash_fields);

static const struct stat_field xattr_thrash_fields[] = {
	STAT_FIELD(xattr_thrash, runs),
	STAT_FIELD(xattr_thrash, set),
	STAT_FIELD(xattr_thrash, get),
	STAT_FIELD(xattr_thrash, remove),
	STAT_FIELD(xattr_thrash, list),
	STAT_FIELD(xattr_thrash, failed),
};

const struct stat_category xattr_thrash_category =
	STAT_CATEGORY("xattr_thrash",
	              xattr_thrash_runs,
	              xattr_thrash_fields);

static const struct stat_field epoll_volatility_fields[] = {
	STAT_FIELD(epoll_volatility, runs),
	STAT_FIELD(epoll_volatility, ctl_calls),
	STAT_FIELD(epoll_volatility, failed),
};

const struct stat_category epoll_volatility_category =
	STAT_CATEGORY("epoll_volatility",
	              epoll_volatility_runs,
	              epoll_volatility_fields);

static const struct stat_field cgroup_churn_fields[] = {
	STAT_FIELD(cgroup_churn, runs),
	STAT_FIELD(cgroup, mkdirs),
	STAT_FIELD(cgroup, rmdirs),
	STAT_FIELD(cgroup, failed),
	STAT_FIELD(cgroup, psi_race_runs),
	STAT_FIELD(cgroup, psi_race_writes),
	STAT_FIELD(cgroup, psi_race_failed),
};

const struct stat_category cgroup_churn_category =
	STAT_CATEGORY("cgroup_churn",
	              cgroup_churn_runs,
	              cgroup_churn_fields);

static const struct stat_field mount_churn_fields[] = {
	STAT_FIELD(mount_churn, runs),
	STAT_FIELD(mount_churn, mounts),
	STAT_FIELD(mount_churn, umounts),
	STAT_FIELD(mount_churn, failed),
};

const struct stat_category mount_churn_category =
	STAT_CATEGORY("mount_churn",
	              mount_churn_runs,
	              mount_churn_fields);

static const struct stat_field umount_race_fields[] = {
	STAT_FIELD(umount_race, runs),
	STAT_FIELD(umount_race, picks),
	STAT_FIELD(umount_race, forks),
	STAT_FIELD(umount_race, umounts),
	STAT_FIELD(umount_race, umount_failed),
	STAT_FIELD(umount_race, setup_failed),
};

const struct stat_category umount_race_category =
	STAT_CATEGORY("umount_race",
	              umount_race_runs,
	              umount_race_fields);

static const struct stat_field statmount_idmap_fields[] = {
	STAT_FIELD(statmount_idmap, runs),
	STAT_FIELD(statmount_idmap, setup_failed),
	STAT_FIELD(statmount_idmap, iter),
	STAT_FIELD(statmount_idmap, fork_failed),
	STAT_FIELD(statmount_idmap, carrier_ok),
	STAT_FIELD(statmount_idmap, carrier_fail),
	STAT_FIELD(statmount_idmap, setattr_ok),
	STAT_FIELD(statmount_idmap, setattr_fail),
	STAT_FIELD(statmount_idmap, statmount_call),
	STAT_FIELD(statmount_idmap, statmount_ok),
	STAT_FIELD(statmount_idmap, statmount_overflow),
};

const struct stat_category statmount_idmap_category =
	STAT_CATEGORY("statmount_idmap",
	              statmount_idmap_runs,
	              statmount_idmap_fields);

static const struct stat_field uffd_churn_fields[] = {
	STAT_FIELD(uffd, runs),
	STAT_FIELD(uffd, registers),
	STAT_FIELD(uffd, unregisters),
	STAT_FIELD(uffd, failed),
};

const struct stat_category uffd_churn_category =
	STAT_CATEGORY("uffd_churn",
	              uffd_runs,
	              uffd_churn_fields);

static const struct stat_field iouring_flood_fields[] = {
	STAT_FIELD(iouring, runs),
	STAT_FIELD(iouring, submits),
	STAT_FIELD(iouring, reaped),
	STAT_FIELD(iouring, failed),
};

const struct stat_category iouring_flood_category =
	STAT_CATEGORY("iouring_flood",
	              iouring_runs,
	              iouring_flood_fields);

static const struct stat_field iouring_send_zc_churn_fields[] = {
	STAT_FIELD(iouring_send_zc_churn, runs),
	STAT_FIELD(iouring_send_zc_churn, setup_failed),
	STAT_FIELD(iouring_send_zc_churn, register_bufs_ok),
	STAT_FIELD(iouring_send_zc_churn, send_zc_ok),
	STAT_FIELD(iouring_send_zc_churn, sendmsg_zc_ok),
	STAT_FIELD(iouring_send_zc_churn, unregister_race_ok),
	STAT_FIELD(iouring_send_zc_churn, update_race_ok),
	STAT_FIELD(iouring_send_zc_churn, cqe_drained),
};

const struct stat_category iouring_send_zc_churn_category =
	STAT_CATEGORY("iouring_send_zc_churn",
	              iouring_send_zc_churn_runs,
	              iouring_send_zc_churn_fields);

static const struct stat_field close_racer_fields[] = {
	STAT_FIELD(close_racer, runs),
	STAT_FIELD(close_racer, pairs),
	STAT_FIELD(close_racer, failed),
	STAT_FIELD(close_racer, thread_spawn_fail),
};

const struct stat_category close_racer_category =
	STAT_CATEGORY("close_racer",
	              close_racer_runs,
	              close_racer_fields);

static const struct stat_field refcount_audit_fields[] = {
	STAT_FIELD(refcount_audit, runs),
	STAT_FIELD(refcount_audit, fd_anomalies),
	STAT_FIELD(refcount_audit, mmap_anomalies),
	STAT_FIELD(refcount_audit, sock_anomalies),
};

const struct stat_category refcount_audit_category =
	STAT_CATEGORY("refcount_audit",
	              refcount_audit_runs,
	              refcount_audit_fields);

/*
 * Descriptors for dump_stats_json_lifecycle_and_storms().  The JSON walker
 * ignores gate_offset (it emits every category unconditionally) so the gate
 * field here only matters if a future change wires stat_category_emit_text()
 * onto these tables; the current text dump for these two categories stays
 * hand-coded in dump_stats_childop_runs_local().
 */
static const struct stat_field fs_lifecycle_fields[] = {
	STAT_FIELD(fs_lifecycle, tmpfs),
	STAT_FIELD(fs_lifecycle, ramfs),
	STAT_FIELD(fs_lifecycle, rdonly),
	STAT_FIELD(fs_lifecycle, overlay),
	STAT_FIELD(fs_lifecycle, quota),
	STAT_FIELD(fs_lifecycle, bind),
	STAT_FIELD(fs_lifecycle, unsupported),
};

const struct stat_category fs_lifecycle_category =
	STAT_CATEGORY("fs_lifecycle",
	              fs_lifecycle_tmpfs,
	              fs_lifecycle_fields);

static const struct stat_field futex_storm_fields[] = {
	STAT_FIELD(futex_storm, runs),
	STAT_FIELD(futex_storm, inner_crashed),
	STAT_FIELD(futex_storm, iters),
};

const struct stat_category futex_storm_category =
	STAT_CATEGORY("futex_storm",
	              futex_storm_runs,
	              futex_storm_fields);

static const struct stat_field futex_pi_requeue_rollback_fields[] = {
	STAT_FIELD(futex_pi_requeue_rollback, runs),
	STAT_FIELD(futex_pi_requeue_rollback, setup_failed),
	STAT_FIELD(futex_pi_requeue_rollback, requeue_ok),
	STAT_FIELD(futex_pi_requeue_rollback, requeue_failed),
};

const struct stat_category futex_pi_requeue_rollback_category =
	STAT_CATEGORY("futex_pi_requeue_rollback",
	              futex_pi_requeue_rollback_runs,
	              futex_pi_requeue_rollback_fields);

/*
 * Descriptors for dump_stats_json_oracle().  Every member is named
 * <syscall>_oracle_anomalies in struct stats_s but the JSON schema emits it
 * as "<syscall>_anomalies" (the "oracle_" infix is implicit in the enclosing
 * category key), so each row uses STAT_FIELD_JSON to pin the cross-prefix
 * JSON key.  The JSON walker ignores stat_category.gate_offset (it emits
 * every category unconditionally) and the text dump for oracle stays
 * hand-coded in dump_stats_oracle_anomalies() where each row has its own
 * per-field gate, so fd_oracle_anomalies here is a placeholder gate that
 * matters only if a future change wires stat_category_emit_text() onto this
 * table.
 */
static const struct stat_field oracle_fields[] = {
	STAT_FIELD_JSON(fd_oracle, anomalies, "fd_anomalies"),
	STAT_FIELD_JSON(mmap_oracle, anomalies, "mmap_anomalies"),
	STAT_FIELD_JSON(cred_oracle, anomalies, "cred_anomalies"),
	STAT_FIELD_JSON(sched_oracle, anomalies, "sched_anomalies"),
	STAT_FIELD_JSON(uid_oracle, anomalies, "uid_anomalies"),
	STAT_FIELD_JSON(gid_oracle, anomalies, "gid_anomalies"),
	STAT_FIELD_JSON(setgroups_oracle, anomalies, "setgroups_anomalies"),
	STAT_FIELD_JSON(getegid_oracle, anomalies, "getegid_anomalies"),
	STAT_FIELD_JSON(getuid_oracle, anomalies, "getuid_anomalies"),
	STAT_FIELD_JSON(getgid_oracle, anomalies, "getgid_anomalies"),
	STAT_FIELD_JSON(getppid_oracle, anomalies, "getppid_anomalies"),
	STAT_FIELD_JSON(getcwd_oracle, anomalies, "getcwd_anomalies"),
	STAT_FIELD_JSON(getpid_oracle, anomalies, "getpid_anomalies"),
	STAT_FIELD_JSON(getpgid_oracle, anomalies, "getpgid_anomalies"),
	STAT_FIELD_JSON(getpgrp_oracle, anomalies, "getpgrp_anomalies"),
	STAT_FIELD_JSON(geteuid_oracle, anomalies, "geteuid_anomalies"),
	STAT_FIELD_JSON(getsid_oracle, anomalies, "getsid_anomalies"),
	STAT_FIELD_JSON(gettid_oracle, anomalies, "gettid_anomalies"),
	STAT_FIELD_JSON(setsid_oracle, anomalies, "setsid_anomalies"),
	STAT_FIELD_JSON(setpgid_oracle, anomalies, "setpgid_anomalies"),
	STAT_FIELD_JSON(sched_getscheduler_oracle, anomalies, "sched_getscheduler_anomalies"),
	STAT_FIELD_JSON(getgroups_oracle, anomalies, "getgroups_anomalies"),
	STAT_FIELD_JSON(getresuid_oracle, anomalies, "getresuid_anomalies"),
	STAT_FIELD_JSON(getresgid_oracle, anomalies, "getresgid_anomalies"),
	STAT_FIELD_JSON(umask_oracle, anomalies, "umask_anomalies"),
	STAT_FIELD_JSON(sched_get_priority_max_oracle, anomalies, "sched_get_priority_max_anomalies"),
	STAT_FIELD_JSON(sched_get_priority_min_oracle, anomalies, "sched_get_priority_min_anomalies"),
	STAT_FIELD_JSON(sched_yield_oracle, anomalies, "sched_yield_anomalies"),
	STAT_FIELD_JSON(getpagesize_oracle, anomalies, "getpagesize_anomalies"),
	STAT_FIELD_JSON(time_oracle, anomalies, "time_anomalies"),
	STAT_FIELD_JSON(gettimeofday_oracle, anomalies, "gettimeofday_anomalies"),
	STAT_FIELD_JSON(newuname_oracle, anomalies, "newuname_anomalies"),
	STAT_FIELD_JSON(rt_sigpending_oracle, anomalies, "rt_sigpending_anomalies"),
	STAT_FIELD_JSON(sched_getaffinity_oracle, anomalies, "sched_getaffinity_anomalies"),
	STAT_FIELD_JSON(rt_sigprocmask_oracle, anomalies, "rt_sigprocmask_anomalies"),
	STAT_FIELD_JSON(sched_getparam_oracle, anomalies, "sched_getparam_anomalies"),
	STAT_FIELD_JSON(sched_rr_get_interval_oracle, anomalies, "sched_rr_get_interval_anomalies"),
	STAT_FIELD_JSON(get_robust_list_oracle, anomalies, "get_robust_list_anomalies"),
	STAT_FIELD_JSON(getrlimit_oracle, anomalies, "getrlimit_anomalies"),
	STAT_FIELD_JSON(sysinfo_oracle, anomalies, "sysinfo_anomalies"),
	STAT_FIELD_JSON(times_oracle, anomalies, "times_anomalies"),
	STAT_FIELD_JSON(clock_getres_oracle, anomalies, "clock_getres_anomalies"),
	STAT_FIELD_JSON(capget_oracle, anomalies, "capget_anomalies"),
	STAT_FIELD_JSON(capdrop_oracle, anomalies, "capdrop_anomalies"),
	STAT_FIELD_JSON(newlstat_oracle, anomalies, "newlstat_anomalies"),
	STAT_FIELD_JSON(newstat_oracle, anomalies, "newstat_anomalies"),
	STAT_FIELD_JSON(newfstat_oracle, anomalies, "newfstat_anomalies"),
	STAT_FIELD_JSON(newfstatat_oracle, anomalies, "newfstatat_anomalies"),
	STAT_FIELD_JSON(statx_oracle, anomalies, "statx_anomalies"),
	STAT_FIELD_JSON(fstatfs_oracle, anomalies, "fstatfs_anomalies"),
	STAT_FIELD_JSON(fstatfs64_oracle, anomalies, "fstatfs64_anomalies"),
	STAT_FIELD_JSON(statfs_oracle, anomalies, "statfs_anomalies"),
	STAT_FIELD_JSON(statfs64_oracle, anomalies, "statfs64_anomalies"),
	STAT_FIELD_JSON(uname_oracle, anomalies, "uname_anomalies"),
	STAT_FIELD_JSON(lsm_list_modules_oracle, anomalies, "lsm_list_modules_anomalies"),
	STAT_FIELD_JSON(listmount_oracle, anomalies, "listmount_anomalies"),
	STAT_FIELD_JSON(statmount_oracle, anomalies, "statmount_anomalies"),
	STAT_FIELD_JSON(getsockname_oracle, anomalies, "getsockname_anomalies"),
	STAT_FIELD_JSON(getpeername_oracle, anomalies, "getpeername_anomalies"),
	STAT_FIELD_JSON(file_getattr_oracle, anomalies, "file_getattr_anomalies"),
	STAT_FIELD_JSON(sched_getattr_oracle, anomalies, "sched_getattr_anomalies"),
	STAT_FIELD_JSON(getrusage_oracle, anomalies, "getrusage_anomalies"),
	STAT_FIELD_JSON(sigpending_oracle, anomalies, "sigpending_anomalies"),
	STAT_FIELD_JSON(getcpu_oracle, anomalies, "getcpu_anomalies"),
	STAT_FIELD_JSON(clock_gettime_oracle, anomalies, "clock_gettime_anomalies"),
	STAT_FIELD_JSON(get_mempolicy_oracle, anomalies, "get_mempolicy_anomalies"),
	STAT_FIELD_JSON(lsm_get_self_attr_oracle, anomalies, "lsm_get_self_attr_anomalies"),
	STAT_FIELD_JSON(prlimit64_oracle, anomalies, "prlimit64_anomalies"),
	STAT_FIELD_JSON(sigaltstack_oracle, anomalies, "sigaltstack_anomalies"),
	STAT_FIELD_JSON(olduname_oracle, anomalies, "olduname_anomalies"),
	STAT_FIELD_JSON(lookup_dcookie_oracle, anomalies, "lookup_dcookie_anomalies"),
	STAT_FIELD_JSON(getxattr_oracle, anomalies, "getxattr_anomalies"),
	STAT_FIELD_JSON(lgetxattr_oracle, anomalies, "lgetxattr_anomalies"),
	STAT_FIELD_JSON(fgetxattr_oracle, anomalies, "fgetxattr_anomalies"),
	STAT_FIELD_JSON(listxattrat_oracle, anomalies, "listxattrat_anomalies"),
	STAT_FIELD_JSON(flistxattr_oracle, anomalies, "flistxattr_anomalies"),
	STAT_FIELD_JSON(listxattr_oracle, anomalies, "listxattr_anomalies"),
	STAT_FIELD_JSON(llistxattr_oracle, anomalies, "llistxattr_anomalies"),
	STAT_FIELD_JSON(readlink_oracle, anomalies, "readlink_anomalies"),
	STAT_FIELD_JSON(readlinkat_oracle, anomalies, "readlinkat_anomalies"),
	STAT_FIELD_JSON(sysfs_oracle, anomalies, "sysfs_anomalies"),
};

const struct stat_category oracle_category =
	STAT_CATEGORY("oracle",
	              fd_oracle_anomalies,
	              oracle_fields);

/*
 * Descriptor tables staged for the follow-up JSON fan-out (per-fn conversions
 * of dump_stats_json_iouring_and_zombies / _socket_family_and_tls /
 * _iouring_zc_and_kvm / _netfilter_and_xfrm / _fault_and_fd_lifecycle).
 *
 * The category JSON key in each case doesn't match the struct member's
 * single prefix, so STAT_FIELD() rows pick whichever prefix matches the
 * actual struct member (packet_fanout_*, recipe_*, nat_t_churn_/nat_t_,
 * kvm_run_/kvm_, fd_/local_fd_/epoll_); .name doubles as the text-side
 * key.  For fd_lifecycle's three cross-prefix members (local_fd_* and
 * epoll_*) the suffix alone wouldn't yield the schema's JSON key, so
 * STAT_FIELD_JSON() pins the JSON key explicitly.
 *
 * As with the fs_lifecycle/futex_storm pair above, the JSON walker
 * ignores stat_category.gate_offset; the gate field is set to the same
 * counter the existing text emitter uses (or a placeholder for
 * fd_lifecycle, which has no single gate) so a future text-side wiring
 * has a sensible default.  These tables have no live caller yet -- they
 * land here so the per-fn JSON conversions can be reviewed in isolation.
 */
static const struct stat_field packet_fanout_thrash_fields[] = {
	STAT_FIELD(packet_fanout, runs),
	STAT_FIELD(packet_fanout, setup_failed),
	STAT_FIELD(packet_fanout, ring_failed),
	STAT_FIELD(packet_fanout, rings_installed),
	STAT_FIELD(packet_fanout, mmap_failed),
	STAT_FIELD(packet_fanout, joins),
	STAT_FIELD(packet_fanout, rejoins_ok),
	STAT_FIELD(packet_fanout, rejoins_rejected),
};

static const struct stat_category packet_fanout_thrash_category
	__attribute__((unused)) =
	STAT_CATEGORY("packet_fanout_thrash",
	              packet_fanout_runs,
	              packet_fanout_thrash_fields);

static const struct stat_field recipe_runner_fields[] = {
	STAT_FIELD(recipe, runs),
	STAT_FIELD(recipe, completed),
	STAT_FIELD(recipe, partial),
	STAT_FIELD(recipe, unsupported),
};

const struct stat_category recipe_runner_category =
	STAT_CATEGORY("recipe_runner",
	              recipe_runs,
	              recipe_runner_fields);

/*
 * Descriptors for the remaining categories in
 * dump_stats_json_iouring_and_zombies().  The text-side dump for these stays
 * hand-coded for now, and the JSON walker ignores gate_offset, so the gate
 * field choices below only matter if a future change wires
 * stat_category_emit_text() onto these tables.
 */
static const struct stat_field iouring_recipes_fields[] = {
	STAT_FIELD(iouring_recipes, runs),
	STAT_FIELD(iouring_recipes, completed),
	STAT_FIELD(iouring_recipes, partial),
	STAT_FIELD(iouring_recipes, enosys),
};

const struct stat_category iouring_recipes_category =
	STAT_CATEGORY("iouring_recipes",
	              iouring_recipes_runs,
	              iouring_recipes_fields);

static const struct stat_field iouring_eventfd_fields[] = {
	STAT_FIELD(iouring_eventfd, register_ok),
	STAT_FIELD(iouring_eventfd, register_fail),
	STAT_FIELD(iouring_eventfd, recursive_runs),
	STAT_FIELD(iouring_eventfd, recursive_cqes),
};

const struct stat_category iouring_eventfd_category =
	STAT_CATEGORY("iouring_eventfd",
	              iouring_eventfd_register_ok,
	              iouring_eventfd_fields);

/* aio_submitted: iocbs the kernel accepted on io_submit's success branch
 * (retval > 0 and within [0, nr]).  A single-field category sits next to
 * its iouring siblings so a quiet success window is distinguishable from
 * a quiet rejection window in both JSON and text dumps. */
static const struct stat_field aio_fields[] = {
	STAT_FIELD(aio, submitted),
};

const struct stat_category aio_category =
	STAT_CATEGORY("aio",
	              aio_submitted,
	              aio_fields);

/* errno_gradient: SHADOW measurement of upward errno-class crossings (no
 * fuzzer-behaviour change -- see the errno_gradient_* block in
 * include/stats.h for the class axis and the SHADOW contract).  Aggregate
 * scalars only; the per-syscall last-class array is deliberately
 * unrendered (internal to the predicate, matching the other per-syscall
 * shadow arrays).  Text render gates on errno_gradient_crossings so a
 * run that never observed an upward transition emits nothing in the
 * text dump; JSON renders unconditionally for schema stability,
 * matching the aio sibling above. */
static const struct stat_field errno_gradient_fields[] = {
	STAT_FIELD(errno_gradient, crossings),
	STAT_FIELD(errno_gradient, to_permstate),
	STAT_FIELD(errno_gradient, to_success),
};

const struct stat_category errno_gradient_category =
	STAT_CATEGORY("errno_gradient",
	              errno_gradient_crossings,
	              errno_gradient_fields);

/* cold_overflow: SHADOW measurement of would-save events that fall on the
 * cold-or-corpus-absent tail under a CMP_RISING_PC_FLAT plateau (no
 * fuzzer-behaviour change -- see the cold_overflow_would_save_* block
 * in include/stats.h for the predicate and the SHADOW contract).
 * Aggregate scalars only.  Text render gates on cold_overflow_would_
 * save so a run that never observed a qualifying event emits nothing
 * in the text dump; JSON renders unconditionally for schema stability,
 * matching the errno_gradient sibling above. */
static const struct stat_field cold_overflow_fields[] = {
	STAT_FIELD(cold_overflow, would_save),
	STAT_FIELD(cold_overflow, would_save_cold),
	STAT_FIELD(cold_overflow, would_save_absent),
};

const struct stat_category cold_overflow_category =
	STAT_CATEGORY("cold_overflow",
	              cold_overflow_would_save,
	              cold_overflow_fields);

/* inplace_crypto_mutated: the inplace-crypto oracle childop overwrites a
 * plaintext slot mid-flight to catch handlers that read after the kernel
 * has copied; the per-mutation bump is the only positive signal that the
 * oracle ran productively in a window.  A single-field category renders
 * it in both JSON and text so a quiet "no mutations" window is
 * distinguishable from a window where the childop never fired. */
static const struct stat_field inplace_crypto_fields[] = {
	STAT_FIELD(inplace_crypto, mutated),
};

const struct stat_category inplace_crypto_category =
	STAT_CATEGORY("inplace_crypto",
	              inplace_crypto_mutated,
	              inplace_crypto_fields);

/* fd_runtime_skipped: handle_retval_obj_fd's post-success classify of an
 * fd retval against the per-child local-object table.  The two paths are
 * mutually exclusive per call and both increment from the same site, so a
 * run where neither bumped means no syscall ever produced a registerable
 * fd; gating on _stdio (the dominant arm — retvals 0/1/2 from any
 * fd-returning syscall) keeps a quiet window terse in the text dump.
 * JSON renders unconditionally alongside aio for schema stability. */
static const struct stat_field fd_runtime_skipped_fields[] = {
	STAT_FIELD(fd_runtime_skipped, stdio),
	STAT_FIELD(fd_runtime_skipped, already_registered),
};

const struct stat_category fd_runtime_skipped_category =
	STAT_CATEGORY("fd_runtime_skipped",
	              fd_runtime_skipped_stdio,
	              fd_runtime_skipped_fields);

/* child_dead_parent_observed: init_child()'s pid-handshake loop saw
 * pid_alive(mainpid) == false -- the parent died before publishing this
 * child's slot in pids[].  The original outputerr("BUG!: parent went
 * away!") was swallowed by the dup2 /dev/null redirect; a single-field
 * category surfaces the survivor signal in both dumps.  Text self-gates
 * so a healthy run emits nothing. */
static const struct stat_field child_fields[] = {
	STAT_FIELD(child, dead_parent_observed),
};

const struct stat_category child_category =
	STAT_CATEGORY("child",
	              child_dead_parent_observed,
	              child_fields);

/* parent_inherited_fds_closed: sanitize_inherited_fds() closed an fd
 * the parent inherited from its launcher (or the launcher's parent) at
 * startup.  Non-zero means the parent came in with stray fds beyond
 * {0,1,2}, which could otherwise wedge the reap-path epoll/poll loop.
 * A single-field category surfaces the cleanup count in both dumps;
 * text self-gates so a clean launch environment emits nothing. */
static const struct stat_field parent_fields[] = {
	STAT_FIELD(parent, inherited_fds_closed),
};

const struct stat_category parent_category =
	STAT_CATEGORY("parent",
	              parent_inherited_fds_closed,
	              parent_fields);

/* uid_change_logged: check_uid saw the child's uid drift away from
 * orig_uid + overflowuid.  Non-root drifts log-and-continue rather than
 * hard-bailing, so the drift count is the only positive signal that a
 * fuzzed setresuid/setreuid/setfsuid landed inside an unshared user
 * namespace.  A single-field category surfaces the count in both dumps;
 * text self-gates so a stable-uid run emits nothing. */
static const struct stat_field uid_change_fields[] = {
	STAT_FIELD(uid_change, logged),
};

const struct stat_category uid_change_category =
	STAT_CATEGORY("uid_change",
	              uid_change_logged,
	              uid_change_fields);

/* no_domains_runtime_skipped: socket families auto-marked in no_domains[]
 * at startup because socket() probes returned EAFNOSUPPORT/EPROTONOSUPPORT
 * for both SOCK_STREAM and SOCK_DGRAM.  Non-zero tells the operator how
 * many random-syscall socket() picks per cycle the running kernel can
 * never reach, and confirms the auto-skip ran (vs. --exclude-domains by
 * hand).  Text self-gates so a fully-supported build emits nothing. */
static const struct stat_field no_domains_fields[] = {
	STAT_FIELD(no_domains, runtime_skipped),
};

const struct stat_category no_domains_category =
	STAT_CATEGORY("no_domains",
	              no_domains_runtime_skipped,
	              no_domains_fields);

/* zombie_slots mixes two struct prefixes (zombie_slots_ for the gauge,
 * zombies_ for the counters); each STAT_FIELD picks its own prefix so the
 * JSON keys stay flat ("pending", "reaped", "timed_out"). */
static const struct stat_field zombie_slots_fields[] = {
	STAT_FIELD(zombie_slots, pending),
	STAT_FIELD(zombies, reaped),
	STAT_FIELD(zombies, timed_out),
};

const struct stat_category zombie_slots_category =
	STAT_CATEGORY("zombie_slots",
	              zombies_reaped,
	              zombie_slots_fields);

static const struct stat_field nat_t_churn_fields[] = {
	STAT_FIELD(nat_t_churn, runs),
	STAT_FIELD(nat_t_churn, setup_failed),
	STAT_FIELD(nat_t_churn, sa_added),
	STAT_FIELD(nat_t_churn, sa_deleted),
	STAT_FIELD(nat_t_churn, frames_sent),
	STAT_FIELD(nat_t, xfrm6_setup_ok),
	STAT_FIELD(nat_t, xfrm6_setup_fail),
	STAT_FIELD(nat_t, xfrm6_sendto_runs),
	STAT_FIELD(nat_t, xfrm6_delsa_races),
};

static const struct stat_category nat_t_churn_category
	__attribute__((unused)) =
	STAT_CATEGORY("nat_t_churn",
	              nat_t_churn_runs,
	              nat_t_churn_fields);

static const struct stat_field kvm_run_churn_fields[] = {
	STAT_FIELD(kvm_run, invocations),
	STAT_FIELD(kvm_run, exit_io),
	STAT_FIELD(kvm_run, exit_mmio),
	STAT_FIELD(kvm_run, exit_hlt),
	STAT_FIELD(kvm_run, exit_shutdown),
	STAT_FIELD(kvm_run, exit_fail_entry),
	STAT_FIELD(kvm_run, exit_internal_error),
	STAT_FIELD(kvm_run, exit_intr),
	STAT_FIELD(kvm_run, exit_other),
	STAT_FIELD(kvm_run, errors),
	STAT_FIELD(kvm, gpc_memslot_race_runs),
	STAT_FIELD(kvm, gpc_memslot_race_deletes),
	STAT_FIELD(kvm, gpc_memslot_race_unsupported),
};

static const struct stat_category kvm_run_churn_category
	__attribute__((unused)) =
	STAT_CATEGORY("kvm_run_churn",
	              kvm_run_invocations,
	              kvm_run_churn_fields);

static const struct stat_field fd_lifecycle_fields[] = {
	STAT_FIELD(fd, stale_detected),
	STAT_FIELD(fd, stale_by_generation),
	STAT_FIELD(fd, closed_tracked),
	STAT_FIELD(fd, duped),
	STAT_FIELD(fd, events_processed),
	STAT_FIELD(fd, events_dropped),
	STAT_FIELD(fd, event_close_count),
	STAT_FIELD(fd, event_evict_count),
	STAT_FIELD(fd, hash_reinsert_dropped),
	STAT_FIELD_JSON(local_fd, hash_insert_dropped,
	                "local_hash_insert_dropped"),
	STAT_FIELD(fd, runtime_registered),
	STAT_FIELD_JSON(epoll, lazy_armed, "epoll_lazy_armed"),
	STAT_FIELD_JSON(epoll, blocking_poll_skipped,
	                "epoll_blocking_poll_skipped"),
	STAT_FIELD(fd, random_exhausted),
	STAT_FIELD(fd, provider_invalid),
};

/* fd_lifecycle has no single gate counter -- the text emitter ORs many
 * fields.  Use fd_stale_detected as a placeholder for the JSON walker
 * (which ignores gate_offset); any text-side wiring will need to revisit. */
static const struct stat_category fd_lifecycle_category
	__attribute__((unused)) =
	STAT_CATEGORY("fd_lifecycle",
	              fd_stale_detected,
	              fd_lifecycle_fields);







static void dump_stats_runtime_header(void)
{
	time_t start = shm->start_time;
	uint64_t start_ns = shm->start_mono_ns;
	uint64_t now_ns = mono_ns();
	long elapsed = (start_ns != 0 && now_ns >= start_ns) ?
		(long)((now_ns - start_ns) / 1000000000ULL) : 0;
	struct tm tm;
	char ts[32];

	if (start > 0 && localtime_r(&start, &tm) != NULL &&
	    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm) > 0) {
		output(1, "runtime: %ldh%02ldm%02lds (since %s)\n",
		       elapsed / 3600,
		       (elapsed / 60) % 60,
		       elapsed % 60,
		       ts);
	}
}

static void dump_stats_per_syscall_tables(void)
{
	unsigned int i;

	if (biarch == true) {
		output(0, "32bit:\n");
		for_each_32bit_syscall(i) {
			dump_entry(syscalls_32bit, i);
		}
		output(0, "64bit:\n");
		for_each_64bit_syscall(i) {
			dump_entry(syscalls_64bit, i);
		}
	} else {
		for_each_syscall(i) {
			dump_entry(syscalls, i);
		}
	}

	stats_emit_header();
}

/*
 * SHADOW-ONLY shutdown attribution for the per-syscall stuck-child
 * accounting (see the comment on shm->stats.syscall_wedge_count[]
 * in include/stats.h).  Renders a
 * top-N row sorted by cumulative wedged microseconds, with the per-
 * syscall event count rendered alongside so the operator can
 * distinguish "one rare syscall that wedges for ages" from "many
 * short wedges in a hot syscall".  Read-only: no live-path decision
 * is taken from either array yet; this dump exists so the next
 * iteration has data to choose throttle / isolation targets from.
 *
 * Biarch table choice follows top_syscalls_periodic_dump() exactly --
 * only the 64-bit table is iterated under biarch because 32-bit nrs
 * collide with 64-bit ones in the same index space and would shadow
 * them in the display.  Empty-block gate: if no wedge has ever been
 * accounted (count_total == 0), the block is skipped entirely
 * rather than emit an all-zero header.
 */
#define WEDGE_TOPN	10

static void dump_stats_top_wedging_syscalls(void)
{
	struct wedge_top_entry {
		unsigned int nr;
		unsigned long count;
		unsigned long long total_us;
	} top[WEDGE_TOPN];
	unsigned int top_count = 0;
	unsigned long count_total = 0;
	unsigned long long us_total = 0;
	unsigned int nr_to_scan;
	bool is32bit;
	unsigned int i;
	int j;

	if (biarch) {
		nr_to_scan = max_nr_64bit_syscalls;
		is32bit = false;
	} else {
		nr_to_scan = max_nr_syscalls;
		is32bit = false;
	}
	if (nr_to_scan > MAX_NR_SYSCALL)
		nr_to_scan = MAX_NR_SYSCALL;

	for (i = 0; i < nr_to_scan; i++) {
		unsigned long c = __atomic_load_n(
			&shm->stats.syscall_wedge_count[i],
			__ATOMIC_RELAXED);
		unsigned long long u = __atomic_load_n(
			&shm->stats.syscall_wedge_total_us[i],
			__ATOMIC_RELAXED);

		if (c == 0 && u == 0)
			continue;

		count_total += c;
		us_total += u;

		/* Insertion sort, descending by total_us, capped at WEDGE_TOPN.
		 * Ties on total_us are broken by event count so a hot syscall
		 * with many quick wedges ranks above a single still-pending
		 * wedge whose duration matches by accident. */
		for (j = (int)top_count;
		     j > 0 && (u > top[j - 1].total_us ||
			       (u == top[j - 1].total_us &&
				c > top[j - 1].count));
		     j--) {
			if (j < WEDGE_TOPN)
				top[j] = top[j - 1];
		}
		if (j < WEDGE_TOPN) {
			top[j].nr = i;
			top[j].count = c;
			top[j].total_us = u;
			if (top_count < WEDGE_TOPN)
				top_count++;
		}
	}

	if (count_total == 0 && us_total == 0)
		return;

	output(0, "Top %u most-wedging syscalls (cumulative; %lu events, "
		"%llu.%03llu s wedged total):\n",
		top_count, count_total,
		us_total / 1000000ULL, (us_total / 1000ULL) % 1000ULL);

	for (j = 0; j < (int)top_count; j++) {
		const char *name = print_syscall_name(top[j].nr, is32bit);
		unsigned long long s = top[j].total_us / 1000000ULL;
		unsigned long long ms = (top[j].total_us / 1000ULL) % 1000ULL;
		unsigned long long avg_us = top[j].count > 0 ?
			(top[j].total_us / top[j].count) : 0;
		unsigned long long avg_s = avg_us / 1000000ULL;
		unsigned long long avg_ms = (avg_us / 1000ULL) % 1000ULL;

		output(0, "    %-24s events=%lu wedged=%llu.%03llus avg=%llu.%03llus\n",
			name, top[j].count, s, ms, avg_s, avg_ms);
	}
}

/*
 * Sister of dump_stats_top_wedging_syscalls() above, keyed by enum
 * child_op_type instead of syscall nr.  Wedging on this fleet is
 * dominated by long-lived non-syscall childops (flock_thrash,
 * futex_storm, memory_pressure, ...) whose inner sites cycle through
 * many syscalls; the per-syscall top-N attributes the wedge cost to
 * whichever syscall happened to be in flight at detection, which
 * mis-names the dominant wedgers.  This block surfaces them by the
 * childop that was running when the stall began.
 *
 * Shares the same duration definition as the per-syscall block --
 * full unreusable-slot time (watchdog grace included), CLOCK_MONOTONIC,
 * clamped >= 0 at the accumulator site (see reap_child() in main.c) --
 * so the per-syscall total and the per-childop total over the run are
 * the same number; the two top-N rows just slice it differently.
 *
 * Empty-block gate: skipped entirely if no wedge has ever been
 * accounted on this axis, so a clean run emits nothing.
 */
static void dump_stats_top_wedging_childops(void)
{
	struct childop_wedge_top_entry {
		unsigned int op;
		unsigned long count;
		unsigned long long total_us;
	} top[WEDGE_TOPN];
	unsigned int top_count = 0;
	unsigned long count_total = 0;
	unsigned long long us_total = 0;
	unsigned int i;
	int j;

	for (i = 0; i < NR_CHILD_OP_TYPES; i++) {
		unsigned long c = __atomic_load_n(
			&shm->stats.childop_wedge_count[i],
			__ATOMIC_RELAXED);
		unsigned long long u = __atomic_load_n(
			&shm->stats.childop_wedge_total_us[i],
			__ATOMIC_RELAXED);

		if (c == 0 && u == 0)
			continue;

		count_total += c;
		us_total += u;

		/* Insertion sort, descending by total_us, capped at
		 * WEDGE_TOPN.  Ties on total_us broken by event count so a
		 * hot childop with many quick wedges ranks above a single
		 * still-pending wedge whose duration matches by accident. */
		for (j = (int)top_count;
		     j > 0 && (u > top[j - 1].total_us ||
			       (u == top[j - 1].total_us &&
				c > top[j - 1].count));
		     j--) {
			if (j < WEDGE_TOPN)
				top[j] = top[j - 1];
		}
		if (j < WEDGE_TOPN) {
			top[j].op = i;
			top[j].count = c;
			top[j].total_us = u;
			if (top_count < WEDGE_TOPN)
				top_count++;
		}
	}

	if (count_total == 0 && us_total == 0)
		return;

	output(0, "Top %u most-wedging childops (cumulative; %lu events, "
		"%llu.%03llu s wedged total):\n",
		top_count, count_total,
		us_total / 1000000ULL, (us_total / 1000ULL) % 1000ULL);

	for (j = 0; j < (int)top_count; j++) {
		const char *name = alt_op_name(
			(enum child_op_type) top[j].op);
		unsigned long long s = top[j].total_us / 1000000ULL;
		unsigned long long ms = (top[j].total_us / 1000ULL) % 1000ULL;
		unsigned long long avg_us = top[j].count > 0 ?
			(top[j].total_us / top[j].count) : 0;
		unsigned long long avg_s = avg_us / 1000000ULL;
		unsigned long long avg_ms = (avg_us / 1000ULL) % 1000ULL;

		output(0, "    %-32s events=%lu wedged=%llu.%03llus avg=%llu.%03llus\n",
			name ? name : "?", top[j].count, s, ms, avg_s, avg_ms);
	}
}

static void dump_fd_lifecycle(void)
{
	if (shm->stats.fd_stale_detected || shm->stats.fd_closed_tracked ||
	    shm->stats.fd_stale_by_generation ||
	    shm->stats.fd_duped || shm->stats.fd_events_processed ||
	    shm->stats.fd_hash_reinsert_dropped ||
	    shm->stats.local_fd_hash_insert_dropped ||
	    shm->stats.epoll_lazy_armed ||
	    shm->stats.epoll_blocking_poll_skipped ||
	    shm->stats.fd_random_exhausted ||
	    shm->stats.fd_provider_invalid) {
		stat_row("fd_lifecycle", "stale_detected",      shm->stats.fd_stale_detected);
		stat_row("fd_lifecycle", "stale_by_generation", shm->stats.fd_stale_by_generation);
		stat_row("fd_lifecycle", "closed_tracked",      shm->stats.fd_closed_tracked);
		stat_row("fd_lifecycle", "duped",               shm->stats.fd_duped);
		stat_row("fd_lifecycle", "events_processed",    shm->stats.fd_events_processed);
		stat_row("fd_lifecycle", "events_dropped",      shm->stats.fd_events_dropped);
		stat_row("fd_lifecycle", "event_close_count",   shm->stats.fd_event_close_count);
		stat_row("fd_lifecycle", "event_evict_count",   shm->stats.fd_event_evict_count);
		stat_row("fd_lifecycle", "hash_reinsert_dropped", shm->stats.fd_hash_reinsert_dropped);
		stat_row("fd_lifecycle", "local_hash_insert_dropped",
			 shm->stats.local_fd_hash_insert_dropped);
		stat_row("fd_lifecycle", "epoll_lazy_armed",    shm->stats.epoll_lazy_armed);
		stat_row("fd_lifecycle", "epoll_blocking_poll_skipped",
			 shm->stats.epoll_blocking_poll_skipped);
		stat_row("fd_lifecycle", "random_exhausted",    shm->stats.fd_random_exhausted);
		stat_row("fd_lifecycle", "provider_invalid",    shm->stats.fd_provider_invalid);
	}
}

/*
 * Per-provider outstanding-fd gauge.  Only providers whose live
 * count is non-zero get a row -- a clean run with no leaks emits
 * nothing; a non-empty block at shutdown surfaces a per-provider
 * fd leak (CLOSE events lost in the fd_event ring, an OBJ_GLOBAL
 * registration whose subsequent close() bypassed remove_object_by_fd,
 * etc.).  The label comes from the registered fd_provider name so
 * the row matches --enable-fds/--disable-fds syntax; an entry whose
 * objtype has no matching provider is skipped (defensive: should
 * not happen, since the bump site fires only on a successful
 * fd_hash_insert for an is_fd_type() objtype).
 */
static void dump_fd_provider_outstanding(void)
{
	unsigned int t;

	for (t = 0; t < MAX_OBJECT_TYPES; t++) {
		unsigned long outstanding =
			shm->stats.fd_provider_outstanding[t];
		const char *name;

		if (outstanding == 0)
			continue;

		name = fd_provider_name((enum objecttype) t);
		if (name == NULL)
			continue;

		stat_row("fd_provider_outstanding", name, outstanding);
	}
}

static void dump_stats_fd_tracking(void)
{
	if (parent_stats.fault_injected) {
		stat_row("fault_injection", "armed_fail_nth",  parent_stats.fault_injected);
		stat_row("fault_injection", "returned_enomem", parent_stats.fault_consumed);
	}

	dump_fd_lifecycle();

	dump_fd_provider_outstanding();

	/* Producer-side capture count for the typed-scalar bypass push.
	 * Sibling to kcov_shm->propagation_injected (consumer-side); see
	 * the field comment in include/stats.h.  Lives next to the
	 * fd_runtime_* family because its capture site is the same
	 * register_returned_fd dispatch -- the OBJ_KEY_SERIAL branch
	 * mirrors the value into prop_ring after handing it to the typed
	 * registrar. */
	if (shm->stats.propagation_injected_key_scalar) {
		stat_row("propagation", "injected_key_scalar",
			 shm->stats.propagation_injected_key_scalar);
	}
}


static void dump_stats_shared_buffer_misc(void)
{
	if (parent_stats.shared_buffer_redirected)
		stat_row("shared_buffer", "args_redirected",     parent_stats.shared_buffer_redirected);
	if (parent_stats.libc_heap_redirected)
		stat_row("shared_buffer", "libc_heap_redirected", parent_stats.libc_heap_redirected);
	if (parent_stats.libc_heap_embedded_redirected)
		stat_row("shared_buffer", "libc_heap_embedded_redirected",
			 parent_stats.libc_heap_embedded_redirected);
	if (parent_stats.asb_relocate_readable_skip)
		stat_row("shared_buffer", "asb_relocate_readable_skip",
			 parent_stats.asb_relocate_readable_skip);
	if (parent_stats.asb_relocate_copy_fault)
		stat_row("shared_buffer", "asb_relocate_copy_fault",
			 parent_stats.asb_relocate_copy_fault);
	if (parent_stats.heap_pointer_outside_cache)
		stat_row("shared_buffer", "heap_pointer_outside_cache",
			 parent_stats.heap_pointer_outside_cache);
	if (parent_stats.heap_brk_stale_window_hit)
		stat_row("shared_buffer", "heap_brk_stale_window_hit",
			 parent_stats.heap_brk_stale_window_hit);
	if (parent_stats.range_overlaps_shared_rejects) {
		stat_row("shared_buffer", "range_overlaps_shared_rejects",
			 parent_stats.range_overlaps_shared_rejects);
		if (verbosity > 1)
			dump_range_overlaps_shared_top_offenders();
	}
	if (shm->stats.shared_region_overflow)
		stat_row("shared_buffer", "shared_region_overflow",
			 shm->stats.shared_region_overflow);
	if (parent_stats.mm_gate_post_slip)
		stat_row("shared_buffer", "mm_gate_post_slip",
			 parent_stats.mm_gate_post_slip);
	if (parent_stats.children_recycled_on_storm)
		stat_row("corruption", "children_recycled_on_storm",
			 parent_stats.children_recycled_on_storm);
	if (parent_stats.watchdog_fd_evict)
		stat_row("watchdog", "watchdog_fd_evict",
			 parent_stats.watchdog_fd_evict);

	if (verbosity > 1)
		dump_syscall_category_histogram();
}


static void dump_stats_childop_runs_local(void)
{
	stat_category_emit_text(&refcount_audit_category);

	if (shm->stats.fs_lifecycle_tmpfs   || shm->stats.fs_lifecycle_ramfs   ||
	    shm->stats.fs_lifecycle_rdonly  || shm->stats.fs_lifecycle_overlay ||
	    shm->stats.fs_lifecycle_quota   || shm->stats.fs_lifecycle_bind    ||
	    shm->stats.fs_lifecycle_unsupported) {
		stat_row("fs_lifecycle", "tmpfs",       shm->stats.fs_lifecycle_tmpfs);
		stat_row("fs_lifecycle", "ramfs",       shm->stats.fs_lifecycle_ramfs);
		stat_row("fs_lifecycle", "rdonly",      shm->stats.fs_lifecycle_rdonly);
		stat_row("fs_lifecycle", "overlay",     shm->stats.fs_lifecycle_overlay);
		stat_row("fs_lifecycle", "quota",       shm->stats.fs_lifecycle_quota);
		stat_row("fs_lifecycle", "bind",        shm->stats.fs_lifecycle_bind);
		stat_row("fs_lifecycle", "unsupported", shm->stats.fs_lifecycle_unsupported);
	}

	stat_category_emit_text(&signal_storm_category);

	if (shm->stats.futex_storm_runs)
		output(0, "\nfutex storm: runs:%lu inner_crashed:%lu iters:%lu\n",
			shm->stats.futex_storm_runs,
			shm->stats.futex_storm_inner_crashed,
			shm->stats.futex_storm_iters);

	stat_category_emit_text(&pipe_thrash_category);

	stat_category_emit_text(&fork_storm_category);

	stat_category_emit_text(&cpu_hotplug_rider_category);

	stat_category_emit_text(&pidfd_storm_category);

	stat_category_emit_text(&madvise_cycler_category);

	stat_category_emit_text(&keyring_spam_category);

	stat_category_emit_text(&vdso_mremap_race_category);

	stat_category_emit_text(&flock_thrash_category);

	stat_category_emit_text(&xattr_thrash_category);

	stat_category_emit_text(&epoll_volatility_category);

	stat_category_emit_text(&cgroup_churn_category);

	stat_category_emit_text(&mount_churn_category);

	stat_category_emit_text(&umount_race_category);

	stat_category_emit_text(&statmount_idmap_category);

	stat_category_emit_text(&uffd_churn_category);

	stat_category_emit_text(&iouring_flood_category);

	stat_category_emit_text(&close_racer_category);
}


static void dump_corpus_mutator_productivity(void)
{
	unsigned long tot_trials = 0;
	unsigned int i;

	for (i = 0; i < MUT_NUM_OPS; i++)
		tot_trials += __atomic_load_n(&minicorpus_shm->mut_trials[i],
					      __ATOMIC_RELAXED);

	if (tot_trials == 0)
		return;

	output(0, "\nMutator productivity (wins/trials  [structured wins/trials]):\n");
	for (i = 0; i < MUT_NUM_OPS; i++) {
		unsigned long t  = __atomic_load_n(&minicorpus_shm->mut_trials[i],
						   __ATOMIC_RELAXED);
		unsigned long w  = __atomic_load_n(&minicorpus_shm->mut_wins[i],
						   __ATOMIC_RELAXED);
		unsigned long st = __atomic_load_n(
			&minicorpus_shm->mut_structured_trials[i],
			__ATOMIC_RELAXED);
		unsigned long sw = __atomic_load_n(
			&minicorpus_shm->mut_structured_wins[i],
			__ATOMIC_RELAXED);
		unsigned long spct10 = st ? (sw * 1000UL / st) : 0UL;
		unsigned long pct10 = t ? (w * 1000UL / t) : 0UL;

		output(0, "  %-10s %lu/%lu (%lu.%lu%%)  [%lu/%lu (%lu.%lu%%)]\n",
		       op_names[i], w, t, pct10 / 10, pct10 % 10,
		       sw, st, spct10 / 10, spct10 % 10);
	}
}

static void dump_corpus_xprop(void)
{
	unsigned long xp_hits = __atomic_load_n(
		&minicorpus_shm->xprop_hits, __ATOMIC_RELAXED);
	unsigned long xp_wins = __atomic_load_n(
		&minicorpus_shm->xprop_wins, __ATOMIC_RELAXED);
	unsigned long pct10;

	if (xp_hits == 0)
		return;

	pct10 = xp_wins * 1000UL / xp_hits;
	output(0, "Xprop: %lu hits  %lu wins (%lu.%lu%%)\n",
	       xp_hits, xp_wins, pct10 / 10, pct10 % 10);
}

static void dump_corpus_stack_depth(void)
{
	unsigned long histo_total = 0;
	char hbuf[80];
	int hpos = 0;
	int written;
	unsigned int i;

	for (i = 1; i <= STACK_MAX; i++)
		histo_total += __atomic_load_n(&minicorpus_shm->stack_depth_histogram[i],
					       __ATOMIC_RELAXED);
	if (histo_total == 0)
		return;

	for (i = 1; i <= STACK_MAX; i++) {
		unsigned long d = __atomic_load_n(
			&minicorpus_shm->stack_depth_histogram[i],
			__ATOMIC_RELAXED);
		/* Bound BEFORE snprintf — sizeof(hbuf)-hpos goes to
		 * zero when full, but snprintf still returns the
		 * would-have-written length and the next iteration's
		 * hbuf+hpos lands past the buffer.  Stop here. */
		if (hpos >= (int)sizeof(hbuf) - 1)
			break;
		written = snprintf(hbuf + hpos, sizeof(hbuf) - hpos,
				   " [%u]:%lu", i, d);
		if (written < 0)
			break;
		hpos += written;
	}
	output(0, "Stack depth:%s\n", hbuf);
}

/* CMP-source save / win telemetry.  Always emit when the
 * minicorpus block is being dumped -- a zero on saves_cmp is
 * itself a signal worth seeing ("the gate widening is in but
 * the path isn't firing"), per the falsification criteria in
 * the investigations/ analysis. */
static void dump_corpus_saves(void)
{
	unsigned long saves_pc = __atomic_load_n(
		&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_PC],
		__ATOMIC_RELAXED);
	unsigned long saves_cmp = __atomic_load_n(
		&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_CMP],
		__ATOMIC_RELAXED);
	unsigned long saves_errno = __atomic_load_n(
		&minicorpus_shm->saves_by_reason[CORPUS_SAVE_REASON_ERRNO],
		__ATOMIC_RELAXED);
	unsigned long cmp_wins = __atomic_load_n(
		&minicorpus_shm->mut_attrib_cmp_wins,
		__ATOMIC_RELAXED);
	unsigned long errno_would = __atomic_load_n(
		&shm->stats.errno_grad_save_would_save,
		__ATOMIC_RELAXED);
	unsigned long errno_did = __atomic_load_n(
		&shm->stats.errno_grad_save_did_save,
		__ATOMIC_RELAXED);

	output(0, "Corpus saves: pc=%lu cmp=%lu errno=%lu  mut wins (cmp-source): %lu\n",
	       saves_pc, saves_cmp, saves_errno, cmp_wins);
	output(0, "Errno-gradient save: would=%lu did=%lu (gate=%s)\n",
	       errno_would, errno_did,
	       corpus_save_errno_grad_live ? "live" : "shadow");
}

/*
 * Per-tag productivity for the C.2b post-fill struct-field
 * mutator.  Independent from the per-op MUT_NUM_OPS counters
 * dumped above -- different injection point, different
 * histogram axis.  Suppressed when the aggregate trial count
 * is zero so a build / fleet that never invoked the path
 * stays clean; a single non-zero slot brings the whole
 * histogram into view so per-tag relative productivity
 * (FT_FLAGS bit-flips vs FT_RAW noise) is greppable.
 * Skip-listed tags (FT_PTR_*, FT_LEN_*, FT_FD, FT_ADDRESS,
 * FT_BPF_PROGRAM, FT_TAGGED_UNION) stay zero by design and
 * are silently skipped to keep the output compact.
 */
static void dump_corpus_struct_field_mutator(void)
{
	static const char *const tag_names[FT_NUM_TAGS] = {
		[FT_RAW]		= "raw",
		[FT_ENUM]		= "enum",
		[FT_RANGE]		= "range",
		[FT_FLAGS]		= "flags",
		[FT_PTR_BYTES]		= "ptr_bytes",
		[FT_PTR_ARRAY]		= "ptr_array",
		[FT_PTR_STRUCT]		= "ptr_struct",
		[FT_LEN_BYTES]		= "len_bytes",
		[FT_LEN_COUNT]		= "len_count",
		[FT_FD]			= "fd",
		[FT_MAGIC]		= "magic",
		[FT_VERSION_MAGIC]	= "vermagic",
		[FT_ADDRESS]		= "address",
		[FT_TAGGED_UNION]	= "tagged_union",
		[FT_BPF_PROGRAM]	= "bpf_program",
		[FT_VOCAB]		= "vocab",
		[FT_PICKER]		= "picker",
	};
	unsigned long sf_total = 0;
	unsigned int t;

	for (t = 0; t < FT_NUM_TAGS; t++)
		sf_total += __atomic_load_n(
			&minicorpus_shm->mut_struct_field_trials[t],
			__ATOMIC_RELAXED);

	if (sf_total == 0)
		return;

	output(0, "\nStruct-field mutator wins/trials (per tag):\n");
	for (t = 0; t < FT_NUM_TAGS; t++) {
		unsigned long tr = __atomic_load_n(
			&minicorpus_shm->mut_struct_field_trials[t],
			__ATOMIC_RELAXED);
		unsigned long wn = __atomic_load_n(
			&minicorpus_shm->mut_struct_field_wins[t],
			__ATOMIC_RELAXED);
		unsigned long tag_pct10;

		if (tr == 0 || tag_names[t] == NULL)
			continue;
		tag_pct10 = wn * 1000UL / tr;
		output(0, "  %-12s %lu/%lu (%lu.%lu%%)\n",
		       tag_names[t], wn, tr,
		       tag_pct10 / 10, tag_pct10 % 10);
	}
}

static void dump_corpus_sequence_chains(void)
{
	unsigned long c_iter = __atomic_load_n(
		&minicorpus_shm->chain_iter_count,
		__ATOMIC_RELAXED);
	unsigned long c_subst = __atomic_load_n(
		&minicorpus_shm->chain_substitution_count,
		__ATOMIC_RELAXED);
	unsigned long c_save = chain_corpus_shm ? __atomic_load_n(
		&chain_corpus_shm->save_count,
		__ATOMIC_RELAXED) : 0UL;
	unsigned long c_replay = chain_corpus_shm ? __atomic_load_n(
		&chain_corpus_shm->replay_count,
		__ATOMIC_RELAXED) : 0UL;

	if (c_iter > 0)
		output(0, "Sequence chains: %lu iters  %lu substitutions  %lu corpus saves  %lu replays\n",
		       c_iter, c_subst, c_save, c_replay);
}

static void dump_stats_corpus_tail(void)
{
	unsigned long s_hits, s_wins, r_count, r_wins, torn, pct10;

	dump_corpus_mutator_productivity();

	s_hits = __atomic_load_n(&minicorpus_shm->splice_hits, __ATOMIC_RELAXED);
	s_wins = __atomic_load_n(&minicorpus_shm->splice_wins, __ATOMIC_RELAXED);
	if (s_hits > 0) {
		pct10 = s_wins * 1000UL / s_hits;
		output(0, "Splice: %lu hits  %lu wins (%lu.%lu%%)\n",
		       s_hits, s_wins, pct10 / 10, pct10 % 10);
	}

	dump_corpus_xprop();

	/* Lockless-reader torn-read validator firings (aggregate over
	 * xprop pick, replay common, replay burst).  Gated on non-zero
	 * because the expected steady-state value is 0 -- the writer's
	 * release-store publish pattern makes mid-publish reads rare.
	 * A non-zero rate here means the validator is doing real work
	 * and torn reads ARE happening at the printed rate. */
	torn = __atomic_load_n(&minicorpus_shm->replay_torn_rejects,
			       __ATOMIC_RELAXED);
	if (torn > 0)
		output(0, "Corpus torn-read rejects: %lu\n", torn);

	dump_corpus_stack_depth();

	r_count = __atomic_load_n(&minicorpus_shm->replay_count, __ATOMIC_RELAXED);
	r_wins  = __atomic_load_n(&minicorpus_shm->replay_wins,  __ATOMIC_RELAXED);
	if (r_count > 0) {
		pct10 = r_wins * 1000UL / r_count;
		output(0, "Corpus replay: %lu replays  %lu wins (%lu.%lu%%)\n",
		       r_count, r_wins, pct10 / 10, pct10 % 10);
	}

	dump_corpus_saves();
	dump_corpus_struct_field_mutator();
	dump_corpus_sequence_chains();
}

static void dump_stats_cmp_hints_tail(void)
{
	unsigned int total_hints = 0, syscalls_with_hints = 0;
	unsigned int i, a;

	/* Per-arch slots count individually -- same rationale as the
	 * JSON emitter above. */
	for (i = 0; i < MAX_NR_SYSCALL; i++) {
		for (a = 0; a < 2; a++) {
			unsigned int n = cmp_hints_pool_safe_count(&cmp_hints_shm->pools[i][a]);

			if (n > 0) {
				total_hints += n;
				syscalls_with_hints++;
			}
		}
	}
	stat_row("cmp_hints", "values_total",        total_hints);
	stat_row("cmp_hints", "syscalls_with_hints", syscalls_with_hints);
}

/*
 * Periodic snapshot of /proc/sys/kernel/tainted so successive
 * stats dumps record when the kernel became tainted and which
 * flags were set, without waiting for is_tainted()'s mask-gated
 * "became tainted" trip.  Skipped on a clean kernel to match
 * the "suppress when zero" convention of the surrounding blocks.
 * mask row carries the raw bitmask; one row per recognised flag
 * makes the decoded set greppable.
 */
static void dump_stats_taint_snapshot(void)
{
	static const struct {
		const char *name;
		int bit;
	} taint_flags[] = {
		{ "PROPRIETARY_MODULE",    TAINT_PROPRIETARY_MODULE },
		{ "FORCED_MODULE",         TAINT_FORCED_MODULE },
		{ "UNSAFE_SMP",            TAINT_UNSAFE_SMP },
		{ "FORCED_RMMOD",          TAINT_FORCED_RMMOD },
		{ "MACHINE_CHECK",         TAINT_MACHINE_CHECK },
		{ "BAD_PAGE",              TAINT_BAD_PAGE },
		{ "USER",                  TAINT_USER },
		{ "DIE",                   TAINT_DIE },
		{ "OVERRIDDEN_ACPI_TABLE", TAINT_OVERRIDDEN_ACPI_TABLE },
		{ "WARN",                  TAINT_WARN },
		{ "CRAP",                  TAINT_CRAP },
		{ "FIRMWARE_WORKAROUND",   TAINT_FIRMWARE_WORKAROUND },
		{ "OOT_MODULE",            TAINT_OOT_MODULE },
	};
	int current_taint = get_taint();
	unsigned int t;

	if (current_taint != 0) {
		stat_row("taint", "mask", (unsigned long)current_taint);
		for (t = 0; t < ARRAY_SIZE(taint_flags); t++)
			if (current_taint & (1U << taint_flags[t].bit))
				stat_row("taint", taint_flags[t].name, 1);
	}
}

static void dump_stats_corpus_and_taint_tail(void)
{
	if (minicorpus_shm != NULL)
		dump_stats_corpus_tail();

	if (cmp_hints_shm != NULL)
		dump_stats_cmp_hints_tail();

	dump_stats_taint_snapshot();
}

/*
 * SHADOW reader for the per-childop decaying edge+wall recency ring.
 * Emits one "childop_decay:" line per op that has been invoked at least
 * once this run, carrying the cached recent-edge and recent-wall totals
 * across the last CHILDOP_DECAY_WINDOWS rotations alongside the
 * cumulative childop_edges_clean[] / childop_wall_ns[] denominators so
 * the operator can read recent vs lifetime yield in the same row.  No
 * scheduler / picker / canary path reads either ring -- the dump is the
 * only consumer today; the C2 spec's future util-table extension is the
 * next consumer.  Skips CHILD_OP_SYSCALL (the syscall path attributes
 * its work through the per-strategy counters, matching the surrounding
 * per-childop dumps) and skips never-invoked ops (skip-zero convention).
 */
void __cold dump_stats_childop_decay_recency(void)
{
	enum child_op_type op;
	unsigned int slot;
	bool any = false;

	slot = __atomic_load_n(&shm->stats.childop_decay_slot,
			       __ATOMIC_RELAXED);

	for (op = CHILD_OP_SYSCALL + 1; op < NR_CHILD_OP_TYPES; op++) {
		unsigned long invocations, recent_edges, recent_wall;
		unsigned long cum_edges, cum_wall;

		invocations = __atomic_load_n(
				&shm->stats.childop_invocations[op],
				__ATOMIC_RELAXED);
		if (invocations == 0)
			continue;

		recent_edges = __atomic_load_n(
				&shm->stats.childop_edge_recent_cached[op],
				__ATOMIC_RELAXED);
		recent_wall = __atomic_load_n(
				&shm->stats.childop_wall_recent_cached[op],
				__ATOMIC_RELAXED);
		cum_edges = __atomic_load_n(
				&shm->stats.childop_edges_clean[op],
				__ATOMIC_RELAXED);
		cum_wall = __atomic_load_n(
				&shm->stats.childop_wall_ns[op],
				__ATOMIC_RELAXED);

		if (!any) {
			output(1,
			       "childop_decay: per-op recent edges+wall over "
			       "last %u windows (slot=%u)\n",
			       (unsigned int)CHILDOP_DECAY_WINDOWS,
			       slot & (CHILDOP_DECAY_WINDOWS - 1));
			any = true;
		}

		output(1,
		       "childop_decay %s: invocations=%lu recent_edges=%lu recent_wall_ns=%lu cum_edges=%lu cum_wall_ns=%lu\n",
		       alt_op_name(op), invocations,
		       recent_edges, recent_wall, cum_edges, cum_wall);
	}
}

/*
 * Per-op fd-delta triage dump.  Skips ops that never landed a positive
 * delta (skip-zero convention, matches the rest of the per-childop
 * dumps).  When any op is emitted, the sort of the surviving rows by
 * total leak count is left to the operator; a leaker manifests as a
 * high fd_delta_positive_ops (many invocations that grew the fd table)
 * and a fd_delta_positive_sum trending unbounded across the run, while
 * ops with occasional short-lived probe collisions (open()/close() from
 * a sibling on the same low-numbered slot) sit at fd_delta_positive_ops
 * <= a few and _sum comparable to that count.  Fully self-suppressed
 * when instrumentation never fired -- the summary line only appears
 * once at least one op has a non-zero _sum.
 */
static void __cold dump_stats_childop_fd_delta(void)
{
	enum child_op_type op;
	bool any = false;

	for (op = CHILD_OP_SYSCALL + 1; op < NR_CHILD_OP_TYPES; op++) {
		unsigned long sum, ops;

		sum = __atomic_load_n(
				&shm->stats.childop_fd_delta_positive_sum[op],
				__ATOMIC_RELAXED);
		if (sum == 0)
			continue;
		ops = __atomic_load_n(
				&shm->stats.childop_fd_delta_positive_ops[op],
				__ATOMIC_RELAXED);

		if (!any) {
			output(1,
			       "childop_fd_delta: per-op net fd-table growth "
			       "observed across dispatched alt-op invocations\n");
			any = true;
		}
		output(1,
		       "childop_fd_delta %s: positive_sum=%lu positive_ops=%lu\n",
		       alt_op_name(op), sum, ops);
	}
}

static void __cold dump_stats_topo_pair_shadow(void)
{
	/* Per-setup_op aggregates from the surviving ring entries.  Sized
	 * by NR_CHILD_OP_TYPES so a corrupted setup_op byte that masks to
	 * the sentinel value is still in-bounds; the loop skips
	 * NR_CHILD_OP_TYPES at render time so the sentinel slot stays
	 * inert.  Local-stack to avoid touching shm for the aggregate. */
	unsigned long per_op_pc[NR_CHILD_OP_TYPES] = { 0 };
	unsigned long per_op_trans[NR_CHILD_OP_TYPES] = { 0 };
	unsigned long per_op_age_sum[NR_CHILD_OP_TYPES] = { 0 };
	unsigned long total_records, no_setup, head, total_valid = 0;
	unsigned int i;

	total_records = __atomic_load_n(&shm->stats.topo_pair_records,
					__ATOMIC_RELAXED);
	no_setup = __atomic_load_n(&shm->stats.topo_pair_no_setup_observed,
				   __ATOMIC_RELAXED);

	/* Self-skip when no productive event has fired through the ring
	 * AND no event has been dropped to the no-setup denominator -- in
	 * that state the row would carry no signal at all, and emitting a
	 * blank "shadow active, ring empty" line just adds noise to the
	 * shutdown dump.  Matches the dump_stats_top_wedging_childops()
	 * self-skip pattern. */
	if (total_records == 0 && no_setup == 0)
		return;

	head = __atomic_load_n(&shm->stats.topo_pair_ring_head,
			       __ATOMIC_RELAXED);

	for (i = 0; i < TOPO_PAIR_RING_SIZE; i++) {
		uint64_t packed;
		unsigned int setup_op, reason, syscall_nr, age;

		packed = __atomic_load_n(&shm->stats.topo_pair_ring[i],
					 __ATOMIC_RELAXED);
		if (!topo_pair_unpack(packed, &setup_op, &reason,
				      &syscall_nr, &age))
			continue;
		/* Defensive bounds check: the producer's topo_pair_pack()
		 * AND-masks setup_op to 8 bits, so a sentinel-or-corrupt
		 * value cast from NR_CHILD_OP_TYPES would not be filtered
		 * by the producer's branch alone.  Skip rather than scribble
		 * past the per_op_* arrays. */
		if (setup_op >= NR_CHILD_OP_TYPES)
			continue;
		if (reason == TOPO_PAIR_REASON_PC)
			per_op_pc[setup_op]++;
		else if (reason == TOPO_PAIR_REASON_TRANSITION)
			per_op_trans[setup_op]++;
		else
			continue;
		per_op_age_sum[setup_op] += age;
		total_valid++;
	}

	output(0,
	       "topo_pair_shadow: events_total=%lu sample_window=%u "
	       "valid_in_ring=%lu no_setup_observed=%lu head=%lu wrapped=%s\n",
	       total_records, (unsigned int)TOPO_PAIR_RING_SIZE,
	       total_valid, no_setup, head,
	       total_records >= (unsigned long)TOPO_PAIR_RING_SIZE
	       ? "yes" : "no");

	if (total_valid == 0)
		return;

	for (i = 0; i < NR_CHILD_OP_TYPES; i++) {
		unsigned long n;
		unsigned long mean_age;
		const char *name;

		n = per_op_pc[i] + per_op_trans[i];
		if (n == 0)
			continue;

		mean_age = per_op_age_sum[i] / n;
		name = alt_op_name((enum child_op_type)i);
		output(0,
		       "topo_pair_shadow %s: samples=%lu pc=%lu transition=%lu mean_age=%lu\n",
		       name ? name : "?", n,
		       per_op_pc[i], per_op_trans[i], mean_age);
	}
}

void __cold dump_stats(void)
{
	if (stats_json) {
		dump_stats_json();
		return;
	}

	/* Lead the shutdown report with the run-identity block so the
	 * provenance triple + cold/warm carrier state + own-start deltas
	 * are the first thing an operator sees -- the post-mortem hook a
	 * "did this run actually advance coverage" check needs before
	 * any of the downstream tables can be interpreted. */
	stats_runid_render();

	dump_stats_runtime_header();

	dump_stats_per_syscall_tables();

	dump_stats_top_wedging_syscalls();

	dump_stats_top_wedging_childops();

	dump_stats_fd_tracking();

	dump_stats_oracle_anomalies();

	dump_stats_fuzzer_subsystems();

	dump_stats_corruption_and_pool();

	dump_stats_childop_ranked_tables();

	childop_score_dump();

	childop_outcome_window_dump();

	dump_stats_childop_decay_recency();

	dump_stats_childop_fd_delta();

	dump_stats_topo_pair_shadow();

	dump_stats_shared_buffer_misc();

	dump_stats_strategy_summary();

	dump_stats_childop_runs_local();

	dump_stats_childop_runs_network();

	dump_stats_kcov_block();

	dump_stats_corpus_and_taint_tail();

	/* Cumulative childop vs random-syscall effort split.  Also emitted
	 * mid-run from defense_counters_periodic_dump on the 600 s cadence
	 * for long-fuzz visibility, but a short --dry-run (or any run that
	 * exits before the first periodic dump fires) still needs to see
	 * the block, so emit it unconditionally from the shutdown dump too.
	 * Self-skips silently if no dispatch has happened yet. */
	childop_split_dump();
}
