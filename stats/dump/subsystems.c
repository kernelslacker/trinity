#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "arg-len-semantics.h"
#include "breadcrumb_ring.h"
#include "child-api.h"
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
#include "shadow_promote.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "strategy.h"		/* frontier_spare_lane_decide, enum frontier_spare_reason */
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "utils-proc.h"
#include "version.h"

static void dump_stats_render_vfs_writes(void)
{
	if (shm->stats.procfs_writer.procfs_open_fail || shm->stats.procfs_writer.procfs_write_fail ||
	    shm->stats.procfs_writer.procfs_write_ok ||
	    shm->stats.procfs_writer.sysfs_open_fail || shm->stats.procfs_writer.sysfs_write_fail ||
	    shm->stats.procfs_writer.sysfs_write_ok ||
	    shm->stats.procfs_writer.debugfs_open_fail || shm->stats.procfs_writer.debugfs_write_fail ||
	    shm->stats.procfs_writer.debugfs_write_ok) {
		stat_row("vfs_writes", "procfs_open_fail",   shm->stats.procfs_writer.procfs_open_fail);
		stat_row("vfs_writes", "procfs_write_fail",  shm->stats.procfs_writer.procfs_write_fail);
		stat_row("vfs_writes", "procfs_write_ok",    shm->stats.procfs_writer.procfs_write_ok);
		stat_row("vfs_writes", "sysfs_open_fail",    shm->stats.procfs_writer.sysfs_open_fail);
		stat_row("vfs_writes", "sysfs_write_fail",   shm->stats.procfs_writer.sysfs_write_fail);
		stat_row("vfs_writes", "sysfs_write_ok",     shm->stats.procfs_writer.sysfs_write_ok);
		stat_row("vfs_writes", "debugfs_open_fail",  shm->stats.procfs_writer.debugfs_open_fail);
		stat_row("vfs_writes", "debugfs_write_fail", shm->stats.procfs_writer.debugfs_write_fail);
		stat_row("vfs_writes", "debugfs_write_ok",   shm->stats.procfs_writer.debugfs_write_ok);
	}
}

static void dump_stats_render_memory_pressure(void)
{
	if (shm->stats.memory_pressure_runs)
		stat_row("memory_pressure", "runs_madv_pageout", shm->stats.memory_pressure_runs);
}

static void dump_stats_render_genetlink(void)
{
	if (shm->stats.genetlink_fuzzer.families_discovered ||
	    shm->stats.genetlink_fuzzer.discovery_cycles       ||
	    shm->stats.genetlink_fuzzer.msgs_sent              ||
	    shm->stats.genetlink_fuzzer.missing_producer       ||
	    shm->stats.genetlink_fuzzer.discovery_io_err       ||
	    shm->stats.genetlink_fuzzer.discovery_nlerr        ||
	    shm->stats.genetlink_fuzzer.userns_run_fail        ||
	    shm->stats.genetlink_fuzzer.in_ns_open_fail        ||
	    shm->stats.genetlink_fuzzer.send_drain_fail) {
		stat_row("genetlink_fuzzer", "families_discovered", shm->stats.genetlink_fuzzer.families_discovered);
		stat_row("genetlink_fuzzer", "discovery_cycles",    shm->stats.genetlink_fuzzer.discovery_cycles);
		stat_row("genetlink_fuzzer", "msgs_sent",           shm->stats.genetlink_fuzzer.msgs_sent);
		stat_row("genetlink_fuzzer", "eperm",               shm->stats.genetlink_fuzzer.eperm);
		stat_row("genetlink_fuzzer", "stale_seq_drops",     shm->stats.genetlink_fuzzer.stale_seq_drops);
		stat_row("genetlink_fuzzer", "missing_producer",    shm->stats.genetlink_fuzzer.missing_producer);
		stat_row("genetlink_fuzzer", "discovery_io_err",    shm->stats.genetlink_fuzzer.discovery_io_err);
		stat_row("genetlink_fuzzer", "discovery_nlerr",     shm->stats.genetlink_fuzzer.discovery_nlerr);
		stat_row("genetlink_fuzzer", "userns_run_fail",     shm->stats.genetlink_fuzzer.userns_run_fail);
		stat_row("genetlink_fuzzer", "in_ns_open_fail",     shm->stats.genetlink_fuzzer.in_ns_open_fail);
		stat_row("genetlink_fuzzer", "send_drain_fail",     shm->stats.genetlink_fuzzer.send_drain_fail);
	}
}

static void dump_stats_render_genl_family_calls(void)
{
	if (shm->stats.genl_family_calls_devlink   ||
	    shm->stats.genl_family_calls_nl80211   ||
	    shm->stats.genl_family_calls_taskstats ||
	    shm->stats.genl_family_calls_ethtool   ||
	    shm->stats.genl_family_calls_mptcp_pm  ||
	    shm->stats.genl_family_calls_tipc      ||
	    shm->stats.genl_family_calls_wireguard ||
	    shm->stats.genl_family_calls_netlabel  ||
	    shm->stats.genl_family_calls_team      ||
	    shm->stats.genl_family_calls_hsr       ||
	    shm->stats.genl_family_calls_fou       ||
	    shm->stats.genl_family_calls_psample   ||
	    shm->stats.genl_family_calls_nfsd      ||
	    shm->stats.genl_family_calls_ila       ||
	    shm->stats.genl_family_calls_ioam6     ||
	    shm->stats.genl_family_calls_seg6      ||
	    shm->stats.genl_family_calls_thermal   ||
	    shm->stats.genl_family_calls_ipvs) {
		stat_row("genl_family_calls", "devlink",   shm->stats.genl_family_calls_devlink);
		stat_row("genl_family_calls", "nl80211",   shm->stats.genl_family_calls_nl80211);
		stat_row("genl_family_calls", "taskstats", shm->stats.genl_family_calls_taskstats);
		stat_row("genl_family_calls", "ethtool",   shm->stats.genl_family_calls_ethtool);
		stat_row("genl_family_calls", "mptcp_pm",  shm->stats.genl_family_calls_mptcp_pm);
		stat_row("genl_family_calls", "tipc",      shm->stats.genl_family_calls_tipc);
		stat_row("genl_family_calls", "wireguard", shm->stats.genl_family_calls_wireguard);
		stat_row("genl_family_calls", "netlabel",  shm->stats.genl_family_calls_netlabel);
		stat_row("genl_family_calls", "team",      shm->stats.genl_family_calls_team);
		stat_row("genl_family_calls", "hsr",       shm->stats.genl_family_calls_hsr);
		stat_row("genl_family_calls", "fou",       shm->stats.genl_family_calls_fou);
		stat_row("genl_family_calls", "psample",   shm->stats.genl_family_calls_psample);
		stat_row("genl_family_calls", "nfsd",      shm->stats.genl_family_calls_nfsd);
		stat_row("genl_family_calls", "ila",       shm->stats.genl_family_calls_ila);
		stat_row("genl_family_calls", "ioam6",     shm->stats.genl_family_calls_ioam6);
		stat_row("genl_family_calls", "seg6",      shm->stats.genl_family_calls_seg6);
		stat_row("genl_family_calls", "thermal",   shm->stats.genl_family_calls_thermal);
		stat_row("genl_family_calls", "ipvs",      shm->stats.genl_family_calls_ipvs);
	}
}

static void dump_stats_render_nfnl_subsys(void)
{
	if (shm->stats.nfnl_subsys_calls_ctnetlink     ||
	    shm->stats.nfnl_subsys_calls_ctnetlink_exp ||
	    shm->stats.nfnl_subsys_calls_nftables      ||
	    shm->stats.nfnl_subsys_calls_ipset) {
		stat_row("nfnl_subsys_calls", "ctnetlink",     shm->stats.nfnl_subsys_calls_ctnetlink);
		stat_row("nfnl_subsys_calls", "ctnetlink_exp", shm->stats.nfnl_subsys_calls_ctnetlink_exp);
		stat_row("nfnl_subsys_calls", "nftables",      shm->stats.nfnl_subsys_calls_nftables);
		stat_row("nfnl_subsys_calls", "ipset",         shm->stats.nfnl_subsys_calls_ipset);
	}
}

static void dump_stats_render_netlink_generator(void)
{
	if (shm->stats.netlink_nested_attrs_emitted)
		stat_row("netlink_generator", "nested_attrs_emitted", shm->stats.netlink_nested_attrs_emitted);
}

static void dump_stats_render_kvm(void)
{
	if (shm->stats.kvm_vcpu_ioctls_dispatched)
		stat_row("kvm", "vcpu_ioctls_dispatched", shm->stats.kvm_vcpu_ioctls_dispatched);

	if (shm->stats.kvm_vm_ioctls_dispatched)
		stat_row("kvm", "vm_ioctls_dispatched", shm->stats.kvm_vm_ioctls_dispatched);
}

static void dump_stats_render_tracefs(void)
{
	if (shm->stats.tracefs_fuzzer.kprobe_open_fail || shm->stats.tracefs_fuzzer.kprobe_write_fail ||
	    shm->stats.tracefs_fuzzer.kprobe_write_ok ||
	    shm->stats.tracefs_fuzzer.uprobe_open_fail || shm->stats.tracefs_fuzzer.uprobe_write_fail ||
	    shm->stats.tracefs_fuzzer.uprobe_write_ok ||
	    shm->stats.tracefs_fuzzer.filter_open_fail || shm->stats.tracefs_fuzzer.filter_write_fail ||
	    shm->stats.tracefs_fuzzer.filter_write_ok ||
	    shm->stats.tracefs_fuzzer.event_enable_open_fail || shm->stats.tracefs_fuzzer.event_enable_write_fail ||
	    shm->stats.tracefs_fuzzer.event_enable_write_ok ||
	    shm->stats.tracefs_fuzzer.misc_open_fail || shm->stats.tracefs_fuzzer.misc_write_fail ||
	    shm->stats.tracefs_fuzzer.misc_write_ok) {
		stat_row("tracefs_fuzzer", "kprobe_open_fail",         shm->stats.tracefs_fuzzer.kprobe_open_fail);
		stat_row("tracefs_fuzzer", "kprobe_write_fail",        shm->stats.tracefs_fuzzer.kprobe_write_fail);
		stat_row("tracefs_fuzzer", "kprobe_write_ok",          shm->stats.tracefs_fuzzer.kprobe_write_ok);
		stat_row("tracefs_fuzzer", "uprobe_open_fail",         shm->stats.tracefs_fuzzer.uprobe_open_fail);
		stat_row("tracefs_fuzzer", "uprobe_write_fail",        shm->stats.tracefs_fuzzer.uprobe_write_fail);
		stat_row("tracefs_fuzzer", "uprobe_write_ok",          shm->stats.tracefs_fuzzer.uprobe_write_ok);
		stat_row("tracefs_fuzzer", "filter_open_fail",         shm->stats.tracefs_fuzzer.filter_open_fail);
		stat_row("tracefs_fuzzer", "filter_write_fail",        shm->stats.tracefs_fuzzer.filter_write_fail);
		stat_row("tracefs_fuzzer", "filter_write_ok",          shm->stats.tracefs_fuzzer.filter_write_ok);
		stat_row("tracefs_fuzzer", "event_enable_open_fail",   shm->stats.tracefs_fuzzer.event_enable_open_fail);
		stat_row("tracefs_fuzzer", "event_enable_write_fail",  shm->stats.tracefs_fuzzer.event_enable_write_fail);
		stat_row("tracefs_fuzzer", "event_enable_write_ok",    shm->stats.tracefs_fuzzer.event_enable_write_ok);
		stat_row("tracefs_fuzzer", "misc_open_fail",           shm->stats.tracefs_fuzzer.misc_open_fail);
		stat_row("tracefs_fuzzer", "misc_write_fail",          shm->stats.tracefs_fuzzer.misc_write_fail);
		stat_row("tracefs_fuzzer", "misc_write_ok",            shm->stats.tracefs_fuzzer.misc_write_ok);
	}
}

static void dump_stats_render_bpf_fd_provider(void)
{
	if (shm->stats.bpf_maps_provided || shm->stats.bpf_progs_provided) {
		stat_row("bpf_fd_provider", "maps_provided",  shm->stats.bpf_maps_provided);
		stat_row("bpf_fd_provider", "progs_provided", shm->stats.bpf_progs_provided);
	}
}

static void dump_stats_render_ebpf_gen(void)
{
	if (shm->stats.ebpf_gen_map_fd_substituted) {
		stat_row("ebpf_gen", "map_fd_substituted",
			 shm->stats.ebpf_gen_map_fd_substituted);
	}

	if (shm->stats.ebpf_gen_helper_call_emitted) {
		stat_row("ebpf_gen", "helper_call_emitted",
			 shm->stats.ebpf_gen_helper_call_emitted);
	}

	if (shm->stats.ebpf_gen_map_value_deref_emitted) {
		stat_row("ebpf_gen", "map_value_deref_emitted",
			 shm->stats.ebpf_gen_map_value_deref_emitted);
		stat_row("ebpf_gen", "map_value_deref_read",
			 shm->stats.ebpf_gen_map_value_deref_read);
		stat_row("ebpf_gen", "map_value_deref_write",
			 shm->stats.ebpf_gen_map_value_deref_write);
	}
}

static void dump_stats_render_recipe_runner(void)
{
	if (shm->stats.recipe.runs) {
		stat_row("recipe_runner", "runs",        shm->stats.recipe.runs);
		stat_row("recipe_runner", "completed",   shm->stats.recipe.completed);
		stat_row("recipe_runner", "partial",     shm->stats.recipe.partial);
		stat_row("recipe_runner", "unsupported", shm->stats.recipe.unsupported);
		recipe_runner_dump_stats();
	}
}

static void dump_stats_render_iouring(void)
{
	if (shm->stats.iouring_recipes.runs) {
		stat_row("iouring_recipes", "runs",      shm->stats.iouring_recipes.runs);
		stat_row("iouring_recipes", "completed", shm->stats.iouring_recipes.completed);
		stat_row("iouring_recipes", "partial",   shm->stats.iouring_recipes.partial);
		stat_row("iouring_recipes", "enosys",    shm->stats.iouring_recipes.enosys);
		iouring_recipes_dump_stats();
	}

	if (shm->stats.iouring_eventfd.register_ok ||
	    shm->stats.iouring_eventfd.register_fail) {
		stat_row("iouring_eventfd", "register_ok",
			 shm->stats.iouring_eventfd.register_ok);
		stat_row("iouring_eventfd", "register_fail",
			 shm->stats.iouring_eventfd.register_fail);
		stat_row("iouring_eventfd", "recursive_runs",
			 shm->stats.iouring_eventfd.recursive_runs);
		stat_row("iouring_eventfd", "recursive_cqes",
			 shm->stats.iouring_eventfd.recursive_cqes);
	}
}

static void dump_stats_render_zombie_slots(void)
{
	if (shm->stats.zombies_reaped || shm->stats.zombies_timed_out ||
	    shm->stats.zombie_slots_pending) {
		stat_row("zombie_slots", "pending",   shm->stats.zombie_slots_pending);
		stat_row("zombie_slots", "reaped",    shm->stats.zombies_reaped);
		stat_row("zombie_slots", "timed_out", shm->stats.zombies_timed_out);
	}
}

void dump_stats_fuzzer_subsystems(void)
{
	dump_stats_render_vfs_writes();

	dump_stats_render_memory_pressure();

	stat_category_emit_text(&sched_cycler_category);

	stat_category_emit_text(&userns_fuzzer_category);

	stat_category_emit_text(&userns_bootstrap_category);

	stat_category_emit_text(&barrier_racer_category);

	dump_stats_render_genetlink();

	dump_stats_render_genl_family_calls();

	dump_stats_render_nfnl_subsys();

	dump_stats_render_netlink_generator();

	dump_stats_render_kvm();

	stat_category_emit_text(&perf_event_chains_category);

	dump_stats_render_tracefs();

	stat_category_emit_text(&bpf_lifecycle_category);

	dump_stats_render_bpf_fd_provider();

	dump_stats_render_ebpf_gen();

	dump_stats_render_recipe_runner();

	dump_stats_render_iouring();

	stat_category_emit_text(&aio_category);

	stat_category_emit_text(&errno_gradient_category);

	stat_category_emit_text(&cold_overflow_category);

	stat_category_emit_text(&inplace_crypto_category);

	stat_category_emit_text(&fd_runtime_skipped_category);

	stat_category_emit_text(&child_category);

	stat_category_emit_text(&parent_category);

	stat_category_emit_text(&uid_change_category);

	stat_category_emit_text(&no_domains_category);

	dump_stats_render_zombie_slots();

	if (shm->stats.wrong_fd_type_substitutions)
		stat_row("arggen", "wrong_fd_type_substitutions",
			 shm->stats.wrong_fd_type_substitutions);
	if (shm->stats.wrong_fd_type_subst_generic)
		stat_row("arggen", "wrong_fd_type_subst_generic",
			 shm->stats.wrong_fd_type_subst_generic);

	if (shm->stats.btrfs_ioctls_dispatched)
		stat_row("ioctl", "btrfs_ioctls_dispatched",
			 shm->stats.btrfs_ioctls_dispatched);

	if (shm->stats.mmap_size_clamped)
		stat_row("mmap", "mmap_size_clamped",
			 shm->stats.mmap_size_clamped);

	if (shm->stats.heap_extra_regions_overflow)
		stat_row("heap", "heap_extra_regions_overflow",
			 shm->stats.heap_extra_regions_overflow);
}
