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

/* Per-group shadow of blob_fills.  Sum-suppressed so an OFF /
 * no-blob-fill run emits nothing (render-gap-aware); per-row zero-
 * suppressed so a partially-covered run only shows the groups that
 * actually ran a blob_fill().  Group name table mirrors
 * check_fd_leaks() in child/child.c. */
static void dump_stats_render_blob_fills_by_group(void)
{
	static const char * const group_names[NR_GROUPS] = {
		[GROUP_NONE]     = "none",
		[GROUP_VM]       = "vm",
		[GROUP_VFS]      = "vfs",
		[GROUP_NET]      = "net",
		[GROUP_IPC]      = "ipc",
		[GROUP_PROCESS]  = "process",
		[GROUP_SIGNAL]   = "signal",
		[GROUP_IO_URING] = "io_uring",
		[GROUP_BPF]      = "bpf",
		[GROUP_SCHED]    = "sched",
		[GROUP_TIME]     = "time",
		[GROUP_XATTR]    = "xattr",
	};
	unsigned long total = 0;
	unsigned int i;

	for (i = 0; i < NR_GROUPS; i++)
		total += shm->stats.blob.fills_by_group[i];
	if (total == 0)
		return;

	for (i = 0; i < NR_GROUPS; i++) {
		if (shm->stats.blob.fills_by_group[i] == 0)
			continue;
		stat_row("blob_fills_by_group", group_names[i],
			 shm->stats.blob.fills_by_group[i]);
	}
}

static void dump_stats_render_accept_unblocker(void)
{
	if (shm->stats.accept_unblocker.connects_fired ||
	    shm->stats.accept_unblocker.loopback_only_skipped ||
	    shm->stats.accept_unblocker.probe_failed) {
		stat_row("accept_unblocker", "connects_fired",
			 shm->stats.accept_unblocker.connects_fired);
		stat_row("accept_unblocker", "loopback_only_skipped",
			 shm->stats.accept_unblocker.loopback_only_skipped);
		stat_row("accept_unblocker", "probe_failed",
			 shm->stats.accept_unblocker.probe_failed);
	}
}

static void dump_stats_render_pipe_waker(void)
{
	if (shm->stats.pipe_waker.bytes_written ||
	    shm->stats.pipe_waker.no_target ||
	    shm->stats.pipe_waker.write_failed) {
		stat_row("pipe_waker", "bytes_written",
			 shm->stats.pipe_waker.bytes_written);
		stat_row("pipe_waker", "no_target",
			 shm->stats.pipe_waker.no_target);
		stat_row("pipe_waker", "write_failed",
			 shm->stats.pipe_waker.write_failed);
	}
}

static void dump_stats_render_vsock_transport_churn(void)
{
	if (shm->stats.vsock_transport_churn.runs) {
		stat_row("vsock_transport_churn", "runs",           shm->stats.vsock_transport_churn.runs);
		stat_row("vsock_transport_churn", "setup_failed",   shm->stats.vsock_transport_churn.setup_failed);
		stat_row("vsock_transport_churn", "bind_ok",        shm->stats.vsock_transport_churn.bind_ok);
		stat_row("vsock_transport_churn", "connect_ok",     shm->stats.vsock_transport_churn.connect_ok);
		stat_row("vsock_transport_churn", "send_ok",        shm->stats.vsock_transport_churn.send_ok);
		stat_row("vsock_transport_churn", "buffer_size_ok", shm->stats.vsock_transport_churn.buffer_size_ok);
		stat_row("vsock_transport_churn", "timeout_ok",     shm->stats.vsock_transport_churn.timeout_ok);
		stat_row("vsock_transport_churn", "get_cid_ok",     shm->stats.vsock_transport_churn.get_cid_ok);
		stat_row("vsock_transport_churn", "seq_eom_runs",         shm->stats.vsock_transport_churn.seq_eom_runs);
		stat_row("vsock_transport_churn", "seq_eom_sends_ok",     shm->stats.vsock_transport_churn.seq_eom_sends_ok);
		stat_row("vsock_transport_churn", "seq_eom_sends_failed", shm->stats.vsock_transport_churn.seq_eom_sends_failed);
		stat_row("vsock_transport_churn", "seq_eom_skipped",      shm->stats.vsock_transport_churn.seq_eom_skipped);
	}
}

static void dump_stats_render_kvm_run_churn(void)
{
	if (shm->stats.kvm.invocations) {
		stat_row("kvm_run_churn", "invocations",        shm->stats.kvm.invocations);
		stat_row("kvm_run_churn", "exit_io",            shm->stats.kvm.exit_io);
		stat_row("kvm_run_churn", "exit_mmio",          shm->stats.kvm.exit_mmio);
		stat_row("kvm_run_churn", "exit_hlt",           shm->stats.kvm.exit_hlt);
		stat_row("kvm_run_churn", "exit_shutdown",      shm->stats.kvm.exit_shutdown);
		stat_row("kvm_run_churn", "exit_fail_entry",    shm->stats.kvm.exit_fail_entry);
		stat_row("kvm_run_churn", "exit_internal_error", shm->stats.kvm.exit_internal_error);
		stat_row("kvm_run_churn", "exit_intr",          shm->stats.kvm.exit_intr);
		stat_row("kvm_run_churn", "exit_other",         shm->stats.kvm.exit_other);
		stat_row("kvm_run_churn", "errors",             shm->stats.kvm.errors);
		stat_row("kvm_run_churn", "gpc_memslot_race_runs",         shm->stats.kvm.gpc_memslot_race_runs);
		stat_row("kvm_run_churn", "gpc_memslot_race_deletes",      shm->stats.kvm.gpc_memslot_race_deletes);
		stat_row("kvm_run_churn", "gpc_memslot_race_unsupported",  shm->stats.kvm.gpc_memslot_race_unsupported);
	}
}
void __cold dump_stats_childop_runs_network(void)
{
	stat_category_emit_text(&socket_family_grammar_category);
	stat_category_emit_text(&xfrm_grammar_category);


	dump_stats_render_accept_unblocker();

	dump_stats_render_pipe_waker();






	stat_category_emit_text(&blob_mutator_category);

	stat_category_emit_text(&blob_ab_mode_category);

	dump_stats_render_blob_fills_by_group();

	stat_category_emit_text(&setsockopt_pairing_category);


	dump_stats_render_vsock_transport_churn();




	dump_stats_render_kvm_run_churn();


	stat_category_emit_text(&rxrpc_key_install_category);



}
