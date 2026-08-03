#pragma once

/* Sub-struct of struct kcov_shared, embedded as .coverage.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_coverage_core {
	/* Count of (edge, bucket) bit-flips ever observed.  Since the
	 * bucket-seen table was introduced this is NOT the count of distinct
	 * edges -- a re-hit of a known edge that lands in a previously-unseen
	 * hit-count bucket bumps this counter, so it conflates "new code
	 * reached" with "known code reached at a new iteration depth".  Kept
	 * as the fine-grained feedback signal for the minicorpus / mutator-
	 * attribution consumers that want every novel bucket
	 * transition to register.  For the cardinality of edges ever reached
	 * -- the signal the coverage-plateau detector needs -- read
	 * distinct_edges below instead. */
	unsigned long edges_found;
	/* Count of distinct edges ever seen in any bucket: incremented exactly
	 * once per edge, on the bucket_seen[edge] == 0 -> first-bit transition
	 * in kcov_collect().  This is the true "new code reached" signal and
	 * the one the plateau detector samples; edges_found above grows with
	 * bucket churn on already-known edges and so its delta never falls to
	 * zero even when no new code is being reached. */
	unsigned long distinct_edges;
	/* Count of edges seeded into bucket_seen[] / edges_found by the
	 * warm-start cache loader at startup.  Zero on a cold-start run
	 * (no cache file, version/fingerprint mismatch, CRC failure, etc.).
	 * Set once after the cache-load loop completes and never mutated
	 * thereafter, so cold = edges_found - edges_warm_loaded is the
	 * subset of coverage actually discovered by this process — the
	 * operator-facing split that distinguishes "plateau near the prior
	 * corpus ceiling" from "plateau after genuinely exhausting easy
	 * edges this run". */
	unsigned long edges_warm_loaded;
	/* Mirror of edges_warm_loaded for the distinct_edges counter.
	 * Snapshotted to distinct_edges at warm-start load so a later
	 * (distinct_edges - distinct_edges_warm_loaded) subtraction is the
	 * count of truly new edges this process has discovered itself.
	 * Zero on a cold-start run. */
	unsigned long distinct_edges_warm_loaded;
	unsigned long total_pcs;
	unsigned long total_calls;
	unsigned long remote_calls;	/* calls using KCOV_REMOTE_ENABLE */
	/* Number of kcov_collect() calls where the kernel filled the entire
	 * trace buffer.  When non-zero a non-trivial fraction of syscalls
	 * are losing tail coverage and KCOV_TRACE_SIZE should be raised. */
	unsigned long trace_truncated;
	/* Magnitude estimate for coverage dropped by trace-buffer truncation.
	 * Bumped in kcov_collect() on every truncation event by the
	 * post-cap PC count actually captured (= kcov_trace_size - 1).
	 * The kernel-side kcov stops writing once the buffer fills and
	 * does not report the dropped-tail length, so this is a
	 * PC-magnitude proxy rather than a direct "edges lost" tally: the
	 * true lost PC count is >= trace_loss / trace_truncated per event,
	 * strictly greater than zero on any truncated bracket.  Exposed
	 * so operators can read (trace_loss / total_pcs) as the "fraction
	 * of captured coverage that lived in a truncated bracket" and
	 * (trace_loss / edges_found) as the "PCs captured under truncation
	 * per discovered edge" -- both climb toward saturation when the
	 * trace buffer is the bottleneck on coverage growth.  Distinct
	 * from trace_truncated (event count) in units and monotonicity:
	 * a run of small truncated brackets grows trace_truncated fast
	 * but trace_loss slowly, whereas one large truncated bracket
	 * grows both together. */
	unsigned long trace_loss;
};
