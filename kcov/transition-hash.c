/*
 * kcov/transition-hash.c — KASLR canonicalisation for kernel comparison
 * instruction addresses.
 *
 * kcov_canon_cmp_ip() is the single ingress point that CMP-hint
 * consumers use to strip the runtime KASLR base from a comparison-
 * instruction PC before it is stored in the per-syscall pool or the
 * persisted cmp-hints file.  Kept in its own TU, apart from the
 * PC-coverage kcov_canon_pc in collect-internal.h, so every cmp-hint
 * caller goes through one named ingress.
 */

#include "kcov-internal.h"	/* kcov_kaslr_base extern, kcov types */

/*
 * KASLR-strip a kernel comparison-instruction address before it lands in
 * the cmp-hints bloom + per-syscall pool + persisted state file.  Same
 * transform as kcov_canon_pc -- both subtract the runtime _text base
 * resolved by kcov_get_kaslr_base -- but kept as a distinct entry point
 * for the cmp-hint side so the cmp-hints code has a single named
 * ingress, separate from the PC-coverage canonicalisation rule.
 *
 * Without this, the cmp-hints pool indexed entries by the raw runtime
 * PC of the kernel comparison site; a KASLR reroll between save and
 * load shifted every cmp_ip by the difference in kernel-text bases, so
 * the kallsyms-fingerprint match said "same kernel" but the warm-loaded
 * pool aliased every constant to a different (cmp_ip, value, size) key.
 * Field-scoped scoring planned on top of cmp_ip would compound the
 * noise.  The persisted-file header now stamps kcov_kaslr_base alongside
 * the canonical cmp_ip values, and the load path rejects a canonical-vs-
 * raw mismatch the same way kcov_bitmap_file_header.kaslr_base does.
 */
unsigned long kcov_canon_cmp_ip(unsigned long ip)
{
	return ip - (unsigned long)kcov_kaslr_base;
}
