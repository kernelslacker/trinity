#ifndef _TRINITY_STATS_SUBSYS_MREMAP_MERGE_MATRIX_H
#define _TRINITY_STATS_SUBSYS_MREMAP_MERGE_MATRIX_H

struct mremap_merge_matrix_stats {
	/* Incremented every time do_move() is invoked so a reader can
	 * distinguish "oracle ran and passed" from "oracle never ran"
	 * (a healthy zero in tag_mismatch/topology_unexpected is only
	 * meaningful when checks_run is non-zero). */
	unsigned long checks_run;
	/* do_move() returned false: at least one verify_pages() comparison
	 * found the wrong cookie at the destination (or the DONTUNMAP
	 * source).  Indicates mremap relocated or duplicated a page to the
	 * wrong address, or the page-table rewrite corrupted the content. */
	unsigned long tag_mismatch;
	/* Topology assertion fired: post_vmas > pre_vmas after a
	 * same-prot adjacent landing where a merge was expected to
	 * collapse the VMA count.  Indicates the kernel did not merge
	 * when it should have, or unexpectedly split an existing VMA. */
	unsigned long topology_unexpected;
};

#endif /* _TRINITY_STATS_SUBSYS_MREMAP_MERGE_MATRIX_H */
