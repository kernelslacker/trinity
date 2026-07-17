#include <stddef.h>
#include "stats-internal.h"

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
 * split.  Per-rung attribution: blob_fills bumps for every non-OFF
 * mode (FILL / HAVOC / CMPDICT), blob_havoc_ops and
 * blob_havoc_prefix_len_ops bump for HAVOC and CMPDICT, and
 * blob_dict_inserts, blob_static_magic_inserts, and
 * blob_dict_transform_inserts bump only for CMPDICT -- so each
 * rung's contribution is isolated across an off / fill / havoc /
 * cmpdict A/B.  When the mode is OFF the gate counter stays at zero so
 * stat_category_emit_text suppresses the whole block (render-gap-
 * aware). */
static const struct stat_field blob_mutator_fields[] = {
	STAT_FIELD_SUB(blob, fills),
	STAT_FIELD_SUB(blob, havoc_ops),
	STAT_FIELD_SUB(blob, havoc_prefix_len_ops),
	STAT_FIELD_SUB(blob, dict_inserts),
	STAT_FIELD_SUB(blob, static_magic_inserts),
	STAT_FIELD_SUB(blob, dict_transform_inserts),
	STAT_FIELD_SUB(blob, base_from_corpus),
	STAT_FIELD_SUB(blob, base_from_random),
};

const struct stat_category blob_mutator_category =
	STAT_CATEGORY("blob_mutator",
	              blob.fills,
	              blob_mutator_fields);
