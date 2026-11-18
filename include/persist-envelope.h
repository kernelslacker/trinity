#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Shared persistence envelope: a fixed header prepended to every
 * cross-run state file (minicorpus, chain corpus, kcov bucket_seen[]
 * bitmap, cmp-hints pool).  The per-component header + payload follows
 * immediately.  A mis-pointed path (e.g. cmp-hints file passed to the
 * kcov loader) or a file saved under another kernel is refused before
 * the component parser sees a byte.
 */

#define TRINITY_PERSIST_MAGIC		0x54524e50455253ULL  /* "TRNPERS" */

/* Kernel identity buffer size (utsname.release + version, truncated). */
#define TRINITY_PERSIST_KERNEL_IDENTITY_LEN	64U

/*
 * Component IDs.  Values are stable on-disk -- never renumber and
 * never reuse.  If a component is dropped, retire its slot rather
 * than reassigning it.
 */
enum trinity_persist_component {
	PERSIST_MINICORPUS	= 1,
	PERSIST_CHAIN		= 2,
	PERSIST_KCOV		= 3,
	PERSIST_CMP_HINTS	= 4,
};

struct trinity_persist_envelope {
	uint64_t magic;			/* TRINITY_PERSIST_MAGIC */
	uint32_t component_id;		/* enum trinity_persist_component */
	uint32_t schema_version;	/* per-component payload version */
	uint64_t generation;		/* run id, monotonic across saves */
	uint8_t  kernel_identity[TRINITY_PERSIST_KERNEL_IDENTITY_LEN];
	uint32_t checksum;		/* over payload; 0 if not computed */
	uint32_t payload_len;		/* bytes following envelope; 0 if unknown */
};

/*
 * Populate an envelope with the caller's ids and this run's
 * generation.  kernel_identity is filled from uname(); on uname()
 * failure the field is zeroed and load-side validation will refuse
 * the mismatch on a subsequent run.
 */
void persist_envelope_init(struct trinity_persist_envelope *env,
			   enum trinity_persist_component component,
			   uint32_t schema_version,
			   uint32_t payload_len,
			   uint32_t checksum);

/*
 * Validate an envelope just read from disk.  Checks magic,
 * component_id (must equal expected), and kernel_identity.  On
 * mismatch returns false and logs one line via output().  Callers
 * treat false as "stale, cold-start this component".
 */
bool persist_envelope_validate(const struct trinity_persist_envelope *env,
			       enum trinity_persist_component expected,
			       const char *path);
