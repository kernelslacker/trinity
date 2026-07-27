#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Shared persistence envelope: a fixed header prepended to every
 * cross-run state file (minicorpus, chain corpus, kcov bucket_seen[]
 * bitmap, cmp-hints pool).  The per-component header + payload follows
 * immediately.  Two problems this fixes:
 *
 *   1. A mis-pointed path (e.g. cmp-hints file passed to the kcov
 *      loader) is refused before the component parser sees a byte.
 *
 *   2. Torn warm-start: the four files rename independently, so a
 *      crash between a kcov save and a minicorpus save leaves them
 *      one generation apart.  On the next boot the manifest pins
 *      which generation each component must load from -- anything
 *      older is cold-started.
 */

#define TRINITY_PERSIST_MAGIC		0x54524e50455253ULL  /* "TRNPERS" */
#define TRINITY_PERSIST_MANIFEST_MAGIC	0x54524e4d414e46ULL  /* "TRNMANF" */

/* Manifest filename (basename inside the persist directory). */
#define TRINITY_PERSIST_MANIFEST_NAME	"generation.manifest"

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

struct trinity_persist_manifest_header {
	uint64_t magic;			/* TRINITY_PERSIST_MANIFEST_MAGIC */
	uint64_t generation;		/* generation of this coordinated save */
	uint32_t nr_components;
	uint32_t reserved;
	/* followed by nr_components * uint32_t component_id values */
};

/*
 * Current run's generation id.  Lazy-inited on first call from
 * CLOCK_REALTIME so all four save paths in a process share the same
 * value.  Forked children inherit the cached value via COW.
 */
uint64_t persist_envelope_current_generation(void);

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

/*
 * Cross-check the envelope's generation against the shared manifest.
 * When no manifest exists (first-run of manifest-aware trinity, or
 * user cleared cache) the check is skipped and returns true --
 * fall back to per-file validation.  When a manifest exists but
 * either omits this component or names a different generation, the
 * file is torn from a partial coordinated save and false is returned.
 */
bool persist_envelope_check_generation(const struct trinity_persist_envelope *env,
				       enum trinity_persist_component expected,
				       const char *path);

/*
 * Return the shared manifest path ($XDG_CACHE_HOME/trinity/<name>
 * or $HOME/.cache/trinity/<name>).  Pointer is owned by a static
 * buffer.  Returns NULL if neither env var yields an absolute path
 * or the parent directory cannot be created.
 */
const char *persist_manifest_default_path(void);

/*
 * Write the generation manifest naming components successfully
 * persisted in this coordinated save.  Best-effort: on failure
 * returns false and logs.  Called once at the end of the shutdown
 * save sequence.
 */
bool persist_write_generation_manifest(uint64_t generation,
				       const enum trinity_persist_component *components,
				       uint32_t nr_components);
