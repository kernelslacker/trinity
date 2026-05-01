#pragma once

#include "compat.h"

#ifdef USE_IF_ALG

/*
 * Runtime algorithm dictionary for AF_ALG fuzzing.
 *
 * Built once in the parent at startup by parsing /proc/crypto and merging
 * the result with the static fallback arrays in net/proto-alg.c.  The
 * dictionary is read-only post-init and inherited by every child via COW,
 * so no locking or shm placement is required.
 *
 * The 7 buckets correspond to the salg_type strings used in
 * alg_gen_sockaddr(): aead/hash/rng/skcipher/akcipher/kpp/sig.
 */
enum alg_dict_type {
	ALG_DICT_AEAD = 0,
	ALG_DICT_HASH,
	ALG_DICT_RNG,
	ALG_DICT_SKCIPHER,
	ALG_DICT_AKCIPHER,
	ALG_DICT_KPP,
	ALG_DICT_SIG,
	ALG_DICT_NR_TYPES,
};

void init_alg_template_dict(void);

/*
 * Returns a pointer to the names array for the given type and the
 * count of entries.  Names array may contain duplicates (used for
 * weighting interesting templates).  Returns NULL/0 if the dict is
 * empty for that type.
 */
const char **alg_dict_names(enum alg_dict_type type, unsigned int *count);

/*
 * Static-fallback accessor exported by net/proto-alg.c and consumed by
 * net/proto-alg-dict.c during the merge step.  Also used as a last-
 * resort fallback inside proto-alg.c if the dict bucket is empty.
 */
void alg_static_fallback_get(enum alg_dict_type type,
			     const char *const **arr, unsigned int *count);

#endif
