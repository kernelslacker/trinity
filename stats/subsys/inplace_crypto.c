#include <stddef.h>
#include "stats-internal.h"

/* inplace_crypto_mutated: the inplace-crypto oracle childop overwrites a
 * plaintext slot mid-flight to catch handlers that read after the kernel
 * has copied; the per-mutation bump is the only positive signal that the
 * oracle ran productively in a window.  A single-field category renders
 * it in both JSON and text so a quiet "no mutations" window is
 * distinguishable from a window where the childop never fired. */
static const struct stat_field inplace_crypto_fields[] = {
	STAT_FIELD_SUB(inplace_crypto, mutated),
};

const struct stat_category inplace_crypto_category =
	STAT_CATEGORY("inplace_crypto",
	              inplace_crypto.mutated,
	              inplace_crypto_fields);
