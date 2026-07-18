#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field af_alg_weak_cipher_probe_fields[] = {
	STAT_FIELD_SUB(af_alg_weak_cipher_probe, runs),
	STAT_FIELD_SUB(af_alg_weak_cipher_probe, socket_failed),
	STAT_FIELD_SUB(af_alg_weak_cipher_probe, total_bind_attempts),
	STAT_FIELD_SUB(af_alg_weak_cipher_probe, total_bind_accepted),
	STAT_FIELD_SUB(af_alg_weak_cipher_probe, weak_accepted_total),
	STAT_FIELD_SUB(af_alg_weak_cipher_probe, setkey_accepted_total),
	STAT_FIELD_SUB(af_alg_weak_cipher_probe, skcipher_weak_accepted),
	STAT_FIELD_SUB(af_alg_weak_cipher_probe, aead_weak_accepted),
	STAT_FIELD_SUB(af_alg_weak_cipher_probe, hash_weak_accepted),
	STAT_FIELD_SUB(af_alg_weak_cipher_probe, strong_rejected),
};

const struct stat_category af_alg_weak_cipher_probe_category =
	STAT_CATEGORY("af_alg_weak_cipher_probe",
	              af_alg_weak_cipher_probe.runs,
	              af_alg_weak_cipher_probe_fields);
