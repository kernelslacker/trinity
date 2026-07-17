#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field keyring_spam_fields[] = {
	STAT_FIELD_SUB(keyring_spam, runs),
	STAT_FIELD_SUB(keyring_spam, calls),
	STAT_FIELD_SUB(keyring_spam, failed),
};

const struct stat_category keyring_spam_category =
	STAT_CATEGORY("keyring_spam",
	              keyring_spam.runs,
	              keyring_spam_fields);
