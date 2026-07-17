#ifndef _TRINITY_STATS_SUBSYS_KEYRING_SPAM_H
#define _TRINITY_STATS_SUBSYS_KEYRING_SPAM_H

/* keyring_spam childop counters */
struct keyring_spam_stats {
	unsigned long runs;	/* total keyring_spam invocations */
	unsigned long calls;	/* total add_key/keyctl ops attempted */
	unsigned long failed;	/* add_key/keyctl returned -1 */
};

#endif /* _TRINITY_STATS_SUBSYS_KEYRING_SPAM_H */
