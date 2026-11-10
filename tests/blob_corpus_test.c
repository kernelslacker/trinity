/*
 * Self-check for blob_corpus_try_get_base() (args/pools/blob_corpus.c):
 * it says how many bytes of a stored base it copied, so blob_fill() can
 * fill the rest of a longer request, and touches nothing past them.
 */

#include <stdbool.h>
#include <string.h>

#include "blob_corpus.h"
#include "debug.h"		/* BUG */

#define NR		5
#define BASE_LEN	10
#define SENTINEL	0xa5

void blob_corpus_self_check(void);
void blob_corpus_test_self_check(void);
void blob_corpus_test_self_check(void)
{
	static const unsigned char base[BASE_LEN] = "productive";
	unsigned char buf[100];
	size_t i;

	blob_corpus_init();
	blob_corpus_stash_pending(NR, false, base, sizeof(base));
	blob_corpus_promote_pending();

	memset(buf, SENTINEL, sizeof(buf));
	if (blob_corpus_try_get_base(NR, false, buf, sizeof(buf)) != BASE_LEN)
		BUG("blob corpus: a short base did not say how much it copied");
	if (memcmp(buf, base, BASE_LEN) != 0)
		BUG("blob corpus: a base came back changed");
	for (i = BASE_LEN; i < sizeof(buf); i++)
		if (buf[i] != SENTINEL)
			BUG("blob corpus: a base was copied past its length");

	if (blob_corpus_try_get_base(NR, false, buf, 4) != 4)
		BUG("blob corpus: a short request did not say it took four bytes");
	if (blob_corpus_try_get_base(NR, true, buf, sizeof(buf)) != 0 ||
	    blob_corpus_try_get_base(NR + 1, false, buf, sizeof(buf)) != 0)
		BUG("blob corpus: a key with no base copied something");

	blob_corpus_self_check();
}
