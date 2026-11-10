/*
 * Self-check for generate_rand_bytes() (rand/random-page.c): whichever arm
 * a call takes, it writes every one of the len bytes it is handed, which
 * ARG_BUF_SIZED's fresh buffers count on.  The rest of the test binary
 * takes genl_ops_test.c's fake; this check reaches the real generator
 * through the name --wrap leaves it.
 */

#include <string.h>

#include "debug.h"		/* BUG */

void __real_generate_rand_bytes(unsigned char *ptr, unsigned int len);

#define CALLS		20000
#define MAX_LEN		200

/* A byte the arms rarely write: not text, and not 0, 1 or 0xff. */
#define SENTINEL	0xa5

void rand_bytes_self_check(void);
void rand_bytes_self_check(void)
{
	static unsigned char buf[MAX_LEN];
	unsigned int i, kept = 0;

	for (i = 0; i < CALLS; i++) {
		unsigned int len = 1 + i % MAX_LEN;

		memset(buf, SENTINEL, len);
		__real_generate_rand_bytes(buf, len);
		kept += buf[len - 1] == SENTINEL;
	}
	if (kept > CALLS / 50)
		BUG("rand bytes: the end of a buffer was left unwritten");
}
