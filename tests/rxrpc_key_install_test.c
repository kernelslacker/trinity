/*
 * Self-check for rxrpc_key_install's XDR ticket arms: add_key() is
 * answered by a model of rxrpc_preparse_xdr()'s walk of the token
 * wrappers and of the rxkad and yfs-rxgk parsers' length checks
 * (net/rxrpc/key.c).  Every token the two arms build gets past the walk
 * to its parser, and each length check the arms aim at is met there.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>

#include "child.h"		/* struct childdata */
#include "child-api.h"		/* rxrpc_key_install, CHILD_OP_RXRPC_KEY_INSTALL */
#include "debug.h"		/* BUG */
#include "kcov-api.h"		/* childop_cmp_reset, childop_cmp_collect */
#include "childop-cmp.h"	/* childop_cmp_value */

extern bool (*fake_syscall)(long number, const unsigned long a[6], long *ret);	/* landlock_test.c */

/* include/keys/rxrpc-type.h */
#define AFSTOKEN_LENGTH_MAX	16384
#define AFSTOKEN_CELL_MAX	64
#define AFSTOKEN_MAX		8
#define AFSTOKEN_RK_TIX_MAX	12000
#define AFSTOKEN_GK_KEY_MAX	64
#define AFSTOKEN_GK_TOKEN_MAX	16384

/* Tokens each arm builds before it is judged. */
#define TOKENS	256

static unsigned int rxkad_tokens, rxkad_tix_max, rxkad_overclaim, rxkad_accepted;
static unsigned int rxgk_tokens, rxgk_key_max, rxgk_token_max, rxgk_past;

/* kcov/enable.c and cmp_hints/childop_consume.c are not linked: no
 * comparison is collected, and every field commits its draw. */
void childop_cmp_reset(struct kcov_child *kc)
{
	(void) kc;
}

void childop_cmp_collect(struct kcov_child *kc, unsigned int nr)
{
	(void) kc;
	(void) nr;
}

unsigned long childop_cmp_value(unsigned int nr, enum cmp_hint_use use,
				unsigned long old, unsigned long fallback)
{
	(void) nr;
	(void) use;
	(void) old;
	return fallback;
}

static uint32_t be32(const uint8_t *p)
{
	uint32_t v;

	memcpy(&v, p, sizeof(v));
	return ntohl(v);
}

/*
 * rxrpc_preparse() and rxrpc_preparse_xdr()'s walk of the wrappers: the
 * first token's body past its sec_ix, with the length its parser is
 * handed in *toklen, or NULL for a payload turned away as not XDR.  The
 * arms write ASCII cell names, where the C locale's isprint() agrees
 * with the kernel's.
 */
static const uint8_t *xdr_walk(const uint8_t *xdr, size_t datalen,
			       uint32_t *sec_ix, uint32_t *toklen)
{
	const uint8_t *p, *first = NULL;
	uint32_t len, paddedlen, ntoken, i;

	if (datalen <= 7 * 4 || datalen > AFSTOKEN_LENGTH_MAX || (datalen & 3))
		return NULL;
	if (be32(xdr) != 0)
		return NULL;
	len = be32(xdr + 4);
	datalen -= 8;
	if (len < 1 || len > AFSTOKEN_CELL_MAX)
		return NULL;
	paddedlen = (len + 3) & ~3U;
	if (paddedlen > datalen)
		return NULL;
	for (i = 0; i < len; i++)
		if (!isprint(xdr[8 + i]))
			return NULL;
	for (; i < paddedlen; i++)
		if (xdr[8 + i] != 0)
			return NULL;
	datalen -= paddedlen;
	p = xdr + 8 + paddedlen;

	if (datalen < 12)
		return NULL;
	ntoken = be32(p);
	p += 4;
	datalen -= 4;
	if (ntoken < 1 || ntoken > AFSTOKEN_MAX)
		return NULL;
	for (i = 0; i < ntoken; i++) {
		uint32_t tl;

		if (datalen < 8)
			return NULL;
		tl = be32(p);
		datalen -= 4;
		paddedlen = (tl + 3) & ~3U;
		if (tl < 20 || tl > datalen || paddedlen > datalen)
			return NULL;
		if (i == 0) {
			*sec_ix = be32(p + 4);
			*toklen = tl - 4;
			first = p + 8;
		}
		datalen -= paddedlen;
		p += 4 + paddedlen;
	}
	return datalen == 0 ? first : NULL;
}

/* rxrpc_preparse_xdr_rxkad()'s length checks. */
static void rxkad_checks(const uint8_t *xdr, uint32_t toklen)
{
	uint32_t tktlen;

	if (toklen <= 8 * 4)
		return;
	tktlen = be32(xdr + 7 * 4);
	if (tktlen > AFSTOKEN_RK_TIX_MAX)
		rxkad_tix_max++;
	else if (toklen < 8 * 4 + tktlen)
		rxkad_overclaim++;
	else
		rxkad_accepted++;
}

/* rxrpc_preparse_xdr_yfs_rxgk()'s length checks. */
static void rxgk_checks(const uint8_t *xdr, uint32_t toklen)
{
	uint32_t raw_keylen, keylen, raw_tktlen, tktlen;

	if (6 * 2 + 2 > toklen / 4)
		return;
	raw_keylen = be32(xdr + 6 * 2 * 4);
	if (raw_keylen > AFSTOKEN_GK_KEY_MAX) {
		rxgk_key_max++;
		return;
	}
	keylen = (raw_keylen + 3) & ~3U;
	if ((6 * 2 + 2) * 4 + keylen > toklen)
		return;
	raw_tktlen = be32(xdr + (6 * 2 + 1) * 4 + keylen);
	if (raw_tktlen > AFSTOKEN_GK_TOKEN_MAX) {
		rxgk_token_max++;
		return;
	}
	tktlen = (raw_tktlen + 3) & ~3U;
	if ((6 * 2 + 2) * 4 + keylen + tktlen == toklen)
		rxgk_past++;
}

/* add_key() and keyctl() stand-in: no key is ever made, so the op's
 * ring of serials stays empty and its teardown sends nothing. */
static bool answer_syscall(long number, const unsigned long a[6], long *ret)
{
	const char *desc = (const char *) a[1];
	const uint8_t *body;
	uint32_t sec_ix, toklen;
	bool rxkad;

	if (number == __NR_keyctl) {
		*ret = -EINVAL;
		return true;
	}
	if (number != __NR_add_key)
		return false;
	*ret = -EKEYREJECTED;

	if (strncmp(desc, "trinity-rxrpc-xrxkad-", 21) == 0)
		rxkad = true;
	else if (strncmp(desc, "trinity-rxrpc-xrxgk-", 20) == 0)
		rxkad = false;
	else
		return true;

	body = xdr_walk((const uint8_t *) a[2], a[3], &sec_ix, &toklen);
	if (body == NULL)
		BUG("rxrpc_key_install: a ticket arm's token was turned away as not XDR");
	if (rxkad) {
		if (sec_ix != 2)
			BUG("rxrpc_key_install: an rxkad token carried another sec_ix");
		rxkad_tokens++;
		rxkad_checks(body, toklen);
	} else {
		if (sec_ix != 6)
			BUG("rxrpc_key_install: an rxgk token carried another sec_ix");
		rxgk_tokens++;
		rxgk_checks(body, toklen);
	}
	return true;
}

void rxrpc_key_install_self_check(void);
void rxrpc_key_install_self_check(void)
{
	static struct childdata child;
	unsigned int runs;

	child.op_type = CHILD_OP_RXRPC_KEY_INSTALL;
	fake_syscall = answer_syscall;
	for (runs = 0; runs < 1024 &&
	     (rxkad_tokens < TOKENS || rxgk_tokens < TOKENS); runs++)
		rxrpc_key_install(&child);
	fake_syscall = NULL;

	if (rxkad_tokens < TOKENS || rxgk_tokens < TOKENS)
		BUG("rxrpc_key_install: too few ticket-arm tokens to judge by");
	if (rxkad_tix_max == 0 || rxkad_overclaim == 0 || rxkad_accepted == 0)
		BUG("rxrpc_key_install: an rxkad ticket check went unmet");
	if (rxgk_key_max == 0 || rxgk_token_max == 0 || rxgk_past == 0)
		BUG("rxrpc_key_install: an rxgk length check went unmet");
}
