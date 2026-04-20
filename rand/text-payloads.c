/*
 * Content-aware text payload generators for kernel string-parser fuzzing.
 *
 * Kernel interfaces (sysfs, procfs, tracefs, debugfs) contain hundreds of
 * hand-written parsers.  A uniform random byte stream fails immediately on
 * the first character for most of them, never reaching the deeper branches
 * where bugs live.  These generators produce inputs that look plausible
 * enough to pass early validation: long repeated-character runs that can
 * overflow fixed buffers, embedded NULs that confuse strlen-based parsers,
 * format specifiers that trigger printf misuse, numeric boundary values that
 * exercise overflow and sign-extension paths, and so on.
 */

#include <stdlib.h>
#include <string.h>

#include "random.h"
#include "text-payloads.h"
#include "utils.h"

static unsigned int cap(unsigned int n, unsigned int buflen)
{
	return n < buflen ? n : buflen;
}

/*
 * Fill buf with a single repeated character class.
 *
 * Three classes exercise different parser assumptions: pure alpha triggers
 * strtoul failures at byte 0; pure digits look like valid numbers and reach
 * deeper into numeric parsers; repeating multi-byte UTF-8 sequences stress
 * parsers that walk by byte without understanding encoding.
 */
unsigned int gen_long_string(char *buf, unsigned int buflen)
{
	unsigned int i;

	if (buflen == 0)
		return 0;

	switch (rand() % 3) {
	case 0:
		memset(buf, 'A', buflen);
		break;
	case 1:
		for (i = 0; i < buflen; i++)
			buf[i] = '0' + (i % 10);
		break;
	default:
		/* Repeating 2-byte UTF-8 sequence U+00C0 (0xC3 0x80). */
		for (i = 0; i < buflen; i++)
			buf[i] = (i & 1) ? (char)0x80 : (char)0xC3;
		break;
	}

	return buflen;
}

/*
 * Embed a NUL mid-stream: 'A' * 100 + NUL + 'B' * 100.
 *
 * Parsers that compute length via strlen() before passing the buffer to a
 * kernel API will silently truncate at the NUL; parsers that use the
 * explicitly supplied length will see both halves.  The mismatch has
 * historically caused off-by-one reads and double-fetch bugs.
 */
unsigned int gen_embedded_nul(char *buf, unsigned int buflen)
{
	unsigned int a, b, total;

	a = cap(100, buflen);
	memset(buf, 'A', a);

	if (a < buflen) {
		buf[a] = '\0';
		b = cap(100, buflen - a - 1);
		memset(buf + a + 1, 'B', b);
		total = a + 1 + b;
	} else {
		total = a;
	}

	return total;
}

/*
 * Printf-style format specifiers.
 *
 * A kernel driver that accidentally passes user data as the format argument
 * to printk / seq_printf / sprintf-family interprets these as format strings.
 * Kernel printk dropped %n support years ago (commit f2d5dcb48f7b "vsprintf:
 * remove %n handling", v5.2), so the classic write-where primitive is inert
 * against modern kernels — focus on the surfaces that ARE still processed:
 * %s with bogus pointers (kernel uses pgtable check + zero-substitution but
 * the path is still reachable), %p extended specifiers (%pS, %pK, %pV, %pa),
 * and excessive padding/precision fields that exercise the formatter's
 * length math.
 */
unsigned int gen_format_string_attack(char *buf, unsigned int buflen)
{
	static const char * const payloads[] = {
		"%s%s%s%s%s%s%s%s%s%s",
		"%d%d%d%d%d%d%d%d%d%d",
		"%p%p%p%p%p%p%p%p%p%p",
		"%pS%pS%pS%pS%pS",          /* symbol resolution */
		"%pK%pK%pK%pK%pK",          /* kernel-pointer hash */
		"%pV",                       /* struct vsprintf args — funky path */
		"%pa%pa%pa%pa",             /* phys_addr_t */
		"%%",
		"%x%x%x%x%x%x%x%x%x%x",
		"AAAA%08x%08x%08x%08x",
		"%99999999d",                /* width math overflow */
		"%.99999999d",               /* precision math overflow */
		"%0*d",                      /* * width consumed from arg list */
		"%2147483647s",              /* INT_MAX width */
	};
	const char *s = RAND_ARRAY(payloads);
	unsigned int n = cap((unsigned int)strlen(s), buflen);

	memcpy(buf, s, n);
	return n;
}

/*
 * Valid-looking prefix followed by random garbage.
 *
 * Parsers that validate a prefix (numeric, hex, keyword) and then continue
 * reading the rest of the buffer unsafely are the target.  kstrtol and
 * simple_strtoul, for example, stop at the first invalid character — but
 * custom parsers built on top of them may not.
 */
unsigned int gen_valid_prefix_garbage(char *buf, unsigned int buflen)
{
	static const char * const prefixes[] = {
		"1234567890",
		"deadbeef\n",
		"0x1234",
		"-1",
		"0",
		"4294967295",
		"0xffffffffffffffff",
	};
	const char *pfx = RAND_ARRAY(prefixes);
	unsigned int plen = cap((unsigned int)strlen(pfx), buflen);
	unsigned int i;

	memcpy(buf, pfx, plen);
	for (i = plen; i < buflen; i++)
		buf[i] = (char)(rand() & 0xff);

	return buflen;
}

/*
 * Integer boundary values.
 *
 * kstrtol, kstrtoull, and simple_strtol have well-known edge cases around
 * INT_MAX, LLONG_MAX, overflow by one, leading zeros, invalid sign prefixes,
 * trailing whitespace, and scientific notation.  Kernel parsers that roll
 * their own numeric decoding are especially likely to mis-handle these.
 */
unsigned int gen_numeric_boundary_string(char *buf, unsigned int buflen)
{
	static const char * const values[] = {
		"2147483647",           /* INT_MAX */
		"-2147483648",          /* INT_MIN */
		"2147483648",           /* INT_MAX + 1 */
		"-1",
		"0",
		"000",                  /* leading zeros */
		"+-1",                  /* invalid sign prefix */
		"1e308",                /* scientific notation */
		"18446744073709551615", /* ULLONG_MAX */
		"9223372036854775808",  /* LLONG_MAX + 1 */
		"-9223372036854775809", /* LLONG_MIN - 1 */
		"1 ",                   /* trailing space */
		" 1",                   /* leading space */
	};
	const char *s = RAND_ARRAY(values);
	unsigned int n = cap((unsigned int)strlen(s), buflen);

	memcpy(buf, s, n);
	return n;
}

/*
 * Path traversal sequences.
 *
 * Kernel interfaces that interpret user-supplied strings as paths — sysfs
 * attribute writes, debugfs file names, cgroup path components — may be
 * vulnerable to escape attempts.  These strings are more useful for driving
 * the parser into unusual code paths than for actual traversal (the kernel
 * checks are robust), but a parser bug that evaluates even one more component
 * before rejecting can expose a UAF or OOB.
 */
unsigned int gen_path_traversal(char *buf, unsigned int buflen)
{
	static const char * const paths[] = {
		"../../../etc/passwd",
		"//../foo",
		"../../../../../../../../etc/shadow",
		"/proc/self/mem",
		"//proc//self",
		"..%2f..%2fetc%2fpasswd",
		"/sys/../proc/sysrq-trigger",
		"..\\..\\..\\windows\\system32",
	};
	const char *s = RAND_ARRAY(paths);
	unsigned int n = cap((unsigned int)strlen(s), buflen);

	memcpy(buf, s, n);
	return n;
}

/*
 * ASCII text with binary control characters mixed in.
 *
 * Parsers that walk input byte-by-byte and branch on character class may
 * behave unexpectedly when control characters appear in positions they do not
 * anticipate (e.g., a \x01 inside a function name, or \x0c in a numeric
 * field).  This generator produces the kind of semi-printable garbage that
 * protocol fuzzers routinely surface.
 */
unsigned int gen_binary_control_chars(char *buf, unsigned int buflen)
{
	static const char base[] = "hello world test string";
	unsigned int blen = sizeof(base) - 1;
	unsigned int i, j = 0;

	for (i = 0; i < buflen; i++) {
		if (ONE_IN(4))
			buf[i] = (char)(1 + (rand() % 0x1f)); /* \x01-\x1f */
		else
			buf[i] = base[j++ % blen];
	}

	return buflen;
}

/* Pick one of the above generators at random. */
unsigned int gen_text_payload(char *buf, unsigned int buflen)
{
	switch (rand() % 7) {
	case 0: return gen_long_string(buf, buflen);
	case 1: return gen_embedded_nul(buf, buflen);
	case 2: return gen_format_string_attack(buf, buflen);
	case 3: return gen_valid_prefix_garbage(buf, buflen);
	case 4: return gen_numeric_boundary_string(buf, buflen);
	case 5: return gen_path_traversal(buf, buflen);
	default: return gen_binary_control_chars(buf, buflen);
	}
}
