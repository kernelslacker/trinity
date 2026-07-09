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


#include <stdio.h>
#include <string.h>
#include "name-pool.h"
#include "random.h"
#include "rnd.h"
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

	switch (rnd_modulo_u32(3)) {
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
		buf[i] = (char)(rnd_u32() & 0xff);

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
			buf[i] = (char)(1 + rnd_modulo_u32(0x1f)); /* \x01-\x1f */
		else
			buf[i] = base[j++ % blen];
	}

	return buflen;
}

/*
 * cpu-list / bitmap-list strings.
 *
 * lib/bitmap.c's cpulist_parse() / bitmap_parselist() is a hand-rolled
 * parser used by sysfs cpumask writes, the cpuset cgroup files, and the
 * taskstats REGISTER_CPUMASK / DEREGISTER_CPUMASK netlink attributes.
 * It accepts comma-separated ranges ("0,2-5,7"), the literal "all", and
 * an optional ":used/group" stride suffix.  Random bytes fail at the
 * first non-digit, so without a content-aware producer those parsers
 * are effectively unreachable from a uniform fuzzer.
 *
 * The well-formed list mixes valid shapes with deliberately-fragile
 * inputs (reversed ranges, empty fields, lone separators, trailing
 * dashes, oversize cpu numbers, embedded whitespace) — the historical
 * crop of bitmap_parselist() bugs has clustered around exactly those
 * shapes.  Output is bounded by the caller's buflen; nothing here can
 * overrun the on-wire attribute cap.
 */
unsigned int gen_cpu_list_string(char *buf, unsigned int buflen)
{
	static const char * const variants[] = {
		"0",
		"0-1",
		"0-3",
		"0,2-5,7",
		"all",
		"1,3,5-9",
		"",
		",",
		"0,",
		",0",
		"5-2",                  /* reversed range */
		"0-99999",              /* range past nr_cpu_ids */
		"0--3",                 /* doubled dash */
		" 0 , 1 ",              /* embedded whitespace */
		"0-",                   /* dangling dash */
		"-3",                   /* leading dash */
		"4294967295",           /* UINT_MAX cpu index */
		"0-4095",
		"0-7:1/2",              /* stride suffix */
	};
	char scratch[128];
	const char *s;
	unsigned int n;

	if (buflen == 0)
		return 0;

	if (ONE_IN(3)) {
		/* Compose a fresh "a-b,c,d-e" of up to 4 parts. */
		unsigned int parts = RAND_RANGE(1, 4);
		unsigned int pos = 0;
		unsigned int i;

		for (i = 0; i < parts; i++) {
			unsigned int a = rnd_modulo_u32(4096);
			unsigned int avail;
			int wrote;

			if (i > 0) {
				if (pos + 1 >= sizeof(scratch))
					break;
				scratch[pos++] = ',';
			}
			avail = (unsigned int)sizeof(scratch) - pos;
			if (avail < 16)
				break;
			if (ONE_IN(2))
				wrote = snprintf(scratch + pos, avail, "%u-%u",
						 a, a + rnd_modulo_u32(32));
			else
				wrote = snprintf(scratch + pos, avail, "%u", a);
			if (wrote <= 0 || (unsigned int)wrote >= avail)
				break;
			pos += (unsigned int)wrote;
		}
		if (pos == 0) {
			scratch[0] = '0';
			pos = 1;
		}
		s = scratch;
		n = pos;
	} else {
		s = RAND_ARRAY(variants);
		n = (unsigned int)strlen(s);
	}

	n = cap(n, buflen);
	memcpy(buf, s, n);
	if (n < buflen)
		memset(buf + n, 0, buflen - n);
	return n;
}

/*
 * Per-kind stateful-name lane.
 *
 * The generators below produce shape-correct names for specific
 * kernel object kinds (netdev, key-desc, xattr-name, bpf-obj-name,
 * mq-name, netlink-table).  Each call either generates a fresh
 * random name AND records it into the per-kind ring of the shared
 * name pool, or -- on a minority arm (REUSE_DENOM-in-1 draws) --
 * pulls a previously-recorded name out of the pool with one of the
 * mutation ops in rand/name-pool.c (reuse-exactly, 1-byte-mutate,
 * truncate, case-flip, suffix-near-max).
 *
 * The mix is deliberately MINORITY for the reuse arm: the goal is
 * to ADD the stateful create-then-reference coverage arm without
 * collapsing fresh-random diversity to a small ring of repeating
 * names.  Diversity in fresh-random is what keeps the long tail of
 * one-shot parser paths exercised.
 *
 * REUSE_DENOM=4 → reuse arm fires on ~25% of draws, fresh-random
 * is the majority at ~75%.  Note that when the pool is empty for a
 * given kind (early in a child's life), the reuse arm falls back to
 * the fresh path -- so the effective reuse rate is below 25% during
 * pool warmup and asymptotes at 25% once filled.
 */
#define REUSE_DENOM 4

static unsigned int write_str(char *buf, unsigned int buflen,
			      const char *src, unsigned int srclen)
{
	unsigned int n = cap(srclen, buflen);

	memcpy(buf, src, n);
	return n;
}

static unsigned int gen_netdev_fresh(char *buf, unsigned int buflen)
{
	/* IFNAMSIZ is 16 (incl NUL); cap names at 15 bytes here. */
	static const char * const prefixes[] = {
		"eth", "lo", "veth", "tap", "br", "wlan",
		"tun", "bond", "vlan", "trinity", "mlx5_",
	};
	char scratch[16];
	const char *pfx = RAND_ARRAY(prefixes);
	int wrote;

	if (ONE_IN(2))
		wrote = snprintf(scratch, sizeof(scratch), "%s%u",
				 pfx, rnd_modulo_u32(10000));
	else
		wrote = snprintf(scratch, sizeof(scratch), "%s%x",
				 pfx, rnd_u32() & 0xffff);
	if (wrote <= 0)
		return 0;
	if ((size_t)wrote >= sizeof(scratch))
		wrote = (int)sizeof(scratch) - 1;

	name_pool_record(NAME_KIND_NETDEV, scratch, (size_t)wrote);
	return write_str(buf, buflen, scratch, (unsigned int)wrote);
}

static unsigned int gen_key_desc_fresh(char *buf, unsigned int buflen)
{
	static const char * const prefixes[] = {
		"trinity_key", "session_keyring", "user_session",
		"logon", "asymmetric_key", "trusted_blob",
		"user:", "system:",
	};
	char scratch[48];
	const char *pfx = RAND_ARRAY(prefixes);
	int wrote;

	if (ONE_IN(3))
		wrote = snprintf(scratch, sizeof(scratch), "%s:%u",
				 pfx, rnd_u32());
	else
		wrote = snprintf(scratch, sizeof(scratch), "%s_%x",
				 pfx, rnd_u32());
	if (wrote <= 0)
		return 0;
	if ((size_t)wrote >= sizeof(scratch))
		wrote = (int)sizeof(scratch) - 1;

	name_pool_record(NAME_KIND_KEY_DESC, scratch, (size_t)wrote);
	return write_str(buf, buflen, scratch, (unsigned int)wrote);
}

static unsigned int gen_xattr_name_fresh(char *buf, unsigned int buflen)
{
	static const char * const namespaces[] = {
		"user", "trusted", "security", "system",
	};
	static const char * const stems[] = {
		"test", "data", "attr", "blob", "tag", "marker",
	};
	char scratch[64];
	int wrote;

	wrote = snprintf(scratch, sizeof(scratch), "%s.%s_%x",
			 RAND_ARRAY(namespaces),
			 RAND_ARRAY(stems),
			 rnd_u32() & 0xffff);
	if (wrote <= 0)
		return 0;
	if ((size_t)wrote >= sizeof(scratch))
		wrote = (int)sizeof(scratch) - 1;

	name_pool_record(NAME_KIND_XATTR_NAME, scratch, (size_t)wrote);
	return write_str(buf, buflen, scratch, (unsigned int)wrote);
}

static unsigned int gen_bpf_obj_name_fresh(char *buf, unsigned int buflen)
{
	/* BPF_OBJ_NAME_LEN is 16 (incl NUL); produce at most 15 bytes. */
	static const char alphabet[] =
		"abcdefghijklmnopqrstuvwxyz0123456789_";
	char scratch[16];
	unsigned int n = 1 + rnd_modulo_u32(15);
	unsigned int i;

	for (i = 0; i < n; i++)
		scratch[i] = alphabet[rnd_modulo_u32(sizeof(alphabet) - 1)];

	name_pool_record(NAME_KIND_BPF_OBJ_NAME, scratch, n);
	return write_str(buf, buflen, scratch, n);
}

static unsigned int gen_mq_name_fresh(char *buf, unsigned int buflen)
{
	/* POSIX mq names start with '/' and contain no further slashes. */
	char scratch[32];
	int wrote;

	wrote = snprintf(scratch, sizeof(scratch), "/trinity_q_%x",
			 rnd_u32() & 0xffffff);
	if (wrote <= 0)
		return 0;
	if ((size_t)wrote >= sizeof(scratch))
		wrote = (int)sizeof(scratch) - 1;

	name_pool_record(NAME_KIND_MQ_NAME, scratch, (size_t)wrote);
	return write_str(buf, buflen, scratch, (unsigned int)wrote);
}

static unsigned int gen_netlink_table_fresh(char *buf, unsigned int buflen)
{
	/* nftables table names: short identifiers; max 32-ish. */
	static const char * const wellknown[] = {
		"filter", "nat", "mangle", "raw", "security",
	};
	char scratch[32];
	int wrote;

	if (ONE_IN(3)) {
		const char *w = RAND_ARRAY(wellknown);

		wrote = snprintf(scratch, sizeof(scratch), "%s", w);
	} else {
		wrote = snprintf(scratch, sizeof(scratch), "trinity_t_%x",
				 rnd_u32() & 0xffff);
	}
	if (wrote <= 0)
		return 0;
	if ((size_t)wrote >= sizeof(scratch))
		wrote = (int)sizeof(scratch) - 1;

	name_pool_record(NAME_KIND_NETLINK_TABLE, scratch,
			 (size_t)wrote);
	return write_str(buf, buflen, scratch, (unsigned int)wrote);
}

static unsigned int gen_kind(enum name_kind kind, char *buf,
			     unsigned int buflen)
{
	if (buflen == 0)
		return 0;

	/*
	 * Minority reuse arm: ~1-in-REUSE_DENOM draws try the pool.
	 * Empty-pool draws return 0 and we fall through to fresh.
	 */
	if (ONE_IN(REUSE_DENOM)) {
		size_t got = name_pool_draw_mutated(kind, buf, buflen);

		if (got > 0)
			return (unsigned int)got;
	}

	switch (kind) {
	case NAME_KIND_NETDEV:		return gen_netdev_fresh(buf, buflen);
	case NAME_KIND_KEY_DESC:	return gen_key_desc_fresh(buf, buflen);
	case NAME_KIND_XATTR_NAME:	return gen_xattr_name_fresh(buf, buflen);
	case NAME_KIND_BPF_OBJ_NAME:	return gen_bpf_obj_name_fresh(buf, buflen);
	case NAME_KIND_MQ_NAME:		return gen_mq_name_fresh(buf, buflen);
	case NAME_KIND_NETLINK_TABLE:	return gen_netlink_table_fresh(buf, buflen);
	case NAME_KIND__MAX:		break;
	}
	return 0;
}

/*
 * Pick a kind uniformly and produce a name for it.  Bridges the
 * per-kind lane into the gen_text_payload() dispatcher used by
 * generic ARG_STRING fuzzing so the stateful arm runs regardless of
 * which syscall is currently selected; per-kind tagging in the pool
 * itself prevents cross-kind contamination on the reuse side.
 */
static unsigned int gen_pool_name(char *buf, unsigned int buflen)
{
	enum name_kind k = (enum name_kind)rnd_modulo_u32(NAME_KIND__MAX);

	return gen_kind(k, buf, buflen);
}

/* Pick one of the above generators at random. */
unsigned int gen_text_payload(char *buf, unsigned int buflen)
{
	switch (rnd_modulo_u32(9)) {
	case 0: return gen_long_string(buf, buflen);
	case 1: return gen_embedded_nul(buf, buflen);
	case 2: return gen_format_string_attack(buf, buflen);
	case 3: return gen_valid_prefix_garbage(buf, buflen);
	case 4: return gen_numeric_boundary_string(buf, buflen);
	case 5: return gen_path_traversal(buf, buflen);
	case 6: return gen_cpu_list_string(buf, buflen);
	case 7: return gen_pool_name(buf, buflen);
	default: return gen_binary_control_chars(buf, buflen);
	}
}
