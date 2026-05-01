#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "proto-alg-dict.h"
#include "trinity.h"

#ifdef USE_IF_ALG

struct alg_name_list {
	const char **names;
	unsigned int count;
	unsigned int cap;
};

static struct alg_name_list dict[ALG_DICT_NR_TYPES];
static bool dict_from_proc;

/* Map kernel /proc/crypto "type :" string to an alg_dict_type bucket.
 * Returns ALG_DICT_NR_TYPES (sentinel) for unknown types — caller skips. */
static enum alg_dict_type kernel_type_to_bucket(const char *t)
{
	if (strcmp(t, "aead") == 0)		return ALG_DICT_AEAD;
	if (strcmp(t, "skcipher") == 0)		return ALG_DICT_SKCIPHER;
	if (strcmp(t, "shash") == 0)		return ALG_DICT_HASH;
	if (strcmp(t, "ahash") == 0)		return ALG_DICT_HASH;
	if (strcmp(t, "rng") == 0)		return ALG_DICT_RNG;
	if (strcmp(t, "akcipher") == 0)		return ALG_DICT_AKCIPHER;
	if (strcmp(t, "kpp") == 0)		return ALG_DICT_KPP;
	if (strcmp(t, "sig") == 0)		return ALG_DICT_SIG;
	return ALG_DICT_NR_TYPES;
}

static bool list_contains(const struct alg_name_list *l, const char *name)
{
	unsigned int i;

	for (i = 0; i < l->count; i++)
		if (strcmp(l->names[i], name) == 0)
			return true;
	return false;
}

static void list_append(struct alg_name_list *l, const char *name)
{
	if (l->count == l->cap) {
		unsigned int newcap = l->cap ? l->cap * 2 : 32;
		const char **nn = realloc(l->names, newcap * sizeof(*nn));

		if (nn == NULL)
			return;
		l->names = nn;
		l->cap = newcap;
	}
	l->names[l->count++] = name;
}

/* Append name iff not already present.  Caller-owned string (already
 * strdup'd or string-literal). */
static void list_add_unique(struct alg_name_list *l, const char *name)
{
	if (list_contains(l, name))
		return;
	list_append(l, name);
}

/*
 * Strip leading whitespace and the "field :" prefix.  Returns a pointer
 * into the same buffer at the start of the value, or NULL if the line
 * is not a "<field> :" assignment for the given field name.
 */
static char *parse_field(char *line, const char *field)
{
	size_t flen = strlen(field);
	char *p = line;

	while (*p == ' ' || *p == '\t')
		p++;
	if (strncmp(p, field, flen) != 0)
		return NULL;
	p += flen;
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p != ':')
		return NULL;
	p++;
	while (*p == ' ' || *p == '\t')
		p++;
	return p;
}

static void rstrip(char *s)
{
	size_t n = strlen(s);

	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
			 s[n - 1] == ' ' || s[n - 1] == '\t')) {
		s[n - 1] = '\0';
		n--;
	}
}

/* Parse /proc/crypto.  Block boundary = blank line.  Per-block we capture
 * "name :" and "type :" — when both are seen, register name into the
 * appropriate bucket.  Unknown lines and unknown types are silently
 * skipped; never aborts on parse error. */
static void parse_proc_crypto(void)
{
	FILE *f = fopen("/proc/crypto", "r");
	char line[512];
	char cur_name[256] = "";
	char cur_type[64] = "";

	if (f == NULL)
		return;

	while (fgets(line, sizeof(line), f) != NULL) {
		char *val;

		rstrip(line);

		if (line[0] == '\0') {
			/* End of block — register if we have both fields. */
			if (cur_name[0] != '\0' && cur_type[0] != '\0') {
				enum alg_dict_type b = kernel_type_to_bucket(cur_type);

				if (b != ALG_DICT_NR_TYPES) {
					if (!list_contains(&dict[b], cur_name))
						list_append(&dict[b], strdup(cur_name));
					dict_from_proc = true;
				}
			}
			cur_name[0] = '\0';
			cur_type[0] = '\0';
			continue;
		}

		val = parse_field(line, "name");
		if (val != NULL) {
			strncpy(cur_name, val, sizeof(cur_name) - 1);
			cur_name[sizeof(cur_name) - 1] = '\0';
			continue;
		}
		val = parse_field(line, "type");
		if (val != NULL) {
			strncpy(cur_type, val, sizeof(cur_type) - 1);
			cur_type[sizeof(cur_type) - 1] = '\0';
			continue;
		}
		/* Other fields ignored. */
	}

	/* Flush trailing block if file didn't end with a blank line. */
	if (cur_name[0] != '\0' && cur_type[0] != '\0') {
		enum alg_dict_type b = kernel_type_to_bucket(cur_type);

		if (b != ALG_DICT_NR_TYPES) {
			if (!list_contains(&dict[b], cur_name))
				list_append(&dict[b], strdup(cur_name));
			dict_from_proc = true;
		}
	}

	fclose(f);
}

/* Merge static fallback arrays into the dict.  Entries already present
 * (from /proc/crypto) are skipped. */
static void merge_static_fallback(void)
{
	enum alg_dict_type t;

	for (t = 0; t < ALG_DICT_NR_TYPES; t++) {
		const char *const *arr = NULL;
		unsigned int n = 0, i;

		alg_static_fallback_get(t, &arr, &n);
		for (i = 0; i < n; i++)
			list_add_unique(&dict[t], arr[i]);
	}
}

/* Count parenthesis depth in a template name.  authenc(hmac(sha256),...)
 * has depth 2; gcm(aes) has depth 1. */
static unsigned int template_depth(const char *name)
{
	unsigned int d = 0, max = 0;

	for (; *name; name++) {
		if (*name == '(') {
			d++;
			if (d > max)
				max = d;
		} else if (*name == ')') {
			if (d > 0)
				d--;
		}
	}
	return max;
}

/* Apply weighting bias by appending duplicates of "structurally
 * interesting" entries.  The names array is read with a uniform random
 * index in alg_gen_sockaddr(), so duplicates raise the selection
 * probability proportionally. */
static void apply_bias(void)
{
	enum alg_dict_type t;

	for (t = 0; t < ALG_DICT_NR_TYPES; t++) {
		unsigned int orig = dict[t].count;
		unsigned int i;

		for (i = 0; i < orig; i++) {
			const char *n = dict[t].names[i];
			unsigned int extra = 0;

			if (strstr(n, "authencesn") || strstr(n, "rfc7539esp"))
				extra = 2;
			else if (template_depth(n) >= 2)
				extra = 1;

			while (extra--)
				list_append(&dict[t], n);
		}
	}
}

void init_alg_template_dict(void)
{
	parse_proc_crypto();
	merge_static_fallback();
	apply_bias();

	output(1, "alg dict: %u aead, %u hash, %u rng, %u skcipher, %u akcipher, %u kpp, %u sig (from %s)\n",
		dict[ALG_DICT_AEAD].count,
		dict[ALG_DICT_HASH].count,
		dict[ALG_DICT_RNG].count,
		dict[ALG_DICT_SKCIPHER].count,
		dict[ALG_DICT_AKCIPHER].count,
		dict[ALG_DICT_KPP].count,
		dict[ALG_DICT_SIG].count,
		dict_from_proc ? "/proc/crypto+fallback" : "fallback only");
}

const char **alg_dict_names(enum alg_dict_type type, unsigned int *count)
{
	if (type >= ALG_DICT_NR_TYPES) {
		*count = 0;
		return NULL;
	}
	*count = dict[type].count;
	return dict[type].names;
}

#endif /* USE_IF_ALG */
