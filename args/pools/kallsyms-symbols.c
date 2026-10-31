/*
 * Kallsyms-derived kernel symbol pool for the kprobe_multi scalar
 * fill.  Built lazily from /proc/kallsyms on first use and read-only
 * after, following the kcov fingerprint's parse and filters: module
 * and runtime BPF symbols are skipped, only text symbols are kept.
 * kptr_restrict zeroes every address for an unprivileged reader, so
 * names and addresses are tracked separately -- an address-hidden
 * pool still yields resolvable names, and the addrs arm is offered
 * only when at least one nonzero address survived.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kallsyms-symbols.h"
#include "rnd.h"

#define KALLSYMS_SYMBOLS_CAP	4096U
#define KALLSYMS_LINE_MAX	4096

static struct kallsyms_symbol symbols[KALLSYMS_SYMBOLS_CAP];
static unsigned int num_symbols;
/* Nonzero addresses only, compacted: addr_pick() never draws 0
 * from a pool that has real addresses to give. */
static unsigned long long symbol_addrs[KALLSYMS_SYMBOLS_CAP];
static unsigned int num_symbol_addrs;
static bool symbols_built;

static void kallsyms_symbols_build(void)
{
	FILE *f;
	char line[KALLSYMS_LINE_MAX];

	if (symbols_built)
		return;
	symbols_built = true;

	f = fopen("/proc/kallsyms", "r");
	if (f == NULL)
		return;

	while (num_symbols < KALLSYMS_SYMBOLS_CAP &&
	       fgets(line, sizeof(line), f) != NULL) {
		char *p = line;
		char *end;
		unsigned long long addr;
		char type;
		const char *name;
		size_t len;
		char *copy;

		addr = strtoull(p, &end, 16);
		if (end == p)
			continue;
		p = end;
		while (*p == ' ' || *p == '\t')
			p++;
		/* Module symbols carry "[module]" and runtime BPF
		 * symbols vary per load: the same filters the kcov
		 * fingerprint applies, which must not see them. */
		if (strchr(p, '[') != NULL)
			continue;
		if (*p == '\0')
			continue;
		type = *p++;
		while (*p == ' ' || *p == '\t')
			p++;
		if (type != 'T' && type != 't' &&
		    type != 'W' && type != 'w')
			continue;
		name = p;
		len = strcspn(name, " \t\n");
		if (len == 0)
			continue;
		if ((len >= 9 && strncmp(name, "bpf_prog_", 9) == 0) ||
		    (len >= 15 && strncmp(name, "bpf_trampoline_", 15) == 0))
			continue;
		copy = strndup(name, len);
		if (copy == NULL)
			continue;
		symbols[num_symbols].name = copy;
		symbols[num_symbols].addr = addr;
		num_symbols++;
		if (addr != 0)
			symbol_addrs[num_symbol_addrs++] = addr;
	}
	(void) fclose(f);
}

bool kallsyms_symbols_have_names(void)
{
	kallsyms_symbols_build();
	return num_symbols > 0;
}

bool kallsyms_symbols_have_addrs(void)
{
	kallsyms_symbols_build();
	return num_symbol_addrs > 0;
}

const char *kallsyms_symbol_name_pick(void)
{
	if (!kallsyms_symbols_have_names())
		return NULL;
	return symbols[rnd_modulo_u32(num_symbols)].name;
}

unsigned long long kallsyms_symbol_addr_pick(void)
{
	if (!kallsyms_symbols_have_addrs())
		return 0;
	return symbol_addrs[rnd_modulo_u32(num_symbol_addrs)];
}

unsigned int kallsyms_symbols_count(void)
{
	kallsyms_symbols_build();
	return num_symbols;
}

const struct kallsyms_symbol *kallsyms_symbol_at(unsigned int i)
{
	kallsyms_symbols_build();
	if (i >= num_symbols)
		return NULL;
	return &symbols[i];
}
