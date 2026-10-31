/*
 * Kallsyms-derived kernel symbol pool: text-symbol names and
 * addresses for the kprobe_multi scalar fill.
 */

#pragma once

#include <stdbool.h>

/* One /proc/kallsyms entry the pool kept.  addr is 0 when
 * kptr_restrict hid the addresses; the name is still usable. */
struct kallsyms_symbol {
	const char *name;
	unsigned long long addr;
};

/* True when the pool holds at least one name / one nonzero address.
 * Both build the pool on first call.  Side-effect-free after that,
 * so the fill's xor check can probe them without consuming a draw. */
bool kallsyms_symbols_have_names(void);
bool kallsyms_symbols_have_addrs(void);

/* One random name / nonzero address from the pool, or NULL / 0 when
 * the pool is empty (unreadable kallsyms, no text symbols kept). */
const char *kallsyms_symbol_name_pick(void);
unsigned long long kallsyms_symbol_addr_pick(void);

/* Pool introspection for the bpf_gen self-check: how many entries
 * the pool holds, and the entry at an index (NULL past the end). */
unsigned int kallsyms_symbols_count(void);
const struct kallsyms_symbol *kallsyms_symbol_at(unsigned int i);
