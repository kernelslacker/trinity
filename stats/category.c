#include "shm.h"
#include "stats-internal.h"

/*
 * Descriptor-table form for stat categories whose JSON / text emit shape
 * is "object name + N (field, value) scalar pairs".  Each category lists
 * its fields once; the JSON walker and the text walker iterate the same
 * descriptor so a new counter is added by declaring the struct member and
 * appending one STAT_FIELD() row -- the JSON key is derived from the
 * field-name suffix so the schema cannot drift from the struct.
 *
 * Generalises the in-tree pattern already used by periodic_counter_rates[] for
 * the periodic-window dump; here it replaces correlated edits in
 * struct stats_s + dump_stats_json() + dump_stats() with a single edit
 * site per counter.
 */
unsigned long stat_field_load(const struct stat_field *f)
{
	unsigned long *p = (unsigned long *)((char *)&shm->stats + f->offset);
	return __atomic_load_n(p, __ATOMIC_RELAXED);
}

static unsigned long stat_gate_load(const struct stat_category *cat)
{
	unsigned long *p = (unsigned long *)((char *)&shm->stats + cat->gate_offset);
	return __atomic_load_n(p, __ATOMIC_RELAXED);
}

/*
 * Emit one category as text rows.  Mirrors the existing
 * "if (shm->stats.<gate>) { stat_row(...); ... }" idiom: when the gate
 * counter is zero the whole block is suppressed so quiet runs stay terse.
 */
void stat_category_emit_text(const struct stat_category *cat)
{
	size_t i;

	if (stat_gate_load(cat) == 0)
		return;
	for (i = 0; i < cat->n_fields; i++)
		stat_row(cat->name, cat->fields[i].name,
		         stat_field_load(&cat->fields[i]));
}
