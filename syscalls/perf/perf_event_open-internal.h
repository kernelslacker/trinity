/*
 * perf_event_open-internal.h
 *
 * Shared declarations split out of syscalls/perf_event_open.c so the
 * sysfs PMU enumerator and the tracefs tracepoint-id pool builder
 * (scan_pmu_*, iter_pmu_dir, init_pmus, scan_tracepoint_*,
 * init_tracepoint_ids) can live in their own translation unit and
 * compile in parallel with the perf_event_attr randomizer, the
 * sanitise / post / cleanup hooks and the syscall dispatch table.
 * This header is private to the two TUs that make up perf_event_open
 * -- do not include it from anywhere else.
 *
 * Contents:
 *   - the struct generic_event_type / format_type / pmu_type triple
 *     shared between the discovery side (writes pmus[]) and the
 *     randomizer side (random_sysfs_config reads pmus[]);
 *   - the FIELD_* tags those structs encode;
 *   - extern declarations for the pmus[] / num_pmus pair owned by the
 *     discovery TU (already external-linkage in the pre-split file --
 *     the leading comment there records they're "not static so other
 *     tools can access the PMU data", and this header just makes that
 *     access typed for the in-tree caller);
 *   - a forward declaration for init_pmus(), deliberately widened
 *     from file-static to external linkage so syscall_perf_event_open
 *     .init in perf_event_open.c can still take its address across
 *     the TU boundary.  random_tracepoint_config() is already declared
 *     in include/perf.h (for struct_catalog.c's FT_PICKER) so it is
 *     not redeclared here.
 */

#ifndef SYSCALLS_PERF_EVENT_OPEN_INTERNAL_H
#define SYSCALLS_PERF_EVENT_OPEN_INTERNAL_H

struct generic_event_type {
	const char *name;
	const char *value;
	long long config;
	long long config1;
	long long config2;
};

struct format_type {
	const char *name;
	const char *value;
	int field;
	unsigned long long mask;
};

struct pmu_type {
	const char *name;
	int type;
	int num_formats;
	int num_generic_events;
	struct format_type *formats;
	struct generic_event_type *generic_events;
};

/* Not static so other tools can access the PMU data */
extern int num_pmus;
extern struct pmu_type *pmus;


#define FIELD_UNKNOWN	0
#define FIELD_CONFIG	1
#define FIELD_CONFIG1	2
#define FIELD_CONFIG2	3
#define MAX_FIELDS	4

int init_pmus(void);

#endif /* SYSCALLS_PERF_EVENT_OPEN_INTERNAL_H */
