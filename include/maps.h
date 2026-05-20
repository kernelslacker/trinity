#pragma once

#include <limits.h>
#include <stdbool.h>
#include "compiler.h"
#include "types.h"
#include "list.h"
#include "object-types.h"

#define INITIAL_ANON 1
#define CHILD_ANON 2
#define MMAPED_FILE 3

#define MAPS_NAME_MAX_LEN PATH_MAX

struct map {
	void *ptr;
	char *name;
	unsigned long size;
	int prot;
	int flags;
	int fd;
	unsigned char type;
};

extern unsigned int num_initial_mappings;
extern struct map *initial_mappings;

#define NR_MAPPING_SIZES 9
extern unsigned long mapping_sizes[NR_MAPPING_SIZES];

struct object;
void map_destructor(struct object *obj);
void map_destructor_shared(struct object *obj);
void map_dump(struct object *obj, enum obj_scope scope);

void setup_initial_mappings(void);

struct map * get_map(void) __must_check;
struct map * get_map_with_prot(int required_prot) __must_check;

/*
 * Lightweight handle for an entry in the OBJ_MMAP_* pools.  Post-
 * Stage-5 every pool lives in private heap so there is no concurrent
 * destroyer to coordinate with; validate_map_handle() collapses to a
 * NULL check.  Kept as a thin wrapper rather than inlining so callers
 * that already pass a handle around (multi-frame arg-gen paths,
 * iovec builders) don't need to change shape.
 */
struct map_handle {
	struct map *map;
	enum objecttype type;
	enum obj_scope scope;
};

bool get_map_handle(struct map_handle *h) __must_check;
bool validate_map_handle(struct map_handle *h) __must_check;

/*
 * Process-local ownership validator for runtime mmap() results.
 * Walks the current child's OBJ_LOCAL OBJ_MMAP_* pool and returns true
 * iff [addr, addr+len) is fully contained in at least one runtime
 * mapping the child created itself (CHILD_ANON / MMAPED_FILE entries
 * seeded by post_mmap()).  Used by get_writable_address() as a
 * second-chance acceptance test when range_in_tracked_shared() rejects:
 * runtime mmap results are not registered in shared_regions[] (which
 * exists for self-protection of trinity bookkeeping), so the global
 * tracker cannot validate them.
 *
 * INITIAL_ANON OBJ_LOCAL entries alias the global initial-mapping ptrs
 * and are already covered by range_in_tracked_shared(); this helper
 * intentionally skips them so the two acceptance paths stay disjoint.
 */
bool addr_in_local_runtime_map(unsigned long addr, unsigned long len) __must_check;

struct map * common_set_mmap_ptr_len(void);

void dirty_mapping(struct map *map);
void dirty_random_mapping(void);

struct faultfn {
	void (*func)(struct map *map);
};

void random_map_readfn(struct map *map);
void random_map_writefn(struct map *map);

unsigned long get_rand_mmap_flags(void);

void mmap_fd(int fd, const char *name, size_t len, int prot, enum obj_scope scope, enum objecttype type);

bool proc_maps_check(unsigned long addr, unsigned long len,
		     int expected_prot, bool expect_present);
