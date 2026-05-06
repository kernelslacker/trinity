#pragma once

#include <limits.h>
#include <stdbool.h>
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

struct map * get_map(void);
struct map * get_map_with_prot(int required_prot);

/*
 * Slot-version handle for the lockless OBJ_GLOBAL maps-pool reader.
 *
 * get_map() narrows the destroy-vs-deref window to the few cycles
 * between its internal validate_object_handle() call and the caller's
 * first deref.  Consumers that hold the returned struct map * across
 * a longer window — multi-frame arg-gen paths, periodic dirty loops
 * that walk every page, iovec builders that draw many maps before
 * any syscall is issued — can reopen that window for the parent's
 * __destroy_object() to race in.  The handle bundles the picked
 * (map, owning obj, slot idx, slot version) so the consumer can
 * re-validate right before the deref via validate_map_handle() and
 * drop the slot rather than dereferencing a recycled obj.
 *
 * The map pointer is &owner->map; the owner is recovered via
 * container_of() inside validate_map_handle() and re-checked against
 * head->array[slot_idx] / head->slot_versions[slot_idx] using the
 * existing object-pool slot-version primitive.
 */
struct map_handle {
	struct map *map;
	enum objecttype type;
	enum obj_scope scope;
	unsigned int slot_idx;
	unsigned int slot_version;
};

bool get_map_handle(struct map_handle *h);
bool validate_map_handle(struct map_handle *h);

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
