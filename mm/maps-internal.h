#pragma once

/*
 * Private declarations shared between the source-split
 * mm/maps-*.c pieces (pick, lifecycle).  Public API stays in
 * include/maps.h.
 */

#include "object-types.h"

/*
 * Seed an OBJ_LOCAL OBJ_MMAP_* pool from the matching OBJ_GLOBAL snapshot.
 * Called from init_child_mappings() (lifecycle) at fork and from
 * maybe_refill_local_anon_pool() (pick) on OBJ_LOCAL ANON exhaustion.
 * Not part of the public maps.h surface -- only the two mm/maps-*.c
 * pieces are expected to reach it.
 */
void clone_global_mmap_pool(enum objecttype type);
