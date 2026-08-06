#pragma once

/*
 * Private API shared between the utils/shared_mem*.c sibling files.
 * Not for use outside utils/shared_mem*.  Public API lives in
 * include/utils-mem.h.
 */

#include <stdbool.h>
#include <stddef.h>

/* Bitmap + size-bucket subsystem (utils/shared_mem_bitmap.c). */
void shared_bitmap_mark(unsigned long addr, unsigned long size);
void shared_bitmap_unmark(unsigned long addr, unsigned long size);
void tracked_size_mark(unsigned long len);
void tracked_size_unmark(unsigned long len);

#ifdef CONFIG_GUARD_SHARED
/* Guard-page debug mode (utils/shared_mem_guard.c). */
void *guard_pages_alloc(size_t size);
bool guard_scope_covers(bool is_pool);
void guard_pages_derive_span(void *ret, size_t size,
			     void **base_out, size_t *span_out);
#endif
