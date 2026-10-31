/*
 * Per-element scalar fill for FT_PTR_ARRAY: an annotation carrying
 * elem_pick / elem_str_pick must fill every element from its source
 * (distinct when elem_unique asks), an empty string source must leave
 * NULL elements, no source must keep the zero fill, and an xor pair
 * must roll toward the side whose source reports values available.
 * Synthetic field tables drive struct_fill_passes() directly, as
 * struct_field_bounds_test.c does; no sanitiser runs.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args-internal.h"
#include "debug.h"		/* BUG_ON */
#include "struct_catalog.h"
#include "struct_catalog-internal.h"	/* FIELDX */

/* Entry point declared in test_main.c. */
void struct_fill_elem_self_check(void);

struct elem_test_buf {
	uint64_t arr;
	uint32_t cnt;
};

static const char *const elem_test_arrays[] = { "arr" };

static unsigned long long elem_counter;

static unsigned long long pick_counter(void)
{
	return ++elem_counter;
}

static unsigned long long pick_constant(void)
{
	return 42;
}

static const char *const elem_names[] = {
	"alpha", "beta", "gamma", "delta", "epsilon", "zeta",
};

static unsigned int elem_name_idx;

static const char *pick_name_cycling(void)
{
	const char *name = elem_names[elem_name_idx %
			(sizeof(elem_names) / sizeof(elem_names[0]))];

	elem_name_idx++;
	return name;
}

static const char *pick_name_constant(void)
{
	return "alpha";
}

static const char *pick_name_null(void)
{
	return NULL;
}

static bool avail_false(void)
{
	return false;
}

static bool avail_true(void)
{
	return true;
}

/*
 * A counter picker with elem_unique: draws are already distinct, so
 * the array holds 1..cnt in order and cnt agrees with the LEN field.
 */
static void scalar_counter_unique(void)
{
	static const struct struct_field fields[] = {
		FIELDX(struct elem_test_buf, arr, FT_PTR_ARRAY,
		       .u.ptr_array = { .elem_size = sizeof(uint32_t),
					.max_count = 4,
					.elem_pick = pick_counter,
					.elem_unique = true }),
		FIELDX(struct elem_test_buf, cnt, FT_LEN_COUNT,
		       .u.len_of = { .buf_fields = elem_test_arrays,
				     .n_buf_fields = 1 }),
	};
	unsigned char buf[sizeof(struct elem_test_buf)];
	uint64_t arr_ptr;
	uint32_t cnt;
	uint32_t j;

	elem_counter = 0;
	memset(buf, 0, sizeof(buf));
	struct_fill_passes(buf, sizeof(buf), fields, 2, NULL);

	memcpy(&arr_ptr, buf + offsetof(struct elem_test_buf, arr),
	       sizeof(arr_ptr));
	memcpy(&cnt, buf + offsetof(struct elem_test_buf, cnt),
	       sizeof(cnt));
	BUG_ON(arr_ptr == 0);
	BUG_ON(cnt < 1 || cnt > 4);
	for (j = 0; j < cnt; j++) {
		uint32_t v;

		memcpy(&v, (const unsigned char *)(uintptr_t) arr_ptr + j * 4,
		       sizeof(v));
		BUG_ON(v != j + 1);
	}
	free((void *)(uintptr_t) arr_ptr);
}

/*
 * A constant picker with elem_unique: retries cannot find a fresh
 * value, so the fill must still finish (bounded retries) and keep
 * the last draw in every element rather than wedging.
 */
static void scalar_constant_unique(void)
{
	static const struct struct_field fields[] = {
		FIELDX(struct elem_test_buf, arr, FT_PTR_ARRAY,
		       .u.ptr_array = { .elem_size = sizeof(uint64_t),
					.max_count = 4,
					.elem_pick = pick_constant,
					.elem_unique = true }),
		FIELDX(struct elem_test_buf, cnt, FT_LEN_COUNT,
		       .u.len_of = { .buf_fields = elem_test_arrays,
				     .n_buf_fields = 1 }),
	};
	unsigned char buf[sizeof(struct elem_test_buf)];
	uint64_t arr_ptr;
	uint32_t cnt;
	uint32_t j;

	memset(buf, 0, sizeof(buf));
	struct_fill_passes(buf, sizeof(buf), fields, 2, NULL);

	memcpy(&arr_ptr, buf + offsetof(struct elem_test_buf, arr),
	       sizeof(arr_ptr));
	memcpy(&cnt, buf + offsetof(struct elem_test_buf, cnt),
	       sizeof(cnt));
	BUG_ON(arr_ptr == 0);
	BUG_ON(cnt < 1 || cnt > 4);
	for (j = 0; j < cnt; j++) {
		uint64_t v;

		memcpy(&v, (const unsigned char *)(uintptr_t) arr_ptr + j * 8,
		       sizeof(v));
		BUG_ON(v != 42);
	}
	free((void *)(uintptr_t) arr_ptr);
}

/*
 * A constant picker without elem_unique: every element holds the
 * picker's value, proving the source is consulted at all (without
 * one the buffer would stay zero-filled, the next case).
 */
static void scalar_constant_plain(void)
{
	static const struct struct_field fields[] = {
		FIELDX(struct elem_test_buf, arr, FT_PTR_ARRAY,
		       .u.ptr_array = { .elem_size = sizeof(uint32_t),
					.max_count = 4,
					.elem_pick = pick_constant }),
		FIELDX(struct elem_test_buf, cnt, FT_LEN_COUNT,
		       .u.len_of = { .buf_fields = elem_test_arrays,
				     .n_buf_fields = 1 }),
	};
	unsigned char buf[sizeof(struct elem_test_buf)];
	uint64_t arr_ptr;
	uint32_t cnt;
	uint32_t j;

	memset(buf, 0, sizeof(buf));
	struct_fill_passes(buf, sizeof(buf), fields, 2, NULL);

	memcpy(&arr_ptr, buf + offsetof(struct elem_test_buf, arr),
	       sizeof(arr_ptr));
	memcpy(&cnt, buf + offsetof(struct elem_test_buf, cnt),
	       sizeof(cnt));
	BUG_ON(arr_ptr == 0);
	BUG_ON(cnt < 1 || cnt > 4);
	for (j = 0; j < cnt; j++) {
		uint32_t v;

		memcpy(&v, (const unsigned char *)(uintptr_t) arr_ptr + j * 4,
		       sizeof(v));
		BUG_ON(v != 42);
	}
	free((void *)(uintptr_t) arr_ptr);
}

/* No per-element source: the scalar array keeps the zero fill. */
static void scalar_no_picker_zero(void)
{
	static const struct struct_field fields[] = {
		FIELDX(struct elem_test_buf, arr, FT_PTR_ARRAY,
		       .u.ptr_array = { .elem_size = sizeof(uint32_t),
					.max_count = 4 }),
		FIELDX(struct elem_test_buf, cnt, FT_LEN_COUNT,
		       .u.len_of = { .buf_fields = elem_test_arrays,
				     .n_buf_fields = 1 }),
	};
	unsigned char buf[sizeof(struct elem_test_buf)];
	uint64_t arr_ptr;
	uint32_t cnt;
	uint32_t j;

	memset(buf, 0, sizeof(buf));
	struct_fill_passes(buf, sizeof(buf), fields, 2, NULL);

	memcpy(&arr_ptr, buf + offsetof(struct elem_test_buf, arr),
	       sizeof(arr_ptr));
	memcpy(&cnt, buf + offsetof(struct elem_test_buf, cnt),
	       sizeof(cnt));
	BUG_ON(arr_ptr == 0);
	BUG_ON(cnt < 1 || cnt > 4);
	for (j = 0; j < cnt; j++) {
		uint32_t v;

		memcpy(&v, (const unsigned char *)(uintptr_t) arr_ptr + j * 4,
		       sizeof(v));
		BUG_ON(v != 0);
	}
	free((void *)(uintptr_t) arr_ptr);
}

/*
 * A cycling string picker with elem_unique: every element points at
 * a distinct pool name, inside the one allocation the array owns
 * (freed once below); cnt agrees with the LEN field.
 */
static void string_cycling_unique(void)
{
	static const struct struct_field fields[] = {
		FIELDX(struct elem_test_buf, arr, FT_PTR_ARRAY,
		       .u.ptr_array = { .elem_size = sizeof(uint64_t),
					.max_count = 4,
					.elem_str_pick = pick_name_cycling,
					.elem_unique = true }),
		FIELDX(struct elem_test_buf, cnt, FT_LEN_COUNT,
		       .u.len_of = { .buf_fields = elem_test_arrays,
				     .n_buf_fields = 1 }),
	};
	unsigned char buf[sizeof(struct elem_test_buf)];
	uint64_t arr_ptr;
	uint32_t cnt;
	uint32_t j;

	elem_name_idx = 0;
	memset(buf, 0, sizeof(buf));
	struct_fill_passes(buf, sizeof(buf), fields, 2, NULL);

	memcpy(&arr_ptr, buf + offsetof(struct elem_test_buf, arr),
	       sizeof(arr_ptr));
	memcpy(&cnt, buf + offsetof(struct elem_test_buf, cnt),
	       sizeof(cnt));
	BUG_ON(arr_ptr == 0);
	BUG_ON(cnt < 1 || cnt > 4);
	for (j = 0; j < cnt; j++) {
		const char *s;
		uint64_t ptr;
		uint32_t k;
		bool known = false;

		memcpy(&ptr, (const unsigned char *)(uintptr_t) arr_ptr + j * 8,
		       sizeof(ptr));
		BUG_ON(ptr == 0);
		s = (const char *)(uintptr_t) ptr;
		for (k = 0; k < sizeof(elem_names) / sizeof(elem_names[0]); k++) {
			if (strcmp(s, elem_names[k]) == 0)
				known = true;
		}
		BUG_ON(!known);
		for (k = 0; k < j; k++) {
			uint64_t other;
			const char *t;

			memcpy(&other, (const unsigned char *)(uintptr_t) arr_ptr + k * 8,
			       sizeof(other));
			t = (const char *)(uintptr_t) other;
			BUG_ON(strcmp(s, t) == 0);
		}
	}
	free((void *)(uintptr_t) arr_ptr);
}

/*
 * A constant string picker with elem_unique: retries exhaust, the
 * fill finishes, and every element names the one string.
 */
static void string_constant_unique(void)
{
	static const struct struct_field fields[] = {
		FIELDX(struct elem_test_buf, arr, FT_PTR_ARRAY,
		       .u.ptr_array = { .elem_size = sizeof(uint64_t),
					.max_count = 4,
					.elem_str_pick = pick_name_constant,
					.elem_unique = true }),
		FIELDX(struct elem_test_buf, cnt, FT_LEN_COUNT,
		       .u.len_of = { .buf_fields = elem_test_arrays,
				     .n_buf_fields = 1 }),
	};
	unsigned char buf[sizeof(struct elem_test_buf)];
	uint64_t arr_ptr;
	uint32_t cnt;
	uint32_t j;

	memset(buf, 0, sizeof(buf));
	struct_fill_passes(buf, sizeof(buf), fields, 2, NULL);

	memcpy(&arr_ptr, buf + offsetof(struct elem_test_buf, arr),
	       sizeof(arr_ptr));
	memcpy(&cnt, buf + offsetof(struct elem_test_buf, cnt),
	       sizeof(cnt));
	BUG_ON(arr_ptr == 0);
	BUG_ON(cnt < 1 || cnt > 4);
	for (j = 0; j < cnt; j++) {
		uint64_t ptr;
		const char *s;

		memcpy(&ptr, (const unsigned char *)(uintptr_t) arr_ptr + j * 8,
		       sizeof(ptr));
		BUG_ON(ptr == 0);
		s = (const char *)(uintptr_t) ptr;
		BUG_ON(strcmp(s, "alpha") != 0);
	}
	free((void *)(uintptr_t) arr_ptr);
}

/*
 * A string picker returning NULL (empty pool): the array is still
 * allocated, every element stays NULL, and cnt still agrees.
 */
static void string_null_pick(void)
{
	static const struct struct_field fields[] = {
		FIELDX(struct elem_test_buf, arr, FT_PTR_ARRAY,
		       .u.ptr_array = { .elem_size = sizeof(uint64_t),
					.max_count = 4,
					.elem_str_pick = pick_name_null }),
		FIELDX(struct elem_test_buf, cnt, FT_LEN_COUNT,
		       .u.len_of = { .buf_fields = elem_test_arrays,
				     .n_buf_fields = 1 }),
	};
	unsigned char buf[sizeof(struct elem_test_buf)];
	uint64_t arr_ptr;
	uint32_t cnt;
	uint32_t j;

	memset(buf, 0, sizeof(buf));
	struct_fill_passes(buf, sizeof(buf), fields, 2, NULL);

	memcpy(&arr_ptr, buf + offsetof(struct elem_test_buf, arr),
	       sizeof(arr_ptr));
	memcpy(&cnt, buf + offsetof(struct elem_test_buf, cnt),
	       sizeof(cnt));
	BUG_ON(arr_ptr == 0);
	BUG_ON(cnt < 1 || cnt > 4);
	for (j = 0; j < cnt; j++) {
		uint64_t ptr;

		memcpy(&ptr, (const unsigned char *)(uintptr_t) arr_ptr + j * 8,
		       sizeof(ptr));
		BUG_ON(ptr != 0);
	}
	free((void *)(uintptr_t) arr_ptr);
}

struct xor_test_buf {
	uint64_t a;
	uint64_t b;
	uint32_t cnt;
};

static const char *const xor_test_arrays[] = { "a", "b" };

/*
 * Empty source first, live source second: the empty side loses
 * without a roll, the live side takes the buffer.
 */
static void xor_empty_first(void)
{
	static const struct struct_field fields[] = {
		FIELDX(struct xor_test_buf, a, FT_PTR_ARRAY,
		       .u.ptr_array = { .elem_size = sizeof(uint64_t),
					.max_count = 4,
					.elem_str_pick = pick_name_null,
					.elem_available = avail_false,
					.xor_sibling = "b" }),
		FIELDX(struct xor_test_buf, b, FT_PTR_ARRAY,
		       .u.ptr_array = { .elem_size = sizeof(uint64_t),
					.max_count = 4,
					.elem_pick = pick_counter,
					.elem_available = avail_true,
					.xor_sibling = "a" }),
		FIELDX(struct xor_test_buf, cnt, FT_LEN_COUNT,
		       .u.len_of = { .buf_fields = xor_test_arrays,
				     .n_buf_fields = 2 }),
	};
	unsigned char buf[sizeof(struct xor_test_buf)];
	uint64_t a_ptr, b_ptr;
	uint32_t cnt;

	elem_counter = 0;
	memset(buf, 0, sizeof(buf));
	struct_fill_passes(buf, sizeof(buf), fields, 3, NULL);

	memcpy(&a_ptr, buf + offsetof(struct xor_test_buf, a),
	       sizeof(a_ptr));
	memcpy(&b_ptr, buf + offsetof(struct xor_test_buf, b),
	       sizeof(b_ptr));
	memcpy(&cnt, buf + offsetof(struct xor_test_buf, cnt),
	       sizeof(cnt));
	BUG_ON(a_ptr != 0);
	BUG_ON(b_ptr == 0);
	BUG_ON(cnt < 1 || cnt > 4);
	free((void *)(uintptr_t) b_ptr);
}

/*
 * Live source first, empty source second: the live side fills
 * (no roll toward the empty sibling), the empty side stays NULL.
 */
static void xor_empty_second(void)
{
	static const struct struct_field fields[] = {
		FIELDX(struct xor_test_buf, b, FT_PTR_ARRAY,
		       .u.ptr_array = { .elem_size = sizeof(uint64_t),
					.max_count = 4,
					.elem_pick = pick_counter,
					.elem_available = avail_true,
					.xor_sibling = "a" }),
		FIELDX(struct xor_test_buf, a, FT_PTR_ARRAY,
		       .u.ptr_array = { .elem_size = sizeof(uint64_t),
					.max_count = 4,
					.elem_str_pick = pick_name_null,
					.elem_available = avail_false,
					.xor_sibling = "b" }),
		FIELDX(struct xor_test_buf, cnt, FT_LEN_COUNT,
		       .u.len_of = { .buf_fields = xor_test_arrays,
				     .n_buf_fields = 2 }),
	};
	unsigned char buf[sizeof(struct xor_test_buf)];
	uint64_t a_ptr, b_ptr;
	uint32_t cnt;

	elem_counter = 0;
	memset(buf, 0, sizeof(buf));
	struct_fill_passes(buf, sizeof(buf), fields, 3, NULL);

	memcpy(&a_ptr, buf + offsetof(struct xor_test_buf, a),
	       sizeof(a_ptr));
	memcpy(&b_ptr, buf + offsetof(struct xor_test_buf, b),
	       sizeof(b_ptr));
	memcpy(&cnt, buf + offsetof(struct xor_test_buf, cnt),
	       sizeof(cnt));
	BUG_ON(a_ptr != 0);
	BUG_ON(b_ptr == 0);
	BUG_ON(cnt < 1 || cnt > 4);
	free((void *)(uintptr_t) b_ptr);
}

/*
 * Both sources empty: availability agrees, so the roll decides and
 * exactly one side still takes the buffer.
 */
static void xor_both_empty(void)
{
	static const struct struct_field fields[] = {
		FIELDX(struct xor_test_buf, a, FT_PTR_ARRAY,
		       .u.ptr_array = { .elem_size = sizeof(uint64_t),
					.max_count = 4,
					.elem_str_pick = pick_name_null,
					.elem_available = avail_false,
					.xor_sibling = "b" }),
		FIELDX(struct xor_test_buf, b, FT_PTR_ARRAY,
		       .u.ptr_array = { .elem_size = sizeof(uint64_t),
					.max_count = 4,
					.elem_pick = pick_counter,
					.elem_available = avail_false,
					.xor_sibling = "a" }),
		FIELDX(struct xor_test_buf, cnt, FT_LEN_COUNT,
		       .u.len_of = { .buf_fields = xor_test_arrays,
				     .n_buf_fields = 2 }),
	};
	unsigned char buf[sizeof(struct xor_test_buf)];
	uint64_t a_ptr, b_ptr;

	memset(buf, 0, sizeof(buf));
	struct_fill_passes(buf, sizeof(buf), fields, 3, NULL);

	memcpy(&a_ptr, buf + offsetof(struct xor_test_buf, a),
	       sizeof(a_ptr));
	memcpy(&b_ptr, buf + offsetof(struct xor_test_buf, b),
	       sizeof(b_ptr));
	BUG_ON((a_ptr != 0) == (b_ptr != 0));
	if (a_ptr != 0)
		free((void *)(uintptr_t) a_ptr);
	if (b_ptr != 0)
		free((void *)(uintptr_t) b_ptr);
}

void struct_fill_elem_self_check(void)
{
	scalar_counter_unique();
	scalar_constant_unique();
	scalar_constant_plain();
	scalar_no_picker_zero();
	string_cycling_unique();
	string_constant_unique();
	string_null_pick();
	xor_empty_first();
	xor_empty_second();
	xor_both_empty();

	printf("    struct_fill_elem: scalar and string element sources, "
	       "empty-pool fallback and xor availability OK\n");
}
