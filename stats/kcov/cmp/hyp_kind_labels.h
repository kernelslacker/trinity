/*
 * Row labels for enum cmp_hypothesis_kind, shared by the stats/kcov/cmp/
 * renderers that print one row or column per kind.  One list feeds both
 * the designated table and the label count, so a kind added to the enum
 * without a label, or a label dropped from the list, fails the build
 * instead of handing NULL to "%s".  Keep labels within 13 characters,
 * the width of the narrowest per-kind column.
 */

#pragma once

#include "cmp_hints.h"

#define CMP_HYP_KIND_LABEL_LIST(X)				\
	X(CMP_HYP_EXACT,		"exact")		\
	X(CMP_HYP_RANGE,		"range")		\
	X(CMP_HYP_BOUNDARY,		"boundary")		\
	X(CMP_HYP_BITMASK,		"bitmask")		\
	X(CMP_HYP_ENUM_FAMILY,		"enum_family")		\
	X(CMP_HYP_ALIGNMENT,		"alignment")		\
	X(CMP_HYP_LENGTH,		"length")		\
	X(CMP_HYP_FOREIGN_VALUE,	"foreign_value")

#define CMP_HYP_KIND_LABEL_SLOT(kind, label)	[kind] = label,
#define CMP_HYP_KIND_LABEL_ONE(kind, label)	+ 1

static const char * const cmp_hyp_kind_labels[CMP_HYP_KIND_NR] = {
	CMP_HYP_KIND_LABEL_LIST(CMP_HYP_KIND_LABEL_SLOT)
};

_Static_assert(0 CMP_HYP_KIND_LABEL_LIST(CMP_HYP_KIND_LABEL_ONE) == CMP_HYP_KIND_NR,
	       "cmp_hyp_kind_labels needs one label per enum cmp_hypothesis_kind");

#undef CMP_HYP_KIND_LABEL_ONE
#undef CMP_HYP_KIND_LABEL_SLOT
#undef CMP_HYP_KIND_LABEL_LIST
