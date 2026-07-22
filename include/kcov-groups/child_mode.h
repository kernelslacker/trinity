#pragma once

/* Sub-struct of struct kcov_shared, embedded as .child_mode.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_child_mode_pop {
	unsigned int pc_mode_children;
	unsigned int cmp_mode_children;
};
