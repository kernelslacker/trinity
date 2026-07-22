#pragma once

/* Sub-struct of struct kcov_shared, embedded as .plateau.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_plateau {
time_t plateau_window_start;
unsigned long plateau_prev_edges;
unsigned long plateau_last_window_delta;
time_t plateau_entered_at;
bool plateau_armed;
bool plateau_active;
};
