#pragma once

/*
 * Startup process-rlimit caps.  Called from main() after argument
 * parsing (so nr_children is final) and before any fork(), so every
 * later child inherits the capped limits.
 */
void init_rlimits(unsigned int nr_children);
