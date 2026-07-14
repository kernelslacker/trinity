#pragma once

struct childdata;

/* RMID every fuzzed SysV message queue this child created but never cleaned
 * up (a SIGKILL/OOM death skips the OBJ_LOCAL RMID destructor).  Called from
 * reap_child() parent-side, after the child is confirmed dead. */
void reap_child_sysv_msg(struct childdata *child);
