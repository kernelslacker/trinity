#pragma once

#include "child.h"

void dump_uids(void);
void init_uids(void);
void do_uid0_check(void);
void check_uid(void);

extern uid_t orig_uid;
extern gid_t orig_gid;

extern uid_t nobody_uid;
extern gid_t nobody_gid;
