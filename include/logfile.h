#pragma once

#include "child.h"

FILE *find_logfile_handle(void);
void synclogs(void);

extern FILE *mainlogfile;
void open_main_logfile(void);
void close_logfile(FILE **handle);

void open_child_logfile(struct childdata *child);
