#pragma once

#include "child.h"
#include "logfile.h"

void init_logging(void);
void shutdown_logging(void);

enum {
       LOGGING_DISABLED,
       LOGGING_FILES,
       LOGGING_UDP,
};

void init_child_logging(struct childdata *child);
void shutdown_child_logging(struct childdata *child);
