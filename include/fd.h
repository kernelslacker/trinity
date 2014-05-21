#pragma once

#include "list.h"

unsigned int setup_fds(void);

struct fd_provider {
        struct list_head list;
        int (*open)(void);
        int (*get)(void);
};
