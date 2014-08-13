#pragma once

#include "list.h"

void setup_fd_providers(void);

unsigned int open_fds(void);

struct fd_provider {
        struct list_head list;
        int (*open)(void);
        int (*get)(void);
};
