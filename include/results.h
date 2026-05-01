#pragma once

#include "syscall.h"

void handle_success(struct syscallrecord *rec);
int pick_successful_fd(struct results *results);
