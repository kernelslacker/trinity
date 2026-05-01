#pragma once

#include "syscall.h"

void handle_success(struct syscallrecord *rec);
void handle_failure(struct syscallrecord *rec);
int pick_successful_fd(struct results *results);
bool fd_recently_failed(struct results *results, int fd);
