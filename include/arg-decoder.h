#pragma once

#include "syscall.h"

void output_rendered_buffer(char *buffer);
void output_syscall_prefix(struct syscallrecord *rec, struct syscallentry *entry);
void output_syscall_postfix(struct syscallrecord *rec);
