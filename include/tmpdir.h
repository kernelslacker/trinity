#pragma once

const char *trinity_tmpdir_abs(void);
void change_tmp_dir(void);
const char *make_scratch_dir(const char *path);
void sweep_dead_pid_dirs(const char *prefix);
