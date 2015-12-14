#pragma once

extern unsigned int nr_file_fds;
extern char *victim_path;
extern const char **fileindex;
extern unsigned int files_in_index;

#define NR_FILE_FDS 250U

int check_stat_file(const struct stat *sb);
void generate_filelist(void);
