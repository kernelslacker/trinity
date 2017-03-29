#pragma once

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

extern unsigned int nr_file_fds;
extern char *victim_path;
extern const char **fileindex;
extern unsigned int files_in_index;

#define MAX_PATH_LEN 4096

#define NR_FILE_FDS 250U

int check_stat_file(const struct stat *sb);
void generate_filelist(void);
const char * get_filename(void);
const char * generate_pathname(void);
