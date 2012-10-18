#include "constants.h"

void setup_fds(void);

void generate_filelist(void);
void open_files(void);
void close_files(void);
void regenerate_fds(void);

extern unsigned int nr_file_fds;
extern char *victim_path;
extern char **fileindex;
extern unsigned int files_in_index;
