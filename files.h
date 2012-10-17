#include "constants.h"

void setup_fds(void);
int get_fd(void);

void open_files(void);
void close_files(void);
void regenerate_fds(void);

extern unsigned int nr_file_fds;
