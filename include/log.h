#ifndef _LOG_H
#define _LOG_H 1

#define ANSI_RED	"[1;31m"
#define ANSI_GREEN	"[1;32m"
#define ANSI_YELLOW	"[1;33m"
#define ANSI_BLUE	"[1;34m"
#define ANSI_MAGENTA	"[1;35m"
#define ANSI_CYAN	"[1;36m"
#define ANSI_WHITE	"[1;37m"
#define ANSI_RESET	"[0m"

#define RED if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_RED);
#define GREEN if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_GREEN);
#define YELLOW if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_YELLOW);
#define BLUE if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_BLUE);
#define MAGENTA if (monochrome == FALSE) sptr += sprintf(sptr, "%s", ANSI_MAGENTA);
#define CYAN if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_CYAN);
#define WHITE if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_WHITE);
#define CRESET if (monochrome == FALSE)	sptr += sprintf(sptr, "%s", ANSI_RESET);

#define MAX_LOGLEVEL 3
unsigned int highest_logfile(void);
void synclogs(void);
void output(unsigned char level, const char *fmt, ...);
void open_logfiles(void);
void close_logfiles(void);

#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)

#ifndef GIT_VERSION
#define BUGTXT ANSI_RED "BUG!: " ANSI_RESET
#else
#define BUGTXT ANSI_RED "BUG!: " ANSI_RESET GIT_VERSION
#endif


#define BUG(bugtxt)	{ printf("%s:%s:%d %s", __FILE__, __func__, __LINE__, bugtxt); while(1); }

#endif	/* _LOG_H */
