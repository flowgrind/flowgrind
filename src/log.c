#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"

char timestr[20];
char *logstr = NULL;
int log_type = LOGTYPE_SYSLOG;

void
logging_init (void)
{
        logstr = malloc(LOGGING_MAXLEN);
        if (logstr == NULL) {
                fprintf(stderr, "Error: Unable to allocate memory for logging "
                                "string.\n");
                exit(1);
        }

        switch (log_type) {
        case LOGTYPE_SYSLOG:
                openlog("flowgrind_daemon", LOG_NDELAY | LOG_CONS |
                                                LOG_PID, LOG_DAEMON);
        break;
        case LOGTYPE_STDERR:
                break;
        }
}

void
logging_exit (void)
{
        switch (log_type) {
        case LOGTYPE_SYSLOG:
                closelog();
                break;
        case LOGTYPE_STDERR:
                break;
        }

        free(logstr);
}

void
logging_log (int priority, const char *fmt, ...)
{
        int n;
        va_list ap;

        memset(logstr, 0, LOGGING_MAXLEN);

        va_start(ap, fmt);
        n = vsnprintf(logstr, LOGGING_MAXLEN, fmt, ap);
        va_end(ap);

        if (n > -1 && n < LOGGING_MAXLEN)
                logging_log_string(priority, logstr);
}

void
logging_log_string (int priority, const char *s)
{
        switch (log_type) {
                case LOGTYPE_SYSLOG:
                        syslog(priority, "%s", s);
                        break;
                case LOGTYPE_STDERR:
                        fprintf(stderr, "%s %s\n", logging_time(), s);
                        fflush(stderr);
                        break;
        }
}

char *
logging_time(void)
{
        time_t tp;
        struct tm *loc = NULL;

        tp = time(NULL);
        loc = localtime(&tp);
        memset(&timestr, 0, sizeof(timestr));
        strftime(&timestr[0], sizeof(timestr), "%Y/%m/%d %H:%M:%S", loc);

        return (&timestr[0]);
}
