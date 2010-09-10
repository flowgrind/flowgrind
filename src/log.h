#ifndef _LOG_H_
#define _LOG_H_

#define LOGGING_MAXLEN  255             /* maximum string length */

extern int log_type;

enum {
	LOGTYPE_SYSLOG,
	LOGTYPE_STDERR
};

void logging_init (void);
void logging_exit (void);
void logging_log (int priority, const char *fmt, ...);
void logging_log_string (int priority, const char *s);
char *logging_time(void);

#endif
