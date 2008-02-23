#ifndef _FG_TIME_H
#define _FG_TIME_H

#include <sys/time.h>

double time_diff(const struct timeval *, const struct timeval *);
double time_diff_now(const struct timeval *tv1);
void time_add(struct timeval *tv, double seconds);

void tv2ntp(const struct timeval *tv, char *);
void ntp2tv(struct timeval *tv, const char *);
const char * ctime_us_r(struct timeval *tv, char *buf);
const char * ctime_us(struct timeval *tv);
const char * debug_timestamp(void);
int normalize_tv(struct timeval *);
int time_is_after(const struct timeval *, const struct timeval *);

int tsc_gettimeofday(struct timeval *tv);

#if defined(HAVE_FASTTIME_H) && defined(HAVE_LIBFASTTIME)
#define tsc_init()		fasttime_init()
#elif defined(HAVE_TSCI2_H) && defined(HAVE_LIBTSCI2)
#define tsc_init()		tsci2_init(TSCI2_DAEMON | \
				           TSCI2_CLIENT | \
				           TSCI2_FALLBACK)
#else
#define tsc_init()		;
#endif

#endif
