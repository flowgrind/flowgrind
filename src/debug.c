#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "debug.h"

#ifdef DEBUG

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

inline void decrease_debuglevel()
{
        debug_level--;
        printf("DEBUG_LEVEL=%d", debug_level);
}

inline void increase_debuglevel()
{
        debug_level++;
        printf("DEBUG_LEVEL=%d\n", debug_level);
}

static double time_diff(struct timeval *tv1, struct timeval *tv2)
{

        return (double)(tv2->tv_sec - tv1->tv_sec) +
                (double)(tv2->tv_usec - tv1->tv_usec)/1e6;
}

const char *debug_timestamp()
{
        struct timeval now = {.tv_sec = 0, .tv_usec = 0};
        static struct timeval first = {.tv_sec = 0, .tv_usec = 0};
        static struct timeval last = {.tv_sec = 0, .tv_usec = 0};
        size_t len = 0;
        static char buf[80];

        gettimeofday(&now, NULL);

        if (!first.tv_sec && !first.tv_usec)
                last = first = now;

        len = strftime(buf, sizeof(buf), "%Y/%m/%d %H:%M:%S", localtime(&now.tv_sec));
        snprintf(buf+len, sizeof(buf)-len, ".%06ld [+%8.6lf] (%8.6lf)",
                        (long)now.tv_usec, time_diff(&last, &now),
                        time_diff(&first, &now));
        last = now;
        return buf;
}

#else

void decrease_debuglevel() { }
void increase_debuglevel() { }

#endif
