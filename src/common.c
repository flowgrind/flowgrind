#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "debug.h"

void
error(int errcode, const char *fmt, ...)
{
        va_list ap;
        const char *prefix;
        int fatal = 1;
        static char error_string[1024];

        switch (errcode) {
        case ERR_FATAL:
                prefix = "fatal";
                break;
        case ERR_WARNING:
                prefix = "warning";
                fatal = 0;
                break;
        default:
                prefix = "(UNKNOWN ERROR TYPE)";
        }
        va_start(ap, fmt);
        vsnprintf(error_string, sizeof(error_string), fmt, ap);
        va_end(ap);

        fprintf(stderr, "%s: %s\n", prefix, error_string);
        if (fatal)
                exit(1);
}
