#ifndef _MATH_H
#define _MATH_H

#include <sys/types.h>
#include <unistd.h>
#include <math.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef __SOLARIS__
#define RANDOM_MAX              4294967295UL    /* 2**32-1 */
#elif __DARWIN__
#define RANDOM_MAX              LONG_MAX        /* Darwin */
#else
#define RANDOM_MAX              RAND_MAX        /* Linux, FreeBSD */
#endif

void rn_set_seed (const int i);
int rn_read_dev_random ();

#endif
