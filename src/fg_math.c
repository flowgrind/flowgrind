#ifndef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "flowgrind.h"
#include "debug.h"
#include "common.h"
#include "fg_math.h"

#ifdef __SOLARIS__
#define RANDOM_MAX              4294967295UL    /* 2**32-1 */
#elif __DARWIN__
#define RANDOM_MAX              LONG_MAX        /* Darwin */
#else
#define RANDOM_MAX              RAND_MAX        /* Linux, FreeBSD */
#endif

void
rn_set_seed (const int i) {
	srand((unsigned)i);
	DEBUG_MSG(1, "initalizing random functions with seed %u",(unsigned)i);
};

int
rn_read_dev_random () {
	int i, rc;
	int data = open("/dev/urandom", O_RDONLY);
	rc = read(data, &i, sizeof (int) );
	close(data);
	if(rc == -1) {
		error(ERR_FATAL, "read /dev/urandom failed: %s", strerror(errno));
	}
	return i;
}

inline double
rn_uniform() { return (rand()); }

inline double
rn_uniform_zero_to_one() { return (rn_uniform()/RANDOM_MAX+1.0); }

inline double
rn_exponential() { return (-log(rn_uniform())); }

/* source english wikipedia articles */

inline int
dist_bernoulli(const double p) { return (rn_uniform_zero_to_one() <= p); }

inline double
dist_pareto (const double k, const double x_min) {
        double x = rn_uniform();
        if (x < x_min) return 0;
        else return ( (k/x_min) * pow (x_min/rn_uniform(),k+1) );
}

inline double
dist_weibull (const double alpha, const double beta) {
        double x = rn_uniform();
        return   alpha * beta * pow (x,beta-1) * exp( -alpha * pow(x,beta) );
}

