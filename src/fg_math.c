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
#include <syslog.h>

#include "common.h"
#include "debug.h"
#include "fg_math.h"

#ifdef HAVE_FLOAT_H
#include <float.h>
#endif

#ifdef __SOLARIS__
#define RANDOM_MAX              4294967295UL    /* 2**32-1 */
#elif __DARWIN__
#define RANDOM_MAX              LONG_MAX        /* Darwin */
#else
#define RANDOM_MAX              RAND_MAX        /* Linux, FreeBSD */
#endif

extern void
rn_set_seed (int i) {
	srand((unsigned)i);
	DEBUG_MSG(LOG_WARNING, "initalizing random functions with seed %u",(unsigned)i);
}

extern int
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

static inline double
rn_uniform() { return (rand()); }

static inline double
rn_uniform_zero_to_one() { return (rn_uniform()/(RANDOM_MAX)); }

static inline double
rn_uniform_minusone_to_one() { return (rn_uniform()/(RANDOM_MAX/2.0)-1.0); }
		
static inline double
rn_exponential() { return (-log(rn_uniform())); }

/* source english wikipedia articles */

double
dist_uniform(const double minval, const double maxval) {
	const double x = rn_uniform();
	
	return ((int) x % (int)(maxval-minval)) + minval;
}
double
dist_normal(const double mu, const double sigma_square) {
	const double x = rn_uniform_minusone_to_one();
	DEBUG_MSG(LOG_DEBUG, "calculated random number %f", x);
	return ( 1.0 / sqrt(2.0*M_PI*sigma_square) ) * exp( (-pow ((x-mu),2) ) / ( 2 * sigma_square) );
}

extern int
dist_bernoulli(double p) { return (rn_uniform_zero_to_one() <= p); }

extern double
dist_pareto (double k, double x_min) {
        const double x = rn_uniform();
        if (x < x_min) return 0;
        else return ( (k/x_min) * pow (x_min/rn_uniform(),k+1) );
}

extern double
dist_weibull (double alpha, double beta) {
        const double x = rn_uniform_zero_to_one();
	DEBUG_MSG(LOG_DEBUG, "calculated random number %f", x);
        return  alpha * beta * pow (x,beta-1.0) * exp( -alpha * pow(x,beta) );
}

