#include "fg_math.h"
#include <math.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>


void
rn_set_seed (const int i) {
	srand((unsigned)i);
};

int
rn_read_dev_random () {
	int i;
	int data = open("/dev/urandom", O_RDONLY);
	read(data, &i, sizeof (int) );
	close(data);
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
        return   alpha * beta * pow (x,beta-1) * exp( -alpha, pow(x,beta) );
}

