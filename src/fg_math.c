/**
 * @file fg_math.c
 * @brief Routines for statistics and advanced traffic generation
 */

/*
 * Copyright (C) 2010-2013 Christian Samsel <christian.samsel@rwth-aachen.de>
 *
 * This file is part of Flowgrind.
 *
 * Flowgrind is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Flowgrind is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Flowgrind.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

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
#include <float.h>
#include <fenv.h>

#include "debug.h"
#include "fg_math.h"
#include "fg_error.h"
#include "fg_definitions.h"

#ifdef HAVE_LIBGSL
#include <gsl/gsl_rng.h>
#include <gsl/gsl_randist.h>
#include <gsl/gsl_cdf.h>
#include <gsl/gsl_sf_gamma.h>
#include <gsl/gsl_math.h>
#include <gsl/gsl_errno.h>
#endif /* HAVE_LIBGSL */

extern void init_math_functions (struct flow *flow, unsigned long seed)
{
	int rc;
#ifndef HAVE_LIBGSL
	UNUSED_ARGUMENT(flow);
#endif /* HAVE_LIBGSL */
	/* set rounding */
	fesetround(FE_TONEAREST);

	/* initalize rng */
#ifdef HAVE_LIBGSL
	const gsl_rng_type * T;
	gsl_rng_env_setup();
	T = gsl_rng_default;
	flow->r = gsl_rng_alloc (T);
#endif /* HAVE_LIBGSL */

	if (!seed) {
	/* if no seed supplied use urandom */
		DEBUG_MSG(LOG_WARNING, "client did not supply random seed "
			  "value");
		int data = open("/dev/urandom", O_RDONLY);
		rc = read(data, &seed, sizeof (long) );
		close(data);
		if(rc == -1)
			crit("read /dev/urandom failed");
	}

#ifdef HAVE_LIBGSL
	gsl_rng_set (flow->r, seed);
	DEBUG_MSG(LOG_WARNING, "initalized local libgsl random functions for "
		  "flow %d with seed %lu, gsl generator is: %s",
		  flow->id,seed,gsl_rng_name (flow->r));
#else /* HAVE_LIBGSL */
	srand((unsigned int)seed);
	DEBUG_MSG(LOG_WARNING, "initalized posix random functions with seed "
		  "%u", (unsigned int)seed);
#endif /* HAVE_LIBGSL */
}

extern void free_math_functions (struct flow *flow)
{
#ifdef HAVE_LIBGSL
	gsl_rng_free(flow->r);
#else /* HAVE_LIBGSL */
	UNUSED_ARGUMENT(flow);
#endif /* HAVE_LIBGSL */
}

#ifndef HAVE_LIBGSL
static inline double rn_uniform(void)
{
	return (double)rand();
}

static inline double rn_uniform_zero_to_one(void)
{
	return (rn_uniform()/(RAND_MAX + 1.0));
}

static inline double rn_uniform_minusone_to_one(void)
{
	return (rn_uniform()/(RAND_MAX/2.0) - 1.0);
}
#endif /* HAVE_LIBGSL */

extern double dist_exponential(struct flow *flow, const double mu)
{
#ifdef HAVE_LIBGSL
	gsl_rng * r = flow->r;
	return gsl_ran_exponential(r, mu);
#else /* HAVE_LIBGSL */
	UNUSED_ARGUMENT(flow);
	return -log(rn_uniform())+mu;
#endif /* HAVE_LIBGSL */
}

/* source for naive implementation english wikipedia articles */

extern double dist_uniform(struct flow *flow, const double minval,
			   const double maxval)
{
#ifdef HAVE_LIBGSL
	gsl_rng * r = flow->r;
	return gsl_ran_flat(r, minval, maxval);
#else /* HAVE_LIBGSL */
	UNUSED_ARGUMENT(flow);
	const double x = rn_uniform_zero_to_one();
	return ((maxval-minval) * x) + minval;
#endif /* HAVE_LIBGSL */
}

extern double dist_normal(struct flow *flow, const double mu,
			  const double sigma_square)
{
#ifdef HAVE_LIBGSL
	const gsl_rng * r = flow->r;
	return gsl_ran_gaussian (r, sigma_square) + mu;
#else /* HAVE_LIBGSL */
	UNUSED_ARGUMENT(flow);
	const double x = rn_uniform_minusone_to_one();
	return (1.0 / sqrt(2.0*M_PI*sigma_square)) *
		exp((-pow ((x-mu),2)) / (2 * sigma_square));
#endif /* HAVE_LIBGSL */
}

extern double dist_lognormal(struct flow *flow, const double zeta,
			     const double sigma)
{
#ifdef HAVE_LIBGSL
	gsl_rng * r = flow->r;
	return gsl_ran_lognormal (r, zeta, sigma);
#else /* HAVE_LIBGSL */
	/* not implemented */
	UNUSED_ARGUMENT(flow);
	UNUSED_ARGUMENT(zeta);
	UNUSED_ARGUMENT(sigma);
	return 0;
#endif /* HAVE_LIBGSL */
}


extern int dist_bernoulli(struct flow *flow, const double p)
{
#ifdef HAVE_LIBGSL
	gsl_rng * r = flow->r;
	return gsl_ran_bernoulli (r, p);
#else /* HAVE_LIBGSL */
	UNUSED_ARGUMENT(flow);
	return rn_uniform_zero_to_one() <= p;
#endif /* HAVE_LIBGSL */
}

extern double dist_pareto (struct flow *flow, const double k,
			   const double x_min)
{
#ifdef HAVE_LIBGSL
	gsl_rng * r = flow->r;
	return gsl_ran_pareto (r, k, x_min);
#else /* HAVE_LIBGSL */
	UNUSED_ARGUMENT(flow);
	const double x = rn_uniform();
	if (x < x_min)
		return 0;
	else
		return  (k/x_min) * pow (x_min/x,k+1);
#endif /* HAVE_LIBGSL */
}

extern double dist_weibull (struct flow *flow, const double alpha,
			    const double beta)
{
#ifdef HAVE_LIBGSL
	gsl_rng * r = flow->r;
	return gsl_ran_weibull (r, alpha, beta);
#else /* HAVE_LIBGSL */
	UNUSED_ARGUMENT(flow);
	const double x = rn_uniform_zero_to_one();
	return  alpha * beta * pow (x,beta-1.0) * exp(-alpha * pow(x,beta));
#endif /* HAVE_LIBGSL */
}

extern double dist_chisq (struct flow *flow, const double nu)
{
#ifdef HAVE_LIBGSL
	gsl_rng * r = flow->r;
	return gsl_ran_chisq(r, nu);
#else /* HAVE_LIBGSL */
	/* not implemented */
	UNUSED_ARGUMENT(flow);
	UNUSED_ARGUMENT(nu);
	return 0;
#endif /* HAVE_LIBGSL */
}

