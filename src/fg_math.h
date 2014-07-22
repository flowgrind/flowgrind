/**
 * @file fg_math.h
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

#ifndef _FG_MATH_H_
#define _FG_MATH_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "daemon.h"

/* initalization for random number generator */
extern void init_math_functions (struct flow *flow, unsigned long seed);
extern void free_math_functions (struct flow *flow);

/* basic probability distributions */
extern int dist_bernoulli (struct flow *flow, const double p);
extern double dist_pareto (struct flow *flow,
			   const double k, const double x_min);
extern double dist_weibull (struct flow *flow,
			    const double alpha, const double beta);
extern double dist_normal (struct flow *flow,
			   const double mu, const double sigma_square);
extern double dist_lognormal (struct flow *flow,
			      const double zeta, const double sigma);
extern double dist_uniform (struct flow *flow,
			    const double minval, const double maxval);
extern double dist_exponential (struct flow *flow, const double mu);
extern double dist_chisq (struct flow *flow, const double nu);

#endif /* _FG_MATH_H_ */
