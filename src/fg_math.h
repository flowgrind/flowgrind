/**
 * @file fg_math.h
 * @brief Routines for statistics and advanced traffic generation
 */

/*
 * Copyright (C) 2010-2013 Christian Samsel <christian.samsel@rwth-aachen.de>
 *
 * This file is part of Flowgrind. Flowgrind is free software; you can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2 as published by the Free Software Foundation.
 *
 * Flowgrind distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "daemon.h"

/* initalization for random number generator */
extern void init_math_functions (struct _flow *flow, unsigned long seed);
extern void free_math_functions (struct _flow *flow);

/* basic probability distributions */
extern int dist_bernoulli (struct _flow *flow, const double p);
extern double dist_pareto (struct _flow *flow,
			   const double k, const double x_min);
extern double dist_weibull (struct _flow *flow,
			    const double alpha, const double beta);
extern double dist_normal (struct _flow *flow,
			   const double mu, const double sigma_square);
extern double dist_lognormal (struct _flow *flow,
			      const double zeta, const double sigma);
extern double dist_uniform (struct _flow *flow,
			    const double minval, const double maxval);
extern double dist_exponential (struct _flow *flow, const double mu);
extern double dist_chisq (struct _flow *flow, const double nu);
