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
