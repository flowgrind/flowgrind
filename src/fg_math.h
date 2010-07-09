#ifndef _MATH_H
#define _MATH_H

/* initalization for random number generator */
extern void rn_set_seed (const int i);
extern int rn_read_dev_random ();

/* basic probability distributions */
extern int 	dist_bernoulli	(const double p);
extern double 	dist_pareto	(const double k, 	const double x_min); 
extern double 	dist_weibull	(const double alpha, 	const double beta); 
extern double 	dist_standard	(const double mu, 	const double sigma_square);
#endif
