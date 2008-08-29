#ifndef _ADT_H_
#define _ADT_H_

#include <stdio.h>
#include <stdlib.h>
#include <math.h>


/* Returns the raw A^2 test statistic for n sorted samples
 * z[0] .. z[n-1], for z ~ Unif(0,1).
 */
extern double compute_A2(double z[], int n);

/* Returns the significance level associated with a A^2 test
* statistic value of A2, assuming no parameters of the tested
* distribution were estimated from the data.
*/
extern double A2_significance(double A2);

/* Returns a pseudo-random number distributed according to an
* exponential distribution with the given mean.
*/
extern double random_exponential(double mean);
#endif


/* the following 2 functions are the ones we are interested in externally

   Both take as their first argument, x, the array of n values to be
   tested.  (Upon return, the elements of x are sorted.)  The remaining
   parameters characterize the distribution to be used: either the mean
   (1/lambda), for an exponential distribution, or the lower and upper
   bounds, for a uniform distribution.  The names of the routines stress
   that these values must be known in advance, and *not* estimated from
   the data (for example, by computing its sample mean).  Estimating the
   parameters from the data *changes* the significance level of the test
   statistic.
*/

/* Returns the A^2 significance level for testing n observations
* x[0] .. x[n-1] against an exponential distribution with the
* given mean.
*
* SIDE EFFECT: the x[0..n-1] are sorted upon return.
*/
extern double exp_A2_known_mean(double x[], int n, double mean);

/* Returns the A^2 significance level for testing n observations
* x[0] .. x[n-1] against the uniform distribution [min_val, max_val].
*
* SIDE EFFECT: the x[0..n-1] are sorted upon return.
*/
extern double unif_A2_known_range(double x[], int n,
		double min_val, double max_val);



