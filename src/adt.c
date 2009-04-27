/*
*  C Implementation: adt
*
* Description:
* Anderson Darling Test
* Code based on RFC2330
*
* Author:  (C) 2008
*
* Copyright: See COPYING file that comes with this distribution
*
*/

#include "adt.h"

/* Returns the raw A^2 test statistic for n sorted samples
 * z[0] .. z[n-1], for z ~ Unif(0,1).
 */
double compute_A2(double z[], int n);

/* Returns the significance level associated with a A^2 test
* statistic value of A2, assuming no parameters of the tested
* distribution were estimated from the data.
*/
double A2_significance(double A2);

/* Returns a pseudo-random number distributed according to an
* exponential distribution with the given mean.
*/
double random_exponential(double mean);

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
double exp_A2_known_mean(double x[], int n, double mean);

/* Returns the A^2 significance level for testing n observations
* x[0] .. x[n-1] against the uniform distribution [min_val, max_val].
*
* SIDE EFFECT: the x[0..n-1] are sorted upon return.
*/
double unif_A2_known_range(double x[], int n,
		double min_val, double max_val);


/* Array to hold data points */
#define MAXANDERSONSIZE 1000
double adt_data[2][adt_type_max][MAXANDERSONSIZE];

static int adt_num_data_points[2][adt_type_max];

void adt_add_data(double v, enum endpoint direction, enum _adt_data_type type)
{
	int *num = &adt_num_data_points[direction][type];
	if (*num >= MAXANDERSONSIZE)
		return;

	adt_data[direction][type][*num] = v;
	(*num)++;
}

double adt_get_result_range(enum endpoint direction, enum _adt_data_type type, 
                            double lower_bound, double upper_bound)
{
	return unif_A2_known_range(adt_data[direction][type],
	                         adt_num_data_points[direction][type],
	                         lower_bound, upper_bound);
}

double adt_get_result_mean(enum endpoint direction, enum _adt_data_type type, 
                           double mean)
{
	return exp_A2_known_mean(adt_data[direction][type],
	                         adt_num_data_points[direction][type], mean);
}

int adt_too_much_data()
{
	int type, direction;

	for (direction = 0; direction < 2; direction++)
		for (type = 0; type < adt_type_max; type++)
			if (adt_num_data_points[direction][type] >= MAXANDERSONSIZE)
				return 1;

	return 0;
}

/* Helper function used by qsort() to sort double-precision
 * floating-point values.
 */
static int compare_double(const void *v1, const void *v2){
	double d1 = *(double *) v1;
	double d2 = *(double *) v2;

	if (d1 < d2)
		return -1;
	else if (d1 > d2)
		return 1;
	else
		return 0;
}

double compute_A2(double z[], int n){
	int i;
	double sum = 0.0;

	if ( n < 5 )
		/* Too few values. */
		return -1.0;

	/* If any of the values are outside the range (0, 1) then
	 * fail immediately (and avoid a possible floating point
	 * exception in the code below).
	 */
	for (i = 0; i < n; ++i)
		if ( z[i] <= 0.0 || z[i] >= 1.0 )
		return -1.0;

	/* Page 101 of D'Agostino and Stephens. */
	for (i = 1; i <= n; ++i) {
		sum += (2 * i - 1) * log(z[i-1]);
		sum += (2 * n + 1 - 2 * i) * log(1.0 - z[i-1]);
	}
	return -n - (1.0 / n) * sum;
}

double A2_significance(double A2){
	/* Page 105 of D'Agostino and Stephens. */
	if (A2 < 0.0)
		return A2;    /* Bogus A2 value - propagate it. */

	/* Check for possibly doctored values. */
	if (A2 <= 0.201)
		return 0.99;
	else if (A2 <= 0.240)
		return 0.975;
	else if (A2 <= 0.283)
		return 0.95;
	else if (A2 <= 0.346)
		return 0.90;
	else if (A2 <= 0.399)
		return 0.85;

	/* Now check for possible inconsistency. */
	if (A2 <= 1.248)
		return 0.25;
	else if (A2 <= 1.610)
		return 0.15;
	else if (A2 <= 1.933)
		return 0.10;
	else if (A2 <= 2.492)
		return 0.05;
	else if (A2 <= 3.070)
		return 0.025;
	else if (A2 <= 3.880)
		return 0.01;
	else if (A2 <= 4.500)
		return 0.005;
	else if (A2 <= 6.000)
		return 0.001;
	else
		return 0.0;
}

double exp_A2_known_mean(double x[], int n, double mean){
	int i;
	double A2;

	/* Sort the first n values. */
	qsort(x, n, sizeof(x[0]), compare_double);

	/* Assuming they match an exponential distribution, transform
	* them to Unif(0,1).
	*/
	for (i = 0; i < n; ++i) {
		x[i] = 1.0 - exp(-x[i] / mean);
	}

	/* Now make the A^2 test to see if they're truly uniform. */
	A2 = compute_A2(x, n);
	return A2_significance(A2);
}

double unif_A2_known_range(double x[], int n, double min_val, double max_val){
	int i;
	double A2;
	double range = max_val - min_val;

	/* Sort the first n values. */
	qsort(x, n, sizeof(x[0]), compare_double);

	/* Transform Unif(min_val, max_val) to Unif(0,1). */
	for (i = 0; i < n; ++i)
		x[i] = (x[i] - min_val) / range;

	/* Now make the A^2 test to see if they're truly uniform. */
	A2 = compute_A2(x, n);
	return A2_significance(A2);
}

double random_exponential(double mean){
	return -mean * log1p(-drand48());
}
