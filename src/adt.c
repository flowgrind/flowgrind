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
#ifndef __ADT__
#define __ADT__
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

#endif
