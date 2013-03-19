/* Header file for Anderson-Darling Test, see adt.c for details */

#ifndef _ADT_H_
#define _ADT_H_

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "flowgrind.h"

/* Supported metrics for ADT */
enum _adt_data_type
{
	adt_throughput,
	adt_iat,
	adt_rtt,

	adt_type_max
};

/* FIXME: this should be per flow! */
/* Add datapoint to the statistics pool */
void adt_add_data(double v, enum endpoint direction, enum _adt_data_type type);

double adt_get_result_range(enum endpoint direction, enum _adt_data_type type,
		      double lower_bound, double upper_bound);
double adt_get_result_mean(enum endpoint direction, enum _adt_data_type type,
		      double mean);

int adt_too_much_data();

#endif //_ADT_H_
