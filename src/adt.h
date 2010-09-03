#ifndef _ADT_H_
#define _ADT_H_

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "flowgrind.h"

/*
Notes on Anderson Darlington Test

   Both routines return a significance level, as described earlier. This
   is a value between 0 and 1.  The correct use of the routines is to
   pick in advance the threshold for the significance level to test;
   generally, this will be 0.05, corresponding to 5%, as also described
   above.  Subsequently, if the routines return a value strictly less
   than this threshold, then the data are deemed to be inconsistent with
   the presumed distribution, *subject to an error corresponding to the
   significance level*.  That is, for a significance level of 5%, 5% of
   the time data that is indeed drawn from the presumed distribution
   will be erroneously deemed inconsistent.

   Thus, it is important to bear in mind that if these routines are used
   frequently, then one will indeed encounter occasional failures, even
   if the data is unblemished.


   We note, however, that the process of computing Y above might yield
   values of Y outside the range (0..1).  Such values should not occur
   if X is indeed distributed according to G(x), but easily can occur if
   it is not.  In the latter case, we need to avoid computing the
   central A2 statistic, since floating-point exceptions may occur if
   any of the values lie outside (0..1).  Accordingly, the routines
   check for this possibility, and if encountered, return a raw A2
   statistic of -1.  The routine that converts the raw A2 statistic to a
   significance level likewise propagates this value, returning a
   significance level of -1.  So, any use of these routines must be
   prepared for a possible negative significance level.

   The last important point regarding use of A2 statistic concerns n,
   the number of values being tested.  If n < 5 then the test is not
   meaningful, and in this case a significance level of -1 is returned.

   On the other hand, for "real" data the test *gains* power as n
   becomes larger.  It is well known in the statistics community that
   real data almost never exactly matches a theoretical distribution,
   even in cases such as rolling dice a great many times (see [Pa94] for
   a brief discussion and references).  The A2 test is sensitive enough
   that, for sufficiently large sets of real data, the test will almost
   always fail, because it will manage to detect slight imperfections in
   the fit of the data to the distribution.
*/

enum _adt_data_type
{
        adt_throughput,
        adt_iat,
        adt_rtt,

        adt_type_max
};

void adt_add_data(double v, enum endpoint direction, enum _adt_data_type type);

double adt_get_result_range(enum endpoint direction, enum _adt_data_type type,
                      double lower_bound, double upper_bound);
double adt_get_result_mean(enum endpoint direction, enum _adt_data_type type,
                      double mean);

int adt_too_much_data();

#endif //_ADT_H_
