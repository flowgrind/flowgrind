#ifndef HAVE_CONFIG_H
#include <config.h>
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <float.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>

#include "daemon.h"
#include "debug.h"
#include "common.h"
#include "fg_math.h"
#include "trafgen.h"

inline static double calculate(int type, double param_one, double param_two, int minval, int maxval, double defaultval) {
	
	double val = 0;
	
        switch (type) {
		case NORMAL:
		
		break;

		case WEIBULL:

		break;

		case CONSTANT:
		/* constant is default */	
		default:
			val = defaultval;

	}

	if (val && val < minval)
		val = minval;

	if (val > maxval)
		val = maxval;

	return val;

}	
int next_request_block_size(struct _flow *flow)
{
	int bs = calculate(flow->settings.request_trafgen_options.distribution, 
			   flow->settings.request_trafgen_options.param_one,
			   flow->settings.request_trafgen_options.param_two,
			   MIN_BLOCK_SIZE,
		 	   flow->settings.default_request_block_size,
			   flow->settings.default_request_block_size
			   );
	
	DEBUG_MSG(LOG_NOTICE, "calculated request size %d for flow %d", bs, flow->id);
	
	return bs;
}

int next_response_block_size(struct _flow *flow)
{
        int bs = calculate(flow->settings.response_trafgen_options.distribution, 
                           flow->settings.response_trafgen_options.param_one,
                           flow->settings.response_trafgen_options.param_two,
                           MIN_BLOCK_SIZE,
                           flow->settings.default_response_block_size,
			   flow->settings.default_response_block_size
                           );
        if (bs)
		DEBUG_MSG(LOG_NOTICE, "calculated response size %d for flow %d", bs, flow->id);

        return bs;

}

double next_interpacket_gap(struct _flow *flow)
{
        double gap = calculate(flow->settings.interpacket_gap_trafgen_options.distribution, 
			       flow->settings.interpacket_gap_trafgen_options.param_one,
                               flow->settings.interpacket_gap_trafgen_options.param_two,
                               0,
                               60000,
			       0
                               );

	if (gap)
                DEBUG_MSG(LOG_NOTICE, "calculated next interpacket gap %.6fms for flow %d", gap, flow->id);
        
	return gap;
}
