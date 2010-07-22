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

inline static double calculate(enum _stochastic_distributions type, double param_one, double param_two) {
	
	double val = 0;
	
        switch (type) {
		case NORMAL:
			val = dist_normal ( param_one, param_two );
			DEBUG_MSG(LOG_DEBUG, "calculated normal distribution value %f for parameters %f,%f", val, param_one, param_two);
		break;

		case WEIBULL:
			val = dist_weibull ( param_one, param_two );
			DEBUG_MSG(LOG_DEBUG, "calculated weibull distribution value %f for parameters %f,%f", val, param_one, param_two);
		break;

		case UNIFORM:
			val = dist_uniform ( param_one, param_two ); 
			DEBUG_MSG(LOG_DEBUG, "calculated uniform distribution value %f", val);
		break;

		case CONSTANT:
		/* constant is default */	
		default:
			val = param_one;
			DEBUG_MSG(LOG_DEBUG, "default value %f", val);

	}

	return val;

}	
int next_request_block_size(struct _flow *flow)
{
	int bs = calculate(flow->settings.request_trafgen_options.distribution, 
			   flow->settings.request_trafgen_options.param_one,
			   flow->settings.request_trafgen_options.param_two
			   );

	if (bs < MIN_BLOCK_SIZE) {
                bs = MIN_BLOCK_SIZE;
		DEBUG_MSG(LOG_WARNING, "applied minimal request size limit %d for flow %d", bs, flow->id);
	}

	if (bs > flow->settings.default_request_block_size) {
                bs = flow->settings.default_request_block_size;
		DEBUG_MSG(LOG_WARNING, "applied maximal request size limit %d for flow %d", bs, flow->id);

	}

	DEBUG_MSG(LOG_NOTICE, "calculated request size %d for flow %d", bs, flow->id);
	
	return bs;
}

int next_response_block_size(struct _flow *flow)
{
        int bs = calculate(flow->settings.response_trafgen_options.distribution, 
                           flow->settings.response_trafgen_options.param_one,
                           flow->settings.response_trafgen_options.param_two
                           );
	if (!bs && flow->settings.default_response_block_size)
		bs = flow->settings.default_response_block_size;
        if (bs && bs < MIN_BLOCK_SIZE) {
                bs = MIN_BLOCK_SIZE;
                DEBUG_MSG(LOG_WARNING, "applied minimal request size limit %d for flow %d", bs, flow->id);
        }
        if (bs > flow->settings.default_request_block_size) {
                bs = flow->settings.default_request_block_size;
                DEBUG_MSG(LOG_WARNING, "applied maximal request size limit %d for flow %d", bs, flow->id);
        
        }

        if (bs)
		DEBUG_MSG(LOG_NOTICE, "calculated response size %d for flow %d", bs, flow->id);

        return bs;

}

double next_interpacket_gap(struct _flow *flow) {

	double gap = 0.0;
	if (flow->settings.write_rate)
		gap = (double)1/flow->settings.write_rate;
	else
		gap = calculate(flow->settings.interpacket_gap_trafgen_options.distribution,
                	               flow->settings.interpacket_gap_trafgen_options.param_one,
                        	       flow->settings.interpacket_gap_trafgen_options.param_two
                               	      );

	if (gap)
                DEBUG_MSG(LOG_NOTICE, "calculated next interpacket gap %.6fs for flow %d", gap, flow->id);
        
	return gap;
}
