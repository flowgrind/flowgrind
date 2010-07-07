#ifndef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
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

int next_request_block_size(struct _flow *flow)
{
        int bs = 0;
        switch (flow->settings.traffic_generation_type)
        {
                case POISSON:
                case WEIBULL:
                case CONSTANT:
                default:
                bs = flow->settings.default_request_block_size;
        }
        DEBUG_MSG(LOG_NOTICE, "calculated request size %d for flow %d", bs, flow->id);
        return bs;
}

int next_response_block_size(struct _flow *flow)
{
        int bs = 0;
        switch (flow->settings.traffic_generation_type)
        {
                case POISSON:
                case WEIBULL:
                case CONSTANT:
                default:
                bs = flow->settings.default_response_block_size;
        }

        if (bs)
                DEBUG_MSG(LOG_NOTICE, "calculated next response size %d for flow %d", bs, flow->id);

        return bs;
}

double next_interpacket_gap(struct _flow *flow)
{
        double gap = 0;

        /* old variant just for documentation.
         * see: http://portal.acm.org/citation.cfm?id=208389.208390 
        
        if (flow->settings.poisson_distributed) {
                double urand = (double)((random()+1.0)/(RANDOM_MAX+1.0));
                double erand = -log(urand) * 1/(double)flow->settings.write_rate;
                delay = erand;
        } else { 
                delay = (double)1/flow->settings.write_rate;
        }  */

        switch (flow->settings.traffic_generation_type)
        {
                case POISSON:
                case WEIBULL:
                case CONSTANT:
                default:
                if (flow->settings.write_rate) {
                        gap = (double)1/flow->settings.write_rate;
                        DEBUG_MSG(LOG_DEBUG, "flow %d has rate %u", flow->id, flow->settings.write_rate);
                }
        }
        if (gap)
                DEBUG_MSG(LOG_NOTICE, "calculated next interpacket gap %.6f for flow %d", gap, flow->id);
        return gap;
}
