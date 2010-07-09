#ifndef HAVE_CONFIG_H
#include <config.h>
#endif
#include <assert.h>
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
#include "trafgen.h"

int next_request_block_size(struct _flow *flow)
{
        int bs = 0;

        switch (flow->settings.traffic_generation_type)
        {
		case UNIFORM:
			bs = (rand() % (flow->settings.default_request_block_size - MIN_BLOCK_SIZE) ) + MIN_BLOCK_SIZE;
			break;
		case POISSON:
			break;
                case WEIBULL:
			break;
                case CONSTANT:
                default:
                bs = flow->settings.default_request_block_size;
        }
        DEBUG_MSG(LOG_NOTICE, "calculated request size %d for flow %d", bs, flow->id);
	assert(bs >= MIN_BLOCK_SIZE && bs <= flow->settings.default_request_block_size);
        return bs;
}

int next_response_block_size(struct _flow *flow)
{
        int bs = 0;

        switch (flow->settings.traffic_generation_type)
        {
		case UNIFORM:
			break;
                case POISSON:
			break;
                case WEIBULL:
			break;
                case CONSTANT:
                default:
                bs = flow->settings.default_response_block_size;
        }

        if (bs)
                DEBUG_MSG(LOG_NOTICE, "calculated next response size %d for flow %d", bs, flow->id);
	assert(bs == 0 || (bs >= MIN_BLOCK_SIZE && bs <= flow->settings.default_response_block_size) );
        return bs;
}

double next_interpacket_gap(struct _flow *flow)
{
        double gap = .0;

        switch (flow->settings.traffic_generation_type)
        {
		case UNIFORM:
			break;
                case POISSON:
			break;
                case WEIBULL:
			break;
                case CONSTANT:
                default:
                if (flow->settings.write_rate) {
                        gap = (double)1/flow->settings.write_rate;
                }
        }
        if (gap)
                DEBUG_MSG(LOG_NOTICE, "calculated next interpacket gap %.6fms for flow %d", gap, flow->id);
        return gap;
}
