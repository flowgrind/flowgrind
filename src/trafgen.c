/**
 * @file trafgen.c
 * @brief Routines used by the Flowgrind Daemon for advanced traffic generation
 */

/*
 * Copyright (C) 2010-2013 Christian Samsel <christian.samsel@rwth-aachen.de>
 *
 * This file is part of Flowgrind.
 *
 * Flowgrind is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Flowgrind is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Flowgrind.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

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
#include "fg_math.h"
#include "trafgen.h"

#define MAX_RUNS_PER_DISTRIBUTION 10

inline static double calculate(struct flow *flow, enum distributions type, double param_one, double param_two) {

	double val = 0;

	switch (type) {
		case NORMAL:
			val = dist_normal (flow, param_one, param_two );
			DEBUG_MSG(LOG_DEBUG, "calculated normal distribution value %f for parameters %f,%f", val, param_one, param_two);
		break;

		case UNIFORM:
			val = dist_uniform (flow, param_one, param_two );
			DEBUG_MSG(LOG_DEBUG, "calculated uniform distribution value %f", val);
		break;

		case WEIBULL:
			val = dist_weibull (flow, param_one, param_two );
			DEBUG_MSG(LOG_DEBUG, "calculated weibull distribution value %f for parameters %f,%f", val, param_one, param_two);
		break;

		case EXPONENTIAL:
			val = dist_exponential (flow, param_one);
			DEBUG_MSG(LOG_DEBUG, "calculated exponential distribution value %f for parameters %f", val, param_one);
		break;

		case PARETO:
			val = dist_pareto (flow, param_one, param_two);
			DEBUG_MSG(LOG_DEBUG, "calculated pareto distribution value %f for parameters %f,%f", val, param_one, param_two);
		break;

		case LOGNORMAL:
			val = dist_normal (flow, param_one, param_two );
			DEBUG_MSG(LOG_DEBUG, "calculated lognormal distribution value %f for parameters %f,%f", val, param_one, param_two);
		break;

		case CONSTANT:
		/* constant is default */
		default:
			val = param_one;
			DEBUG_MSG(LOG_DEBUG, "constant value %f", val);

	}

	return val;

}
int next_request_block_size(struct flow *flow)
{
	int bs = 0;
	int i = 0;
	/* recalculate values to match prequisits, but at most 10 times */
	while (( bs < MIN_BLOCK_SIZE || bs > flow->settings.maximum_block_size) && i < MAX_RUNS_PER_DISTRIBUTION) {

		bs = round(calculate(
			   flow,
			   flow->settings.request_trafgen_options.distribution,
			   flow->settings.request_trafgen_options.param_one,
			   flow->settings.request_trafgen_options.param_two
			   ));
		i++;
	}

	/* sanity checks */
	if (i >= MAX_RUNS_PER_DISTRIBUTION && bs < MIN_BLOCK_SIZE) {
		bs = MIN_BLOCK_SIZE;
		DEBUG_MSG(LOG_WARNING, "WARNING: applied minimal request size limit %d for flow %d", bs, flow->id);
	}

	if (i >= MAX_RUNS_PER_DISTRIBUTION && bs > flow->settings.maximum_block_size) {
		bs = flow->settings.maximum_block_size;
		DEBUG_MSG(LOG_WARNING, "WARNING: applied maximal request size limit %d for flow %d", bs, flow->id);

	}

	DEBUG_MSG(LOG_NOTICE, "calculated request size %d for flow %d after %d runs", bs, flow->id, i);

	return bs;
}

int next_response_block_size(struct flow *flow)
{
	int bs = round(calculate(
			   flow,
			   flow->settings.response_trafgen_options.distribution,
			   flow->settings.response_trafgen_options.param_one,
			   flow->settings.response_trafgen_options.param_two
			   ));

	/* sanity checks */
	if (bs && bs < MIN_BLOCK_SIZE) {
		bs = MIN_BLOCK_SIZE;
		DEBUG_MSG(LOG_WARNING, "applied minimal response size limit %d for flow %d", bs, flow->id);
	}
	if (bs > flow->settings.maximum_block_size) {
		bs = flow->settings.maximum_block_size;
		DEBUG_MSG(LOG_WARNING, "applied maximal response size limit %d for flow %d", bs, flow->id);

	}

	if (bs)
		DEBUG_MSG(LOG_NOTICE, "calculated response size %d for flow %d", bs, flow->id);

	return bs;

}

double next_interpacket_gap(struct flow *flow) {

	double gap = 0.0;
	if (flow->settings.write_rate)
		gap = ((double)flow->settings.maximum_block_size)/flow->settings.write_rate;
	else
		gap = calculate(flow,
				flow->settings.interpacket_gap_trafgen_options.distribution,
				       flow->settings.interpacket_gap_trafgen_options.param_one,
				       flow->settings.interpacket_gap_trafgen_options.param_two
				      );

	if (gap)
		DEBUG_MSG(LOG_NOTICE, "calculated next interpacket gap %.6fs for flow %d", gap, flow->id);

	return gap;
}
