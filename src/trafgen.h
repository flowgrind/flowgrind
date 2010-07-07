#ifndef _FLOWGRIND_H_
#define _FLOWGRIND_H_

#include "daemon.h"
#include "debug.h"
#include "common.h"
#include "fg_math.h"

int next_request_block_size(struct _flow *);
int next_response_block_size(struct _flow *);
double next_interpacket_gap(struct _flow *);
#endif
