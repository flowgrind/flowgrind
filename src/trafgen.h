#ifndef _TRAFGEN_H_
#define _TRAFGEN_H_

extern int next_request_block_size(struct _flow *);
extern int next_response_block_size(struct _flow *);
extern double next_interpacket_gap(struct _flow *);

#endif
