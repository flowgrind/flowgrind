#ifndef __DESTINATION_H__
#define __DESTINATION_H__

void add_flow_destination(struct _request_add_flow_destination *request);
int accept_reply(struct _flow *flow);
int accept_data(struct _flow *flow);

#endif //__DESTINATION_H__
