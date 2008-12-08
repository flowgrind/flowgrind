#ifndef __DESTINATION_H__
#define __DESTINATION_H__

void add_flow_destination(struct _request_add_flow_destination *request);
void destination_prepare_fds(fd_set *rfds, fd_set *wfds, fd_set *efds, int *maxfd);
void destination_process_select(fd_set *rfds, fd_set *wfds, fd_set *efds);
void destination_timer_check();

void start_flows(int start_timestamp);

#endif //__DESTINATION_H__
