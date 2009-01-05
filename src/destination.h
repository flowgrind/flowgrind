#ifndef __DESTINATION_H__
#define __DESTINATION_H__

void add_flow_destination(struct _request_add_flow_destination *request);
int destination_prepare_fds(fd_set *rfds, fd_set *wfds, fd_set *efds, int *maxfd);
void destination_process_select(fd_set *rfds, fd_set *wfds, fd_set *efds);

#endif //__DESTINATION_H__
