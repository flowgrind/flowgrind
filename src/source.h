#ifndef __SOURCE_H__
#define __SOURCE_H__

int add_flow_source(struct _request_add_flow_source *request);
int source_prepare_fds(fd_set *rfds, fd_set *wfds, fd_set *efds, int *maxfd);
void source_process_select(fd_set *rfds, fd_set *wfds, fd_set *efds);

#endif //__SOURCE_H__
