#ifndef _FG_SOCKET_H
#define _FG_SOCKET_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netinet/tcp.h>
#include <sys/socket.h>

#ifndef TCP_CONG_MODULE
#define TCP_CONG_MODULE 13
#endif

int set_congestion_control(int fd, const char *cc_alg);
int set_so_debug(int fd);
int set_keepalive(int fd, int how);
int set_nodelay(int fd);
int set_non_blocking (int fd);
int set_route_record(int fd);
int set_so_dscp(int fd, uint8_t);
int set_so_elcn(int fd, int val);
int set_so_icmp(int fd);
int set_tcp_mtcp(int fd);
int set_tcp_nodelay(int fd);
int set_dscp(int sock, uint8_t dscp);
int set_tcp_cork(int fd);
int toggle_tcp_cork(int fd);
int set_window_size(int, int);
int set_window_size_directed(int, int, int);

int set_ip_mtu_discover(int fd);
int get_mtu(int fd);
int get_mss(int fd);

const char *fg_nameinfo(const struct sockaddr *sa, socklen_t salen);
char sockaddr_compare(const struct sockaddr *a, const struct sockaddr *b);

int get_port(int fd);

#endif
