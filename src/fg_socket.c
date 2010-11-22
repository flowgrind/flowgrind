#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#ifdef DEBUG
#include <assert.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifdef HAVE_LIBNL
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#endif

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#include "fg_pcap.h"
#endif

#include "common.h"
#include "debug.h"
#include "fg_socket.h"

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

#ifndef IP_MTU
/* Someone forgot to put IP_MTU in <bits/in.h> */
#define IP_MTU 14
#endif

int set_window_size_directed(int fd, int window, int direction)
{
	int rc, try, w;
	unsigned int optlen = sizeof w;

	if (window <= 0)
			{ DEBUG_MSG(LOG_NOTICE, "Getting %sBUF from fd %d ",
				(direction == SO_SNDBUF ? "SND" : "RCV"), fd); }
	else
			{ DEBUG_MSG(LOG_NOTICE, "Setting %sBUF on fd %d to %d",
				(direction == SO_SNDBUF ? "SND" : "RCV"),
				fd, window); }

	rc = getsockopt(fd, SOL_SOCKET, direction, (char *)&w, &optlen);
	if (rc == -1)
		return -1;
	if (window <= 0)
		return w;

	try = window;
	do {
		rc = setsockopt(fd, SOL_SOCKET, direction,
				(char *)&try, optlen);
		try *= 7;
		try /= 8;
	} while (try > w && rc == -1);

	rc = getsockopt(fd, SOL_SOCKET, direction, (char *)&w, &optlen);
	if (rc == -1)
		return -1;
	else {
		DEBUG_MSG(LOG_NOTICE, "Set %sBUF on fd %d to %d (instead of %d)",
				(direction == SO_SNDBUF ? "SND" : "RCV"),
				 fd, w, window);

		return w;
	}
}


int set_window_size(int fd, int window)
{
	int send, receive;

	if (window <= 0)
		{ DEBUG_MSG(LOG_NOTICE, "Getting window size of fd %d", fd); }
	else
		{ DEBUG_MSG(LOG_NOTICE, "Setting window size of fd %d to %d", fd, window); }

	send = set_window_size_directed(fd, window, SO_SNDBUF);
	receive = set_window_size_directed(fd, window, SO_RCVBUF);
	return send < receive? send: receive;
}

int set_dscp(int fd, uint8_t dscp)
{
	int optname = IP_TOS;
	int optlevel = IPPROTO_IP;

	DEBUG_MSG(LOG_NOTICE, "Setting DSCP of fd %d to %0x", fd, dscp);

	if (dscp & ~0x3F) {
		errno = EINVAL;
		return -1;
	}

	dscp <<= 2;

	return setsockopt(fd, optlevel, optname, &dscp, sizeof(dscp));
}

int set_route_record(int fd)
{
#define NROUTES 9
	int rc = 0;
	int opt_on = 1;
	int nroutes = NROUTES;
	char rspace[3 + 4 * NROUTES + 1];

	DEBUG_MSG(LOG_NOTICE, "Enabling route_record for fd %d ", fd);

	if (!(rc = setsockopt(fd, IPPROTO_IP, IP_RECVOPTS, &opt_on, sizeof(opt_on))))
		return rc;

	bzero(rspace, sizeof(rspace));
	rspace[0] = IPOPT_NOP;
	rspace[1+IPOPT_OPTVAL] = IPOPT_RR;
	rspace[1+IPOPT_OLEN] = sizeof(rspace)-1;
	rspace[1+IPOPT_OFFSET] = IPOPT_MINOFF;
	if (!(rc = setsockopt(fd, IPPROTO_IP, IP_OPTIONS, rspace, sizeof(rspace))))
		return rc;
	return setsockopt(fd, SOL_TCP, IP_TTL, &nroutes, sizeof(nroutes));
}

int set_non_blocking(int fd)
{
	int flags;

	DEBUG_MSG(LOG_NOTICE, "Setting fd %d non-blocking", fd);


	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		flags = 0;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int set_nodelay(int fd)
{
	int opt_on = 1;

	DEBUG_MSG(LOG_NOTICE, "Setting TCP_NODELAY on fd %d", fd);

	return setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt_on, sizeof(opt_on));
}

int get_pmtu(int fd)
/* returns path mtu */
{
#ifdef SOL_IP
	int mtu = 0;

	socklen_t mtu_len = sizeof(mtu);

	if (getsockopt(fd, SOL_IP, IP_MTU, &mtu, &mtu_len) == -1)
		return -1;

	return mtu;
#else
	UNUSED_ARGUMENT(fd);
	return 0;
#endif
}

int get_imtu(int fd)
/* returns interface mtu */
{
	struct sockaddr_storage sa;
	socklen_t sl = sizeof(sa);

  	struct ifreq ifreqs[20];

   	struct ifconf ifconf;
   	int nifaces, i, found = 0;

   	memset(&ifconf,0,sizeof(ifconf));
   	ifconf.ifc_buf = (char*)(ifreqs);
   	ifconf.ifc_len = sizeof(ifreqs);

	if (getsockname(fd, (struct sockaddr *)&sa, &sl) < 0)
		return -1;
	
	if (ioctl(fd, SIOCGIFCONF, &ifconf) < 0)
		return -1;
	
	nifaces =  ifconf.ifc_len/sizeof(struct ifreq);

	for(i = 0; i < nifaces; i++)
   	{	
		if (sockaddr_compare((struct sockaddr *)&ifreqs[i].ifr_addr, (struct sockaddr *)&sa)) {
			found = 1;
			break;
		}
   	}

	if (ioctl(fd, SIOCGIFMTU, &ifreqs[i]) < 0)
		return -1;

	DEBUG_MSG(LOG_NOTICE, "interface %s (%s) has mtu %d",
		  ifreqs[i].ifr_name,
		  fg_nameinfo((struct sockaddr *)&ifreqs[i].ifr_addr, sizeof(struct sockaddr)),
		  ifreqs[i].ifr_mtu);
	
	return ifreqs[i].ifr_mtu;
}

int set_keepalive(int fd, int how)
{
	DEBUG_MSG(LOG_NOTICE, "Setting TCP_KEEPALIVE(%d) on fd %d", how, fd);

	return setsockopt(fd, SOL_TCP, SO_KEEPALIVE, &how, sizeof(how));
}

int set_congestion_control(int fd, const char *cc_alg)
{
#ifdef __LINUX__
	DEBUG_MSG(LOG_NOTICE, "Setting cc_alg=\"%s\" for fd %d", cc_alg, fd);
	return setsockopt(fd, IPPROTO_TCP, TCP_CONG_MODULE, cc_alg, strlen(cc_alg));
#else
	UNUSED_ARGUMENT(fd);
	UNUSED_ARGUMENT(cc_alg);
	DEBUG_MSG(LOG_ERR, "Cannot set cc_alg for OS other than Linux");
	return -1;
#endif
}

int set_so_elcn(int fd, int val)
{
#ifndef TCP_ELCN
#define TCP_ELCN 20
#endif
	DEBUG_MSG(LOG_WARNING, "Setting TCP_ELCN on fd %d", fd);

	return setsockopt(fd, SOL_TCP, TCP_ELCN, &val, sizeof(val));
}

int set_so_lcd(int fd)
{
#ifndef TCP_LCD
#define TCP_LCD 21
#endif
	int opt = 1;
	DEBUG_MSG(LOG_WARNING, "Setting TCP_LCD on fd %d", fd);

	return setsockopt(fd, SOL_TCP, TCP_LCD, &opt, sizeof(opt));

}

int set_ip_mtu_discover(int fd)
{
#ifdef SOL_IP
	const int dummy = IP_PMTUDISC_DO;

	DEBUG_MSG(LOG_WARNING, "Setting IP_MTU_DISCOVERY on fd %d", fd);
	return setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &dummy, sizeof(dummy)) ;

#else
return -1;
#endif

}

int set_tcp_cork(int fd)
{
#ifdef __LINUX__
	int opt = 1;

	DEBUG_MSG(LOG_WARNING, "Setting TCP_CORK on fd %d", fd);
	return setsockopt(fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
#else
	UNUSED_ARGUMENT(fd);
	DEBUG_MSG(LOG_ERR, "Cannot set TCP_CORK for OS other than Linux");
	return -1;
#endif
}

int toggle_tcp_cork(int fd)
{
#ifdef __LINUX__
	int opt = 0;

	DEBUG_MSG(LOG_WARNING, "Clearing TCP_CORK on fd %d", fd);
	if (setsockopt(fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt)) == -1)
		return -1;
	return set_tcp_cork(fd);
#else
	UNUSED_ARGUMENT(fd);
	DEBUG_MSG(LOG_ERR, "Cannot toggle TCP_CORK for OS other than Linux");
	return -1;
#endif
}
	
int set_tcp_mtcp(int fd)
{
#ifndef TCP_MTCP
#define TCP_MTCP 15
#endif	
	int opt = 1; 
	
	DEBUG_MSG(LOG_WARNING, "Setting TCP_MTCP on fd %d", fd);
	return setsockopt(fd, SOL_TCP, TCP_MTCP, &opt, sizeof(opt));
}

int set_tcp_nodelay(int fd)
{
	int opt = 1;

	DEBUG_MSG(LOG_WARNING, "Setting TCP_NODELAY on fd %d", fd);
	return setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
}

int set_so_debug(int fd)
{
	int opt = 1;

	DEBUG_MSG(LOG_WARNING, "Setting TCP_DEBUG on fd %d", fd);
	return setsockopt(fd, SOL_SOCKET, SO_DEBUG, &opt, sizeof(opt));
}

const char *fg_nameinfo(const struct sockaddr *sa, socklen_t salen)
{
	static char host[NI_MAXHOST];

	if (getnameinfo(sa, salen, host, sizeof(host),
				NULL, 0, NI_NUMERICHOST) != 0) {
		*host = '\0';
	}

	if (*host == '\0')
		inet_ntop(sa->sa_family, sa, host, sizeof(host));

	return host;
}

char sockaddr_compare(const struct sockaddr *a, const struct sockaddr *b)
{
#ifdef DEBUG
	assert(a != NULL);
	assert(b != NULL);
#endif
	if (a->sa_family != b->sa_family)
		return 0;

	if (a->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;

		/* compare scope */
		if (a6->sin6_scope_id && b6->sin6_scope_id &&
				a6->sin6_scope_id != b6->sin6_scope_id)
			return 0;

		if ((memcmp(&(a6->sin6_addr), &in6addr_any,
						sizeof(struct in6_addr)) != 0) &&
				(memcmp(&(b6->sin6_addr), &in6addr_any,
					sizeof(struct in6_addr)) != 0) &&
				(memcmp(&(a6->sin6_addr), &(b6->sin6_addr),
					sizeof(struct in6_addr)) != 0))
			return 0;

		/* compare port part
		 * either port may be 0(any), resulting in a good match */
		return (a6->sin6_port == 0) || (b6->sin6_port == 0) ||
				(a6->sin6_port == b6->sin6_port);
	}

	if (a->sa_family == AF_INET) {
		const struct sockaddr_in *a_in = (const struct sockaddr_in *)a;
		const struct sockaddr_in *b_in = (const struct sockaddr_in *)b;

		/* compare address part
		 * either may be INADDR_ANY, resulting in a good match */
		if ((a_in->sin_addr.s_addr != INADDR_ANY) &&
				(b_in->sin_addr.s_addr != INADDR_ANY) &&
				(a_in->sin_addr.s_addr != b_in->sin_addr.s_addr))
			return 0;

		/* compare port part */
		/* either port may be 0(any), resulting in a good match */
		return (a_in->sin_port == 0) || (b_in->sin_port == 0) ||
				(a_in->sin_port == b_in->sin_port);
	}

	/* For all other socket types, return false. Bummer */
	return 0;
}

int get_port(int fd)
{
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	static char service[NI_MAXSERV];

	if (getsockname(fd, (struct sockaddr*)&addr, &addrlen) != 0)
		return -1;

	if (getnameinfo((struct sockaddr*)&addr, addrlen, NULL, 0,
				service, sizeof(service), NI_NUMERICSERV) != 0)
		return -1;

	return atoi(service);
}
