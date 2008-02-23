#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/types.h>

#include "debug.h"
#include "fg_socket.h"

ssize_t
read_exactly(int d, void *buf, size_t nbytes)
{
	ssize_t rc = 0;
	size_t bytes_read = 0;

	DEBUG_MSG(5, "d=%d, nbytes=%u", d, (unsigned)nbytes);
	while (bytes_read < nbytes &&
			(rc = read(d, (char *)buf + bytes_read,
				   nbytes - bytes_read)) > 0) {
		DEBUG_MSG(5, "read=%u", (unsigned)bytes_read);
		bytes_read += rc;
	}

	return rc == -1 ? rc : (ssize_t) bytes_read;
}

ssize_t
write_exactly(int d, const void *buf, size_t nbytes)
{
	ssize_t rc = 0;
	size_t bytes_written = 0;

	DEBUG_MSG(5, "d=%d, nbytes=%u", d, (unsigned)nbytes);
	while (bytes_written < nbytes && 
			(rc = write(d, (const char *)buf+bytes_written,
				    nbytes-bytes_written)) > 0) {
		bytes_written += rc;
		DEBUG_MSG(5, "written=%u", (unsigned)bytes_written)
	}
	return rc == -1 ? rc : (ssize_t) bytes_written;
}

size_t
read_until_plus(int d, char *buf, size_t nbytes)
{
	ssize_t rc = 0;
	size_t bytes_read = 0;
	buf[0] = '\0';

	do {
		rc = read(d, buf+bytes_read, nbytes-bytes_read);
		if (rc == -1 || rc == 0)
			return -1;
		DEBUG_MSG(6, "read %u bytes", (unsigned int)rc);
		bytes_read += rc;
		buf[bytes_read] = '\0';
	} while (!strchr(buf, '+'));

	return bytes_read;
}

int set_window_size_directed(int fd, int window, int direction)
{
	int rc, try, w;
	unsigned int optlen = sizeof w;

	DEBUG_MSG(3, "Setting %sBUF on fd %d to %d", 
			(direction == SO_SNDBUF ? "SND" : "RCV"),
			 fd, window);

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
		DEBUG_MSG(3, "Set %sBUF on fd %d to %d (instead of %d)", 
				(direction == SO_SNDBUF ? "SND" : "RCV"), 
				 fd, w, window);

		return w;
	}
}


int set_window_size(int fd, int window)
{
	int send, receive;

	DEBUG_MSG(3, "Setting window size of fd %d to %d", fd, window);

	send = set_window_size_directed(fd, window, SO_SNDBUF);
	receive = set_window_size_directed(fd, window, SO_RCVBUF);
	return send < receive? send: receive;
}

int set_dscp(int fd, uint8_t dscp)
{
	int optname = IP_TOS;
	int optlevel = IPPROTO_IP;

	DEBUG_MSG(3, "Setting DSCP of fd %d to %0x", fd, dscp);

	if (dscp & ~0x3F) {
		errno = EINVAL;
		return -1;
	}

	dscp <<= 2;

	/* XXX: This needs some tweaking/testing for IPng. */
	return setsockopt(fd, optlevel, optname, &dscp, sizeof(dscp));
}

int set_route_record(int fd)
{
#define NROUTES 9 
	int rc = 0;
	int opt_on = 1;
	int nroutes = NROUTES;
	char rspace[3 + 4 * NROUTES + 1];       

	DEBUG_MSG(3, "Enabling route_record for fd %d ", fd);

	if (!(rc = setsockopt(fd, IPPROTO_IP, IP_RECVOPTS, &opt_on, sizeof(opt_on))))
		return rc;

	bzero(rspace, sizeof(rspace));
	rspace[0] = IPOPT_NOP;
	rspace[1+IPOPT_OPTVAL] = IPOPT_RR;
	rspace[1+IPOPT_OLEN] = sizeof(rspace)-1;
	rspace[1+IPOPT_OFFSET] = IPOPT_MINOFF;
	if (!(rc = setsockopt(fd, IPPROTO_IP, IP_OPTIONS, rspace, sizeof(rspace))))
		return rc;
	return setsockopt(fd, IPPROTO_TCP, IP_TTL, &nroutes, sizeof(nroutes));
}

int set_non_blocking(int fd)
{
	int flags;

	DEBUG_MSG(3, "Setting fd %d non-blocking", fd);


	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		flags = 0;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}     

int set_nodelay(int fd)
{
	int opt_on = 1;

	DEBUG_MSG(3, "Setting TCP_NODELAY on fd %d", fd);

	return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt_on, sizeof(opt_on));
}

int get_mtu(int fd)
{
#ifdef IP_MTU
	int mtu;
	socklen_t mtu_len = sizeof(mtu);

	if (getsockopt(fd, SOL_IP, IP_MTU, &mtu, &mtu_len) == -1)
		return -1;

	return mtu;
#else
	return 0;
#endif
}

int get_mss(int fd)
{
	int mss;
	socklen_t mss_len = sizeof(mss);

	if (getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, &mss_len) == -1)
		return -1;

	return mss;
}

int set_keepalive(int fd, int how)
{
	DEBUG_MSG(3, "Setting TCP_KEEPALIVE(%d) on fd %d", how, fd);

	return setsockopt(fd, IPPROTO_TCP, SO_KEEPALIVE, &how, sizeof(how));
}

int set_congestion_control(int fd, const char *cc_alg)
{
#ifdef __LINUX__
	int opt_len = strlen(cc_alg);

	DEBUG_MSG(3, "Setting cc_alg=\"%s\" for fd %d", cc_alg, fd);
	return setsockopt(flow[id].sock, IPPROTO_TCP,
			TCP_CONG_MODULE, cc_alg, opt_len );
#else
	DEBUG_MSG(2, "Cannot set cc_alg for OS other than Linux");
	return -1;
#endif
}

int set_so_elcn(int fd, int val)
{
#ifndef TCP_ELCN
#define TCP_ELCN 20
#endif
	DEBUG_MSG(3, "Setting TCP_ELCN on fd %d", fd);

	return setsockopt(fd, IPPROTO_TCP, TCP_ELCN, &val, sizeof(val));
}

int set_so_icmp(int fd)
{
#ifndef TCP_ICMP
#define TCP_ICMP 21
#endif
	int opt = 1;
	DEBUG_MSG(3, "Setting TCP_ICMP on fd %d", fd);

	return setsockopt(fd, IPPROTO_TCP, TCP_ICMP, &opt, sizeof(opt));

}

int set_so_cork(int fd)
{
#ifdef __LINUX__
	int opt = 1;

	DEBUG_MSG(3, "Setting TCP_CORK on fd %d", fd);
	return setsockopt(fd, IPPROTO_TCP, TCP_CORK, &opt, sizeof(opt));
#else
	DEBUG_MSG(2, "Cannot set TCP_CORK for OS other than Linux");
	return -1;
#endif
}

int set_so_debug(int fd)
{
	int opt = 1;

	DEBUG_MSG(3, "Setting TCP_DEBUG on fd %d", fd);
	return setsockopt(fd, SOL_SOCKET, SO_DEBUG, &opt, sizeof(opt));
}

const char *fg_nameinfo(const struct sockaddr *sa)
{
	static char host[NI_MAXHOST];

	if (getnameinfo(sa, sizeof(*sa), host, sizeof(host), 
				NULL, 0, NI_NUMERICHOST) != 0) {
		*host = '\0';
	}

	if (*host == '\0')
		inet_ntop(sa->sa_family, sa, host, sizeof(host));
		
	return host;
}

char sockaddr_compare(const struct sockaddr *a, const struct sockaddr *b)
{
	assert(a != NULL);
	assert(b != NULL);

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

