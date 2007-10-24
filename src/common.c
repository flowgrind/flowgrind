#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <time.h>
#include "common.h"

#ifndef SOL_IP
#ifdef IPPROTO_IP
#define SOL_IP		IPPROTO_IP
#endif
#endif

#ifndef SOL_IPV6
#ifdef IPPROTO_IPV6
#define SOL_IPV6	IPPROTO_IPV6
#endif
#endif

extern int debug_level;

void
error(int errcode, const char *msg)
{
	const char *prefix;
	int fatal = 1;

	if (errcode == ERR_FATAL) {
		prefix = "fatal";
	} else if (errcode == ERR_WARNING) {
		prefix = "warning";
		fatal = 0;
	} else {
		prefix = "UNKNOWN ERROR TYPE";
	}
	fprintf(stderr, "%s: %s\n", prefix, msg);
	if (fatal)
		exit(1);
}

ssize_t
read_exactly(int d, void *buf, size_t nbytes)
{
	ssize_t rc = 0;
	size_t bytes_read = 0;
	DEBUG_MSG(5, "d=%d, nbytes=%u", d, (unsigned)nbytes)
	while (bytes_read < nbytes &&
	       (rc = read(d, (char *)buf+bytes_read,
			  nbytes-bytes_read)) > 0) {
		DEBUG_MSG(5, "read=%u", (unsigned)bytes_read)
		bytes_read += rc;
	}
	return rc == -1? rc: (ssize_t) bytes_read;
}

ssize_t
write_exactly(int d, const void *buf, size_t nbytes)
{
	ssize_t rc = 0;
	size_t bytes_written = 0;
	DEBUG_MSG(5, "d=%d, nbytes=%u", d, (unsigned)nbytes)
	while (bytes_written < nbytes && 
	       (rc = write(d, (const char *)buf+bytes_written,
			   nbytes-bytes_written)) > 0) {
		bytes_written += rc;
		DEBUG_MSG(5, "written=%u", (unsigned)bytes_written)
	}
	return rc == -1? rc: (ssize_t) bytes_written;
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

const char *
ctime_us_r(struct timeval *tv, char *buf)
{
	char u_buf[8];

	normalize_tv(tv);
	ctime_r(&tv->tv_sec, buf);
	snprintf(u_buf, sizeof(u_buf), ".%06ld", (long)tv->tv_usec);
	strcat(buf, u_buf);

	return buf;
}

const char *
ctime_us(struct timeval *tv)
{
	static char buf[33];

	ctime_us_r(tv, buf);

	return buf;
}

const char *
debug_timestamp()
{
	struct timeval now;
	static struct timeval last;
	static struct timeval first = {.tv_sec = 0, .tv_usec = 0};
	size_t len;
	static char buf[60];
	
	tsc_gettimeofday(&now);
	if (first.tv_sec == 0 && first.tv_usec == 0)
		first = now;
	len = strftime(buf, sizeof(buf), "%Y/%m/%d %H:%M:%S", localtime(&now.tv_sec));
	snprintf(buf+len, sizeof(buf)-len, ".%06ld [+%8.6lf] (%8.6lf)", (long)now.tv_usec, time_diff(&last, &now), time_diff(&first, &now));
	last = now;
	return buf;
}

double
time_diff(const struct timeval *tv1, const struct timeval *tv2)
{
	return (double) (tv2->tv_sec - tv1->tv_sec)
		+ (double) (tv2->tv_usec - tv1->tv_usec) / 1e6;
}

double
time_diff_now(const struct timeval *tv1)
{
	struct timeval now;

	tsc_gettimeofday(&now);
	return (double) (now.tv_sec - tv1->tv_sec)
		+ (double) (now.tv_usec - tv1->tv_usec) / 1e6;
}

void
time_add(struct timeval *tv, double seconds)
{
	tv->tv_sec += (long)seconds;
	tv->tv_usec += (long)((seconds - (long)seconds) * 1e6);
	normalize_tv(tv);
}

int
time_is_after(const struct timeval *tv1, const struct timeval *tv2)
{
	if (tv1->tv_sec > tv2->tv_sec)
		return 1;
	if (tv1->tv_sec < tv2->tv_sec)
		return 0;
	return (tv1->tv_usec > tv2->tv_usec);
}

/* Set window size for file descriptor FD (which must point to a
   socket) to WINDOW for given direction DIRECTION (typically
   SO_SNDBUF or SO_RCVBUF).  Try hard.  Return actual window size. */
int
set_window_size_directed(int fd, int window, int direction)
{
	int rc, try, w;
	unsigned int optlen = sizeof w;

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
	else
		return w;
}

/* Set window size for file descriptor FD (which must point to a
   socket) to WINDOW.  Try hard.  Return actual window size. */
int
set_window_size(int fd, int window)
{
	int send, receive;

	send = set_window_size_directed(fd, window, SO_SNDBUF);
	receive = set_window_size_directed(fd, window, SO_RCVBUF);
	return send < receive? send: receive;
}

int
set_dscp(int sock, uint8_t dscp)
{
	int optname = IP_TOS;
	int optlevel = SOL_IP;
	int sopt;

	if ((dscp & ~0x3F)) {
		fprintf(stderr, "Error: set_dscp(): bad DSCP value.\n");
		return -1;
	}

	sopt = dscp << 2;
	{
		union {
			struct sockaddr sa;
			char data[128];		/* max socket address
						   structure */
		} un;
		socklen_t len = 128;

		if (getsockname(sock, (struct sockaddr *)un.data, &len) == -1) {
			perror("getsockname");
			return -1;
		}

		switch (un.sa.sa_family) {
		case AF_INET:
			optlevel = SOL_IP;
			optname = IP_TOS;
			break;
		case AF_INET6:
#ifdef IPV6_TCLASS
			optlevel = SOL_IPV6;
			optname = IPV6_TCLASS;
			break;
#else
			error(ERR_WARNING, "system does not support setting "
					"DSCP value in IPv6 traffic class.");
			return 0;	/* return 0 so we don't get two
					   error messages. */
#endif
		default:
			error(ERR_WARNING, "set_dscp(): Unknown address "
					"family");
			return -1;
		}
	}

	if (setsockopt(sock, optlevel, optname, &sopt, sizeof(sopt)) == -1) {
		perror("setsockopt");
		return -1;
	}

	return 0;
}

void set_route_record(int fd)
{
	int rc = 0;
	int opt_on = 1;
#define NROUTES 9 
	int nroutes = NROUTES;
	char rspace[3 + 4 * NROUTES + 1];       

	rc = setsockopt(fd, SOL_IP, IP_RECVOPTS, &opt_on, sizeof(opt_on));
	if (rc == -1) {
		fprintf(stderr, "Unable to set IP_RECVOPTS on socket.");
		error(ERR_FATAL, "setsockopt() failed.");
	}
	bzero(rspace, sizeof(rspace));
	rspace[0] = IPOPT_NOP;
	rspace[1+IPOPT_OPTVAL] = IPOPT_RR;
	rspace[1+IPOPT_OLEN] = sizeof(rspace)-1;
	rspace[1+IPOPT_OFFSET] = IPOPT_MINOFF;
	rc = setsockopt(fd, IPPROTO_IP, IP_OPTIONS, rspace, sizeof(rspace));
	if (rc == -1) {
		fprintf(stderr, "Unable to set IP_OPTIONS(RR) on socket.");
		error(ERR_FATAL, "setsockopt() failed.");
	}
	rc = setsockopt(fd, SOL_IP, IP_TTL, &nroutes, sizeof(nroutes));
	if (rc == -1) {
		fprintf(stderr, "Unable to set IP_TTL on socket.");
		error(ERR_FATAL, "setsockopt() failed.");
	}
}


void 
set_non_blocking (int fd)
{
	int flags, rc;

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		flags = 0;
	rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (rc == -1) {
		perror("set_non_blocking");
		error(ERR_FATAL, "failed to set socket non-blocking.");
		/* NOTREACHED */
	}
}     

void
set_nodelay (int fd)
{
	int rc;
	int opt_on = 1;
	int opt_size = sizeof(opt_on);

	rc = setsockopt( fd, IPPROTO_TCP, TCP_NODELAY, &opt_on, opt_size);
	if (rc == -1) { 
		perror("set_nodelay");
		error(ERR_FATAL, "setsockopt() failed.");
	}
}

int
get_mtu(int fd)
{
#ifdef IP_MTU
	int mtu;
	socklen_t mtu_len = sizeof(mtu);
	if (getsockopt(fd, SOL_IP, IP_MTU, &mtu, &mtu_len) == -1) {
		perror("getsockopt");
		error(ERR_WARNING, "unable to determine path MTU");
	}
	return mtu;
#else
	fd=0;
	return -1;
#endif
}


int
get_mss(int fd)
{
	int mss;
	socklen_t mss_len = sizeof(mss);
	if (getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, &mss_len) == -1) {
		perror("getsockopt");
		error(ERR_WARNING, "unable to determine path MSS");
	}
	return mss;
}


void
set_keepalive (int fd, int how)
{
	int rc;
	int opt_size = sizeof(how);

	rc = setsockopt( fd, IPPROTO_TCP, TCP_NODELAY, &how, opt_size);
	if (rc == -1) { 
		perror("set_keepalive");
		error(ERR_FATAL, "setsockopt() failed.");
	}
}


#define NTP_EPOCH_OFFSET	2208988800ULL

/*
 * Convert `timeval' structure value into NTP format (RFC 1305) timestamp.
 * The ntp pointer must resolve to already allocated memory (8 bytes) that
 * will contain the result of the conversion.
 * NTP format is 4 octets of unsigned integer number of whole seconds since
 * NTP epoch, followed by 4 octets of unsigned integer number of
 * fractional seconds (both numbers are in network byte order).
 */
void
tv2ntp(const struct timeval *tv, char *ntp)
{
	uint32_t msb, lsb;

	msb = tv->tv_sec + NTP_EPOCH_OFFSET;
	lsb = (uint32_t)((double)tv->tv_usec * 4294967296.0 / 1000000.0);

	msb = htonl(msb);
	lsb = htonl(lsb);

	memcpy(ntp, &msb, sizeof(msb));
	memcpy(ntp + sizeof(msb), &lsb, sizeof(lsb));
}

/*
 * Convert 8-byte NTP format timestamp into `timeval' structure value.
 * The counterpart to tv2ntp().
 */
void
ntp2tv(struct timeval *tv, const char *ntp)
{
	uint32_t msb, lsb;

	memcpy(&msb, ntp, sizeof(msb));
	memcpy(&lsb, ntp + sizeof(msb), sizeof(lsb));

	msb = ntohl(msb);
	lsb = ntohl(lsb);

	tv->tv_sec = msb - NTP_EPOCH_OFFSET;
	tv->tv_usec = (uint32_t)((double)lsb * 1000000.0 / 4294967296.0);
}

/* Make sure 0 <= tv.tv_usec < 1000000.  Return 0 if it was normal,
 * positive number otherwise. */
int
normalize_tv(struct timeval *tv)
{
	int result = 0;

	while (tv->tv_usec >= 1000000) {
		tv->tv_usec -= 1000000;
		tv->tv_sec++;
		result++;
	}
	while (tv->tv_usec < 0) {
		tv->tv_usec += 1000000;
		tv->tv_sec--;
		result++;
	}
	return result;
}

int 
tsc_gettimeofday(struct timeval *tv) 
{
	int rc;
#if defined(HAVE_FASTTIME_H) && defined(HAVE_LIBFASTTIME)
	rc = fasttime_gettimeofday(tv);
#elif defined(HAVE_TSCI2_H) && defined(HAVE_LIBTSCI2)
	rc = tsci2_gettimeofday(tv, 0);
#else
	rc = gettimeofday(tv, 0);
#endif
	if (rc != 0) {
		perror("gettimeofday");
		error(ERR_FATAL, "gettimeofday(): failed");
		/* NOTREACHED */
	}
	normalize_tv(tv);

	return 0;
}
