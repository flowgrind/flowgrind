#ifndef _COMMON_H_
#define _COMMON_H_

#define min(a, b)	((a) < (b) ? (a) : (b))
#define max(a, b)	((a) > (b) ? (a) : (b))

#include <limits.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_FASTTIME_H
#include <fasttime.h>
#endif

#ifdef HAVE_TSCI2_H
#include <tsci2.h>
#endif

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>

#define ERR_FATAL	0
#define ERR_WARNING	1

extern unsigned debug_level;
#ifdef DEBUG
#define DEBUG_MSG(message_level, msg, args...) if (debug_level>=message_level) { fprintf(stderr, "%s %s:%d  [%d] " msg "\n", debug_timestamp(), __FUNCTION__, __LINE__, getpid(), ##args); }
#else
#define DEBUG_MSG(message_level, msg, args...)
#endif

struct _reply {
	struct timeval sent;
	struct timeval server_time;
	double iat;
} reply;

void error(int, const char *);
ssize_t read_exactly(int, void *, size_t);
size_t read_until_plus(int d, char *buf, size_t nbytes);
ssize_t write_exactly(int, const void *, size_t);
double time_diff(const struct timeval *, const struct timeval *);
double time_diff_now(const struct timeval *tv1);
void time_add(struct timeval *tv, double seconds);
int set_window_size_directed(int, int, int);
int set_window_size(int, int);
void set_route_record(int fd);
void set_non_blocking (int fd);
int get_mtu(int fd);
int get_mss(int fd);
void set_nodelay (int fd);
void set_keepalive (int fd, int how);
int set_dscp(int, uint8_t);
void tv2ntp(const struct timeval *tv, char *);
void ntp2tv(struct timeval *tv, const char *);
const char * ctime_us_r(struct timeval *tv, char *buf);
const char * ctime_us(struct timeval *tv);
const char * debug_timestamp(void);
int normalize_tv(struct timeval *);
int time_is_after(const struct timeval *, const struct timeval *);
const char * fg_nameinfo(const struct sockaddr *sa);
char sockaddr_compare(const struct sockaddr *a, const struct sockaddr *b);
int tsc_gettimeofday(struct timeval *tv);

#if defined(HAVE_FASTTIME_H) && defined(HAVE_LIBFASTTIME)
#define tsc_init()		fasttime_init()
#elif defined(HAVE_TSCI2_H) && defined(HAVE_LIBTSCI2)
#define tsc_init()		tsci2_init(TSCI2_DAEMON | \
				           TSCI2_CLIENT | \
				           TSCI2_FALLBACK)
#else
#define tsc_init()		;
#endif

#endif 
