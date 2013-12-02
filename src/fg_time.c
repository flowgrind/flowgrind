/*
 * fg_time.c - Timing related routines used by Flowgrind
 *
 * Copyright (C) Christian Samsel <christian.samsel@rwth-aachen.de>, 2010-2013
 * Copyright (C) Tim Kosse <tim.kosse@gmx.de>, 2009
 * Copyright (C) Daniel Schaffrath <daniel.schaffrath@mac.com>, 2007-2008
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "common.h"
#include "fg_time.h"

const char * ctime_us_r(struct timeval *tv, char *buf) {
	char u_buf[8];

	normalize_tv(tv);
	ctime_r(&tv->tv_sec, buf);
	snprintf(u_buf, sizeof(u_buf), ".%06ld", (long)tv->tv_usec);
	strcat(buf, u_buf);

	return buf;
}

const char * ctime_us(struct timeval *tv) {
	static char buf[33];

	ctime_us_r(tv, buf);

	return buf;
}

double time_diff(const struct timeval *tv1, const struct timeval *tv2) {
	return (double) (tv2->tv_sec - tv1->tv_sec)
		+ (double) (tv2->tv_usec - tv1->tv_usec) / 1e6;
}

double time_diff_now(const struct timeval *tv1) {
	struct timeval now;

	tsc_gettimeofday(&now);
	return (double) (now.tv_sec - tv1->tv_sec)
		+ (double) (now.tv_usec - tv1->tv_usec) / 1e6;
}

void time_add(struct timeval *tv, double seconds) {
	tv->tv_sec += (long)seconds;
	tv->tv_usec += (long)((seconds - (long)seconds) * 1e6);
	normalize_tv(tv);
}

int time_is_after(const struct timeval *tv1, const struct timeval *tv2) {
	if (tv1->tv_sec > tv2->tv_sec)
		return 1;
	if (tv1->tv_sec < tv2->tv_sec)
		return 0;
	return tv1->tv_usec > tv2->tv_usec;
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
void tv2ntp(const struct timeval *tv, char *ntp) {
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
void ntp2tv(struct timeval *tv, const char *ntp) {
	uint32_t msb, lsb;

	memcpy(&msb, ntp, sizeof(msb));
	memcpy(&lsb, ntp + sizeof(msb), sizeof(lsb));

	msb = ntohl(msb);
	lsb = ntohl(lsb);

	tv->tv_sec = msb - NTP_EPOCH_OFFSET;
	tv->tv_usec = (uint32_t)((double)lsb * 1000000.0 / 4294967296.0);
}

/*
 * Make sure 0 <= tv.tv_usec < 1000000.  Return 0 if it was normal,
 * positive number otherwise.
 */
int normalize_tv(struct timeval *tv) {
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

int tsc_gettimeofday(struct timeval *tv) {
	int rc;
	rc = gettimeofday(tv, 0);
	if (rc != 0) {
		error(ERR_FATAL, "gettimeofday(): failed: %s",
		      strerror(errno));
	}
	normalize_tv(tv);

	return 0;
}
