#ifndef _DEBUG_H
#define _DEBUG_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

void decrease_debuglevel();
void increase_debuglevel();

#ifdef DEBUG

#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

unsigned debug_level;

const char *debug_timestamp(void);

#define DEBUG_MSG(message_level, msg, args...) \
		if (debug_level>=message_level) { \
			fprintf(stderr, "%s %s:%d  [%d/%d] " msg "\n", \
					debug_timestamp(), __FUNCTION__, \
					__LINE__, getpid(), \
					(unsigned int)pthread_self()%USHRT_MAX, ##args); \
		}
#else

#define DEBUG_MSG(message_level, msg, args...) do {} while(0)

#endif
#endif
