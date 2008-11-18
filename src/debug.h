#ifndef _DEBUG_H
#define _DEBUG_H

#ifdef DEBUG
inline void decrease_debuglevel();
inline void increase_debuglevel();

#include <sys/types.h>
#include <unistd.h>

unsigned debug_level;

inline const char *debug_timestamp(void);

#define DEBUG_MSG(message_level, msg, args...) \
        do { \
                if (debug_level>=message_level) { \
                        fprintf(stderr, "%s %s:%d  [%d] " msg "\n", \
                                        debug_timestamp(), __FUNCTION__, \
                                        __LINE__, getpid(), ##args); \
                } \
        } while(0)

#else

#define DEBUG_MSG(message_level, msg, args...) do {} while(0)

#endif
#endif
