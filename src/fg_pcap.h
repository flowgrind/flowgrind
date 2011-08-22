#include "daemon.h"
#include <pcap.h>
#include <pthread.h>
void fg_pcap_init();
void fg_pcap_go(struct _flow *);
void fg_pcap_cleanup(void* arg);
pthread_mutex_t pcap_mutex;
#ifndef __DARWIN__
/* pthread barrier does not exists in MAC OS X */
pthread_barrier_t pcap_barrier;
#endif
pcap_if_t * alldevs;
