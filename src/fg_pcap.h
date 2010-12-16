#include "daemon.h"
#include <pcap.h>
void fg_pcap_init();
void fg_pcap_go(struct _flow *);
void fg_pcap_cleanup(void* arg);
pthread_mutex_t pcap_mutex;
pthread_barrier_t pcap_barrier; 
pcap_if_t * alldevs;
