#include "daemon.h"
void fg_pcap_init();
void fg_pcap_go(struct _flow *, int);
void *fg_pcap_thread(void* ptr);

pthread_t pcap_thread[MAX_FLOWS];
pthread_mutex_t pcap_thread_mutex[MAX_FLOWS];
