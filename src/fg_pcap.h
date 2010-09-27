#include "daemon.h"
void fg_pcap_init();
void fg_pcap_go(struct _flow *, int);
void *fg_pcap_thread(void* ptr);

