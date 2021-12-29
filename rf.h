#include <pcap.h>

#include "packet_storage.h"

pcap_t* internal_pcap_init(char* iface);
struct packet* recv_packet(pcap_t* pcp, int* len);
void broadcast_packet(struct packet* p, int len);
