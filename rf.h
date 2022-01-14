#include <pcap.h>

#include "packet_storage.h"

pcap_t* internal_pcap_init(char* iface);
struct packet* recv_packet(pcap_t* pcp, int* len);
_Bool broadcast_packet(pcap_t* pcp, struct packet* p, int len);
void get_local_addr(char* iname, uint8_t addr[6]);
