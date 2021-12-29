#include <pcap.h>
#include <stdlib.h>

#include "packet_storage.h"

struct rtap_hdr{
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((__packed__));

pcap_t* internal_pcap_init(char* iface){
    pcap_t* pcap_data;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf;

    if(!(pcap_data = pcap_create(iface, errbuf))){
        puts("pcap_create() failed");
        return NULL;
    }

    if(pcap_set_immediate_mode(pcap_data, 1)){
        puts("pcap_set_immediate_mode() failed");
        return NULL;
    }

    if(!pcap_can_set_rfmon(pcap_data)){
        puts("pcap_can_set_rfmon() failed");
        return NULL;
    }
    
    if(pcap_set_rfmon(pcap_data, 1)){
        puts("pcap_set_rfmon() failed");
        return NULL;
    }

    if(pcap_activate(pcap_data) < 0){
        puts("pcap_activate() failed");
        return NULL;
    }

    if(pcap_compile(pcap_data, &bpf, "type mgt subtype probe-req", 0, PCAP_NETMASK_UNKNOWN) == -1){
        puts("pcap_compile() failed");
        return NULL;
    }

    if(pcap_setfilter(pcap_data, &bpf) == -1){
        puts("pcap_setfilter failed");
        return NULL;
    }

    pcap_freecode(&bpf);

    return pcap_data;
}


struct packet* recv_packet(pcap_t* pcp, int* len){
    struct pcap_pkthdr hdr;
    struct packet* pkt = calloc(1, sizeof(struct packet));
    const uint8_t* raw_data = pcap_next(pcp, &hdr);
    (void)len;
    (void)raw_data;
    return pkt;
}
