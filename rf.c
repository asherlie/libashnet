#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

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

    if(pcap_compile(pcap_data, &bpf, "type mgt subtype beacon", 0, PCAP_NETMASK_UNKNOWN) == -1){
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
    struct rtap_hdr* rhdr;
    struct packet* pkt = calloc(1, sizeof(struct packet));
    /* will this ever return NULL? */
    const uint8_t* raw_data = pcap_next(pcp, &hdr);

    rhdr = (struct rtap_hdr*)raw_data;
    *len = hdr.len;
    #if 0
    for(int i = 0; i < (int)hdr.len; ++i){
        if(i % 8 == 0)puts("");
        if(isalnum(raw_data[i]))printf("%i/%.4i/%c ", rhdr->it_len, i, raw_data[i]);
        else printf("         ");
    }
    #endif
    if(raw_data[rhdr->it_len+38] != 'o' && 
       raw_data[rhdr->it_len+38] != 'n' && 
       raw_data[rhdr->it_len+38] != 'G' && 
       raw_data[rhdr->it_len+38] != 'M' && 
       raw_data[rhdr->it_len+38] != '$')
    printf("got packet with data: \"%s\"\n", raw_data+rhdr->it_len+38);
    /*memcpy(pkt->data, raw_data+rhdr->it_len+38, );*/
    return pkt;
}

/* TODO: can we reuse our pcap_t? */
_Bool broadcast_packet(pcap_t* pcp, struct packet* p, int len){
    return pcap_inject(pcp, p, len) == len;
}
