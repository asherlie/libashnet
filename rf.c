#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#include "packet_storage.h"

#define MAC_ADDR_LEN 6

struct rtap_hdr{
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
    /*uint8_t padding[56-4-4];*/
    uint8_t padding[18-4-4];
} __attribute__((__packed__));

pcap_t* internal_pcap_init(char* iface){
    /* TODO: this needs to be pcap_close()d */
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

    /* ~10x the default to ensure no dropped packets */
    if(pcap_set_buffer_size(pcap_data, 10000000)){
        puts("pcap_set_buffer_size() failed");
        return NULL;
    }

    if(pcap_activate(pcap_data) < 0){
        puts("pcap_activate() failed");
        return NULL;
    }

    #if 1
    if(pcap_compile(pcap_data, &bpf, "type mgt subtype beacon", 0, PCAP_NETMASK_UNKNOWN) == -1){
    /*if(pcap_compile(pcap_data, &bpf, "type mgt", 0, PCAP_NETMASK_UNKNOWN) == -1){*/
        puts("pcap_compile() failed");
        return NULL;
    }

    if(pcap_setfilter(pcap_data, &bpf) == -1){
        puts("pcap_setfilter failed");
        return NULL;
    }

    pcap_freecode(&bpf);
    #endif

    return pcap_data;
}


struct packet* recv_packet(pcap_t* pcp, int* len){
    struct pcap_pkthdr hdr;
    struct rtap_hdr* rhdr;
    /* TODO: do i need to memcpy or is pcap_next() guaranteed to not be freed
     * would be nice if i could just cast it to struct packet
     */
    struct packet* pkt = calloc(1, sizeof(struct packet));
    /* will this ever return NULL? */
    const uint8_t* raw_data;

    do{
        raw_data = pcap_next(pcp, &hdr);
        rhdr = (struct rtap_hdr*)raw_data;
    } while((int)hdr.len < rhdr->it_len+38);

    *len = hdr.len;

    memcpy(pkt, raw_data+rhdr->it_len+38, MIN(hdr.len-(rhdr->it_len+38), BASE_PACKET_LEN));
    memcpy(pkt->addr, raw_data+rhdr->it_len+16, 6);

    return pkt;
}

/* for now pcap_inject()ing a captured packet that has ssid field and address
 * fields overwritten
 * sends n_attempts packets, returns if at least one has been
 * succesfully sent
 * it's safe to assume all packets will be sent without error
 * the reason we send duplicates is to reduce the chance of
 * dropped packets on the receiving side
 * TODO: is this still necessary with increased pcap buffer size?
 */
_Bool broadcast_packet(pcap_t* pcp, struct packet* p){
    _Bool ret = 1;
    const int n_attempts = 2;
    /* final four bytes are added although they'll be overwritten by
     * syscalls - works with them for some reason
     * added four bytes to test extra padding
     */
    uint8_t raw_packet_recvd_zeroed[92+4] =
    "\x00\x00\x12\x00\x2e\x48\x00\x00\x10\x02\x6c\x09\xa0\x00\xe5\x03" \
    "\x00\x00\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x74\xe5\x0b\xb5" \
    "\x5b\x08\x74\xe5\x0b\xb5\x5b\x08\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x64\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x5f\x19\x36\xe3\x00\x00\x00\x00";

    /* "data" aka ssid field starts at byte 56, two consecute mac addr fields
     * begin at offset 28
     */
    memcpy(raw_packet_recvd_zeroed+56, p, BASE_PACKET_LEN);
    memcpy(raw_packet_recvd_zeroed+28, p->addr, 6);
    memcpy(raw_packet_recvd_zeroed+28+6, p->addr, 6);

    /* if i want to move away from libpcap, i can use the deprecated gen_packet()
     * or something similar to generate bytes for a raw socket
     * this can be sent using the deprecated write_bytes_old    
     * look back in commit history - they were removed on january 28, 2022
     */
    for(int i = 0; i < n_attempts; ++i){
        ret |= (pcap_inject(pcp, raw_packet_recvd_zeroed, sizeof(raw_packet_recvd_zeroed)) != PCAP_ERROR);
    }

    return ret;
}


_Bool get_local_addr(char* iname, uint8_t addr[6]){
#ifdef __APPLE__
    struct if_msghdr* mhdr;
    struct sockaddr_dl* saddr;
    size_t len;
    int mib[6] = {CTL_NET, AF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, 0};

    if(!(mib[5] = if_nametoindex(iname)))return 0;
    if(sysctl(mib, 6, NULL, &len, NULL, 0) < 0)return 0;

    mhdr = malloc(len);
    if(sysctl(mib, 6, mhdr, &len, NULL, 0) < 0){
        free(mhdr);
        return 0;
    }

    saddr = (struct sockaddr_dl*)(mhdr+1);
    memcpy(addr, LLADDR(saddr), 6);
    free(mhdr);
    return 1;
}
#else
    int sock = socket(AF_PACKET, SOCK_RAW, 0);
    struct ifreq ifr = {0};
    struct ifreq if_mac = {0};
    strncpy(ifr.ifr_name, iname, IFNAMSIZ-1);
    strncpy(if_mac.ifr_name, iname, IFNAMSIZ-1);
    if(ioctl(sock, SIOCGIFINDEX, &ifr) == -1)perror("IOCTL");
    if(ioctl(sock, SIOCGIFHWADDR, &if_mac) < 0)perror("HWADDR");
    memcpy(addr, if_mac.ifr_addr.sa_data, 6);
    close(sock);
    return 1;
}
#endif
