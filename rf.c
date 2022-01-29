#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "packet_storage.h"

#define MAC_ADDR_LEN 6

struct ieee80211_hdr {
	uint16_t frame_control;
	uint16_t duration_id;
	uint8_t addr1[MAC_ADDR_LEN];
	uint8_t addr2[MAC_ADDR_LEN];
	uint8_t addr3[MAC_ADDR_LEN];
	uint16_t seq_ctrl;
	uint8_t addr4[MAC_ADDR_LEN];
} __attribute__ ((__packed__));

struct ieee80211_beacon {
    uint8_t fc_subtype;
    uint8_t fc_order;
	/*uint16_t frame_control;*/
	uint16_t duration;
	uint8_t da[MAC_ADDR_LEN];
	uint8_t sa[MAC_ADDR_LEN];
	uint8_t bssid[MAC_ADDR_LEN];
	uint16_t seq_ctrl;
		struct {
			uint64_t timestamp;
			uint16_t beacon_int;
			uint16_t capab_info;
            uint8_t alignment_padding;
			/* followed by some of SSID, Supported rates,
			 * FH Params, DS Params, CF Params, IBSS Params, TIM */
			uint8_t ssid[32];
		} __attribute__ ((__packed__)) beacon;
} __attribute__ ((__packed__));

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
    const uint8_t* raw_data = pcap_next(pcp, &hdr);

    *len = hdr.len;

    rhdr = (struct rtap_hdr*)raw_data;
    /*struct ethhdr* ehdr = (struct ethhdr*)raw_data+rhdr->it_len;*/
    struct ieee80211_beacon* ieb = (struct ieee80211_beacon*)(raw_data+rhdr->it_len); 
    /*ieb = (struct ieee80211_beacon*)raw_data+rhdr-;*/
    /*
     * for(int i = 0; i < 32; ++i){
     *     printf("ssid: rtap offset: %i %i \"%s\"\n", rhdr->it_len, i, ieb->beacon.ssid+i);
     * }
    */
    #if 0
    printf("ssid: rtap offset: %i \"%s\"\n", rhdr->it_len, ieb->beacon.ssid);

    printf("%hx:%hx:%hx:%hx:%hx:%hx\n", ieb->da[0], ieb->da[1], ieb->da[2], ieb->da[3], ieb->da[4], ieb->da[5]);
    /*for(int i = 0; i < rhdr->it_len-6; ++i){*/
    for(int i = 0; i < (int)hdr.len-6; ++i){
        _Bool sixes = 1;
        for(int j = 0; j < 6; ++j){
            if(raw_data[i+j] != 0xff){
                /*printf("found a zero at %i\n", j+i);*/
                sixes = 0;
                break;
            }
        }
        if(sixes)printf("found sixes @ %i, %i\n", rhdr->it_len, i);
    }
    #endif
    (void)ieb;
    /*printf("%li == %i\n", sizeof(struct rtap_hdr), rhdr->it_len);*/
    /*struct ethhdr* ehdr = (struct ethhdr*)raw_data+sizeof(struct rtap_hdr);*/
    memcpy(pkt, raw_data+rhdr->it_len+38, MIN(hdr.len-(rhdr->it_len+38), BASE_PACKET_LEN));
    memcpy(pkt->addr, raw_data+rhdr->it_len+16, 6);
    /*printf("proto %i\n", (ehdr->h_proto));*/
    /*printf("vers %i, %i\n", rhdr->it_version, (rhdr->it_present));*/

    #if 0
    for(int i = 0; i < (int)hdr.len; ++i){
        if(i % 8 == 0)puts("");
        if(isalnum(raw_data[i]))printf("%i/%.4i/%c ", rhdr->it_len, i, raw_data[i]);
        else printf("         ");
    }
    #else
    /*
     * for(char* i = (char*)raw_data+rhdr->it_len+38; *i; ++i){
     *     if(!isalnum(*i)){
     *         *i = 0;
     *         break;
     *     }
     * }
    */
    /*
     * if(raw_data[rhdr->it_len+38] != 'o' && 
     *    raw_data[rhdr->it_len+38] != 'n' && 
     *    raw_data[rhdr->it_len+38] != 'G' && 
     *    raw_data[rhdr->it_len+38] != 'M' && 
     *    raw_data[rhdr->it_len+38] != '$')
    */
    /*printf("got packet with data: \"%s\"\n", raw_data+rhdr->it_len+38);*/

    /*printf("got packet with data: \"%s\"\n", pkt->data);*/
    #endif
    /*memcpy(pkt->data, raw_data+rhdr->it_len+38, );*/
    #if !1
    /*
     * puts((char*)pkt->data);
     * for(int i = 0; i < 6; ++i){
     *     printf("%.2hx:", pkt->addr[i]);
     * }
     * puts("");
    */
    for(int i = 0; i < (int)hdr.len-4; ++i){
        /*if(raw_data[i] == 0x74 && raw_data[i+1] == 0xe5 && raw_data[i+2] == 0x0b && raw_data[i+3] == 0xb5){*/
        if(raw_data[i] == 'x' && raw_data[i+1] == 'x' && raw_data[i+2] == 'x' && raw_data[i+3] == 'x'){
        /*if(raw_data[i] == 'a' && raw_data[i+1] == 's' && raw_data[i+2] == 'h' && raw_data[i+3] == 'e'){*/
        /*if(raw_data[i] == 'n' && raw_data[i+1] == 'e' && raw_data[i+2] == 'w' && raw_data[i+3] == ' '){*/
            for(int i = 0; i < (int)hdr.len; ++i){
                if(i % 8 == 0)printf(" ");
                if(i % 16 == 0)puts("");
                if(isalnum(raw_data[i]))printf(" %c ", raw_data[i]);
                else printf("%.2hx ", raw_data[i]);
                /*printf("%");*/
            }
            puts("\n");
        }
    }
    /*#if !1*/
    if(strstr((char*)pkt->data, "xxxx") || (
       pkt->addr[0] == 0xc9 && pkt->addr[1] == 0xf4 && pkt->addr[2] == 0x11 && pkt->addr[3] == 0x84 &&
       pkt->addr[4] == 0x0e && pkt->addr[5] == 0xa2)){
        uint8_t dummy[1000] = {0};
        /* copy until just before ssid */
        memcpy(dummy, raw_data, rhdr->it_len+38);
        FILE* fp = fopen("spoofed_header", "w");
        int tmpi = rhdr->it_len + 38;
        dummy[tmpi-1] = 32;
        /*fwrite(&tmpi, sizeof(int), 1, fp);*/
        /*fwrite(dummy, rhdr->it_len+38, 1, fp);*/
        fwrite(raw_data, hdr.len, 1, fp);
        fclose(fp);
        exit(0);
    }
    #endif
    return pkt;
}

/* for now pcap_inject()ing a captured packet that has ssid field and address
 * fields overwritten
 */
_Bool broadcast_packet(pcap_t* pcp, struct packet* p){
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
    return pcap_inject(pcp, raw_packet_recvd_zeroed, sizeof(raw_packet_recvd_zeroed)) != PCAP_ERROR;
}


void get_local_addr(char* iname, uint8_t addr[6]){
    int sock = socket(AF_PACKET, SOCK_RAW, 0);
    struct ifreq ifr = {0};
    struct ifreq if_mac = {0};
    strncpy(ifr.ifr_name, iname, IFNAMSIZ-1);
    strncpy(if_mac.ifr_name, iname, IFNAMSIZ-1);
    if(ioctl(sock, SIOCGIFINDEX, &ifr) == -1)perror("IOCTL");
    if(ioctl(sock, SIOCGIFHWADDR, &if_mac) < 0)perror("HWADDR");
    memcpy(addr, if_mac.ifr_addr.sa_data, 6);
    close(sock);
}
