#include <pcap.h>
#include <string.h>
#include <sys/param.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#include "packet_storage.h"

// temp includes
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>

    uint8_t rpz[92+4] =
    "\x00\x00\x12\x00\x2e\x48\x00\x00\x10\x02\x6c\x09\xa0\x00\xe5\x03" \
    "\x00\x00\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x74\xe5\x0b\xb5" \
    "\x5b\x08\x74\xe5\x0b\xb5\x5b\x08\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x64\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x5f\x19\x36\xe3\x00\x00\x00\x00";

struct ieee80211_hdr {
	__le16 frame_control;
	__le16 duration_id;
	uint8_t addr1[ETH_ALEN];
	uint8_t addr2[ETH_ALEN];
	uint8_t addr3[ETH_ALEN];
	__le16 seq_ctrl;
	uint8_t addr4[ETH_ALEN];
} __attribute__ ((__packed__));

struct ieee80211_beacon {
    uint8_t fc_subtype;
    uint8_t fc_order;
	/*__le16 frame_control;*/
	__le16 duration;
	uint8_t da[ETH_ALEN];
	uint8_t sa[ETH_ALEN];
	uint8_t bssid[ETH_ALEN];
	__le16 seq_ctrl;
		struct {
			__le64 timestamp;
			__le16 beacon_int;
			__le16 capab_info;
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

void write_bytes_old_fashioned(void* buf, int len){
    int sock = socket(AF_PACKET, SOCK_RAW, 0);
    struct ifreq ifr = {0};
    struct ifreq if_mac = {0};
    unsigned char macaddr[6];

    strncpy(ifr.ifr_name, "wlp3s0", IFNAMSIZ-1);
    strncpy(if_mac.ifr_name, "wlp3s0", IFNAMSIZ-1);

    if(ioctl(sock, SIOCGIFINDEX, &ifr) == -1)perror("IOCTL");
    if(ioctl(sock, SIOCGIFHWADDR, &if_mac) < 0)perror("HWADDR");
    memcpy(macaddr, if_mac.ifr_addr.sa_data, 6);

    for(int i = 0; i < 6; ++i){
        printf("%hx:", macaddr[i]);
    }
    puts("");

    if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void*)&ifr, sizeof(ifr)) < 0)perror("setsockopt");

    struct sockaddr_ll saddr;
    saddr.sll_ifindex = ifr.ifr_ifindex;
    /*printf("somehow: %i\n", saddr.sll_ifindex);*/
    saddr.sll_halen = ETH_ALEN;

    printf("old fashun %li/%i\n", sendto(sock, buf, len, 0, (struct sockaddr*)&saddr, sizeof(struct sockaddr_ll)), len);
    printf("sock num %i\n", sock);
    close(sock);
}

uint8_t* gen_packet(struct packet* p, int* packet_len){
    /*struct ethhdr* eth = calloc(sizeof(struct rtap_hdr) +*/
    uint8_t* packet = calloc((*packet_len =
                             sizeof(struct rtap_hdr) +
                             sizeof(struct ieee80211_beacon))
                             /*sizeof(struct ethhdr) +*/
                             /*sizeof(struct packet)-6), 1);*/
                             , 1);
    struct rtap_hdr* rth = (struct rtap_hdr*)packet;
    /*struct ethhdr* eh = (struct ethhdr*)(packet+sizeof(struct rtap_hdr));*/
    struct ieee80211_beacon* eh = (struct ieee80211_beacon*)(packet+sizeof(struct rtap_hdr));

    /* just copying over some bytes to try out */
    /*printf("siz %li\n", MIN(sizeof(rpz), *packet_len));*/
    memcpy(packet, rpz, MIN(sizeof(rpz), *packet_len));
    rth->it_version = 0;
    rth->it_len = htons(sizeof(struct rtap_hdr));
    /*rth->it_len = sizeof(struct rtap_hdr);*/
    rth->it_present = htons(11848);

    eh->fc_subtype = 0x08;
    eh->fc_order = 0;
    eh->duration = 0;
    for(int i = 0; i < 6; ++i)eh->da[i] = 0xff;
    /*eh->h_proto = htons(8);*/
    memcpy(eh->sa, p->addr, 6);
    memcpy(eh->bssid, p->addr, 6);
    /*eh->seq_ctrl = ??*/
    eh->beacon.timestamp = htons(time(NULL));
    /**eh->beacon.beacon_int = figure out how to set this to 0x64 in first byte */
    eh->beacon.beacon_int = htons(0x64);
    /*eh->beacon.capab_info = 0x11 0x11*/
    eh->beacon.capab_info = 0x1111;
    eh->beacon.alignment_padding = 0x20;
    memcpy(&eh->beacon.ssid, p, BASE_PACKET_LEN);
    /*memcpy(eh+sizeof(struct ethhdr), p, sizeof(struct packet)-6);*/
    
    return packet;
}

/* TODO: can we reuse our pcap_t? */
#if !!0
my weird strategy for now is to just copy a received packet
i will take its radiotap header and everything up until ssid field
just need to overwrite source address field - this is at rtap.length + 10 -- VERIFY THIS
#endif
_Bool broadcast_exp(pcap_t* pcp, struct packet* p){
    int peepee;
    uint8_t* new_method_packet = gen_packet(p, &peepee);

    (void)new_method_packet;
    //these should work but don't
    /*
     * write_bytes_old_fashioned(new_method_packet, peepee);
     * return 1;
    */
    /*return pcap_inject(pcp, new_method_packet, peepee) == peepee;*/

    // the method below is functional BUT doesn't work on non-x220s
    #if 0
    this is a raw scapy packet
    "\x00\x00\x38\x00\x6f\x08\x00\xc0\x01\x00\x00\x40\x74\xe5\x0b\xb5" \
    "\xf8\x89\x14\x00\x00\x00\x00\x00\x10\x02\x6c\x09\x80\x04\xd7\xa9" \
    "\x00\x20\x00\x10\x18\x00\x03\x00\x02\x00\x00\x78\x00\x10\x18\x03" \
    "\x06\x00\x78\x78\x50\x02\xf4\xb3\x80\x00\x00\x00\xff\xff\xff\xff" \
    "\xff\xff\x74\xe5\x0b\xb5\x5b\x08\x74\xe5\x0b\xb5\x5b\x08\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x64\x00\x00\x00\x00\x20\x78\x78" \
    "\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78" \
    "\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x5f\x19" \
    "\x36\xe3"
    #endif

    uint8_t raw_packet[126] =
    "\x00\x00\x38\x00\x6f\x08\x00\xc0\x01\x00\x00\x40\x74\xe5\x0b\xb5" \
    "\xf8\x89\x14\x00\x00\x00\x00\x00\x10\x02\x6c\x09\x80\x04\xd7\xa9" \
    "\x00\x20\x00\x10\x18\x00\x03\x00\x02\x00\x00\x78\x00\x10\x18\x03" \
    "\x06\x00\x78\x78\x50\x02\xf4\xb3\x80\x00\x00\x00\xff\xff\xff\xff" \
    "\xff\xff\x74\xe5\x0b\xb5\x5b\x08\x74\xe5\x0b\xb5\x5b\x08\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x64\x00\x00\x00\x00\x20\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    uint8_t raw_packet_recvd[92] =
    "\x00\x00\x12\x00\x2e\x48\x00\x00\x10\x02\x6c\x09\xa0\x00\xe5\x03" \
    "\x00\x00\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x74\xe5\x0b\xb5" \
    "\x5b\x08\x74\xe5\x0b\xb5\x5b\x08\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x64\x00\x00\x00\x00\x20\x78\x78\x78\x78\x78\x78\x78\x78" \
    "\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78" \
    "\x78\x78\x78\x78\x78\x78\x78\x78\x5f\x19\x36\xe3";

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
    #if 0
    /*56 and 57 i THINK*/
    printf("56 %hx %hx\n", raw_packet_recvd_zeroed[55], raw_packet_recvd_zeroed[56]);
    /*29 should be 74\*/
    printf("28 should be 74: %hx\n", raw_packet_recvd_zeroed[28]);
    printf("28+6 should be 74: %hx\n", raw_packet_recvd_zeroed[28+6]);
    #endif
    // DATA STARTS AT 56
    // TWO ADDRESS FIELDS START AT 28

    memcpy(raw_packet_recvd_zeroed+56, p, BASE_PACKET_LEN);
    memcpy(raw_packet_recvd_zeroed+28, p->addr, 6);
    memcpy(raw_packet_recvd_zeroed+28+6, p->addr, 6);

    
    /* either of these options work - should i go with
     * libpcap for now?
     */
    /*write_bytes_old_fashioned(raw_packet_recvd_zeroed, sizeof(raw_packet_recvd_zeroed));*/
    pcap_inject(pcp, raw_packet_recvd_zeroed, sizeof(raw_packet_recvd_zeroed));
    return 1;

    char errbuf[1212];
    return pcap_inject(pcp, raw_packet_recvd_zeroed, sizeof(raw_packet_recvd_zeroed)) == sizeof(raw_packet_recvd_zeroed);
    /*pcap_inject(pcap_open_live("wlp3s0", BUFSIZ, 0, 3000, errbuf), raw_packet_recvd_zeroed, sizeof(raw_packet_recvd_zeroed));*/
    printf("lelnnf %i\n", (int)sizeof raw_packet_recvd);

    memcpy(raw_packet+66, p->addr, 6);
    memcpy(raw_packet+72, p->addr, 6);
    memcpy(raw_packet+94, p, 32);
    write_bytes_old_fashioned(raw_packet, sizeof(raw_packet));
    return 1;
    printf("lenny: %i\n", (int)sizeof(raw_packet));
    /*printf("%hx %hx\n", raw_packet[93], raw_packet[94]);*/
    return pcap_inject(pcp, raw_packet, sizeof(raw_packet)) == sizeof(raw_packet);
    (void)pcp;
    return pcap_inject(pcap_open_live("wlp3s0", BUFSIZ, 0, 3000, errbuf), raw_packet, sizeof(raw_packet)) == sizeof(raw_packet);
    
}


_Bool broadcast_packet(pcap_t* pcp, struct packet* p, int len){
    /* hmm, this was working for a bit but isn't anymore */
    /*
     * literally was working just sending raw bytes for p and header was
     * magically appearing, WHAT'S GOING ON NOW
    */
    /*
     * write_bytes_old_fashioned(p, len);
     * return 1;
    */

    return broadcast_exp(pcp, p);

    (void)len;
    uint8_t* pkt;
    int hdrsz;
    FILE* fp = fopen("spoofed_header", "r");
    fread(&hdrsz, sizeof(int), 1, fp);
    pkt = calloc(1, BASE_PACKET_LEN+hdrsz);
    fread(pkt, hdrsz, 1, fp);
    fclose(fp);
    memcpy(pkt+hdrsz, p, BASE_PACKET_LEN);
    (void)pcp;
    /*pcap_inject(pcp, pkt, sizeof(struct packet)+hdrsz) == (int)sizeof(struct packet)+hdrsz;*/
    /*pcap_inject(pcp, pkt, sizeof(struct packet)+hdrsz);*/
    pcap_inject(pcp, pkt, BASE_PACKET_LEN+hdrsz);
    /*char* dev_name;*/
    char errbuf[1000];
    pcap_t* handle = pcap_open_live("wlp3s0", BUFSIZ, 0, 3000, errbuf);
    return pcap_inject(handle, pkt, BASE_PACKET_LEN+hdrsz) == (int)BASE_PACKET_LEN+hdrsz;
    /*return pcap_inject(pcp, p, len) == len;*/
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
