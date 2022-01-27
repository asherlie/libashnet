#pragma once

#include <stdatomic.h>
#include <stdint.h>

#define BEACON_MARKER 0xdecaf
#define BASE_PACKET_LEN 32
/* TODO: don't hardcode offset */
#define DATA_BYTES BASE_PACKET_LEN-sizeof(int)-4-6-1
#define PADDING_BYTES sizeof(struct packet)-BASE_PACKET_LEN
#define UNAME_LEN DATA_BYTES-1

#define PACKET_MEMORY 1000

/*
 * i need this struct without addr to just throw on top of ssid field
 * ssid is always rtap_hdr+38 and all of this struct minus the addr
 * fits in 32 bytes
 * this will let us use ssid for all meaningful data but addr, which will certainly be
 * included
 * i'll just throw this new simplified struct onto data/ssid offset
 * and immediately have most of our struct parsed! all we'll have to do next is manually
 * set addr, EASY!
*/

/* the compact portion of struct packet fits all
 * necessary info into the `ssid` field of an ethernet
 * frame ASIDE from addr
 */
 /*
 * okay this may not be necessary, i can just put all the fields at front and still cast starting at ssid
 * this should work EXACTLY the same
 * and i won't need to rewrite all my codeg
 */
/*
 * struct __attribute__ ((__packed__)) compact_packet{
 * };
*/

struct __attribute__((__packed__)) packet{
    /* the below fits in 32 bytes for now, just to be safe
     * this may be able to change once i see how i can work
     * with the link layer headers
     */
    /* only need one byte - dlen <= 32 */
    /* original sender address */
    uint8_t from_addr[6];
    uint8_t mtype;
    uint8_t dlen;
    uint8_t data[DATA_BYTES];
    _Bool beacon;
    _Bool built;
    _Bool final_packet;
    int variety;
    /* first 32 over */
    /* immediate sender address */
    uint8_t addr[6];
    /* there are two opportunities for packets to be free()d
     * the first is when insert_packet() is overwriting an existing
     * packet to make room, the second is when a packet is popped from
     * an mq and is being broadcasted
     *
     * when one has occurred, the next free() oportunity will trigger
     * a free(). only when both have occurred is it safe to free up mem
     *
     * free_opportunities defaults to 0, as packets are always calloc()d
     *
     * all packets are sent exactly once and will be overwritten exactly once
     * the only exception is duplicates, which are free()d on the spot and are
     * irrelevant. packets crafted from kq are added to both storage and ready_to_send
     *
     * packets received are added to storage and propogated unless they're duplicates
     */
    /* it's more convenient for free_opportunities to be 1byte wide because of alignment
     * issues with atomic operations on packed structs
     */
    _Atomic uint8_t free_opportunities;
    //struct compact_packet cp_internal;
};

/* each peer struct represents one mac address
 * that belongs to the network
 */
struct peer{
    char uname[UNAME_LEN];
    uint8_t addr[6];

    struct packet** recent_packets;
    /* ins idx is wrapped back to 0 when full */
    int n_stored_packets, ins_idx;

    struct peer* next;
};

struct packet_storage{
    /* this might be useless - do we even
     * access packet storage from different
     * threads?
     */
    //pthread_mutex_t ps_locks[50];
    pthread_mutex_t ps_lock;
    /* (0xff * 6) + 1 */
    struct peer* buckets[1531];
};

void init_packet_storage(struct packet_storage* ps);
struct peer* lookup_peer(struct packet_storage* ps, uint8_t addr[6], char uname[UNAME_LEN], struct peer** created_peer);
struct peer* insert_uname(struct packet_storage* ps, uint8_t addr[6], char uname[UNAME_LEN]);
char* insert_packet(struct packet_storage* ps, uint8_t addr[6], struct packet* p, _Bool* valid_packet);
struct packet** prep_packets(uint8_t* raw_bytes, uint8_t local_addr[6], char* uname, int variety, uint8_t mtype);
