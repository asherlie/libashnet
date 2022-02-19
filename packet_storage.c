#include <stdatomic.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <stdint.h>

#include "packet_storage.h"

int sum_addr(uint8_t addr[6]){
    int ret = 0;
    for(int i = 0; i < 6; ++i){
        ret += addr[i];
    }
    return ret;
}

int compute_sanity_check(struct packet* p){
    uint16_t sum = 0;
    int db = (int)DATA_BYTES;
    for(int i = 0; i < db; ++i){
        sum += (i*p->data[i]);
    }
    return sum;
}

_Bool sanity_check(struct packet* p){
    /* sanity short is always stored in network order
     * after being recvd
     */
    return compute_sanity_check(p) == ntohs(p->sanity);
}

void init_packet_storage(struct packet_storage* ps){
    pthread_mutex_init(&ps->ps_lock, NULL);
    memset(ps->buckets, 0, sizeof(struct peer*)*1531);
}

/*
 * lookup_peer() should return the found peer matching addr, if addr is not provided, it will return
 * the peer matching uname
 * if uname is provided and doesn't match existing uname, uname will be updated
 * if created_peer is set and no match is found, it will be created
*/
struct peer* lookup_peer(struct packet_storage* ps, uint8_t addr[6], char uname[UNAME_LEN], struct peer** created_peer){
    int idx = sum_addr(addr);
    struct peer* ret = ps->buckets[idx], * last = NULL;
    _Bool found = 0;
    if(!uname && !addr)return NULL;
    pthread_mutex_lock(&ps->ps_lock);
    for(; ret; ret = ret->next){
        if(!ret->next)last = ret;
        if((addr && memcmp(ret->addr, addr, 6)))continue;
        /* the data after NUL bytes are sometimes diff
         * TODO: confirm that this has been fixed
         */
        
        /*
         * if uname && addr, we shouldn't narrow based on uname ONLY addr
         * addr always trumps because it's 1:1 there are guaranteed no duplicates
        */
        if(uname){
            if(memcmp(ret->uname, uname, UNAME_LEN)){
                /* if address matches but not uname, we must update uname */
                if(addr)
                    /* updating uname, not continuing - found = 1, break implicitly */
                    memcpy(ret->uname, uname, UNAME_LEN);
                /* if we're searching only with uname, keep on lookin' */
                else continue;
            }
            /* if(uname_match), we will just continue on and set found to 1 and break */
        }
        found = 1;
        break;
    }

    if(found){
        pthread_mutex_unlock(&ps->ps_lock);
        return ret;
    }

    if(created_peer && uname && addr){
        if(last){
            last->next = malloc(sizeof(struct peer));
            last = last->next;
        }
        else last = ps->buckets[idx] = malloc(sizeof(struct peer));
        memcpy(last->addr, addr, 6);
        memcpy(last->uname, uname, UNAME_LEN);
        last->n_stored_packets = PACKET_MEMORY;
        last->ins_idx = 0;
        last->recent_packets = calloc(sizeof(struct packet*), last->n_stored_packets);
        last->next = NULL;
        *created_peer = last;
    }

    pthread_mutex_unlock(&ps->ps_lock);

    return ret;
}

/* TODO: args 1 and 2 can be consolidated */
/* returns whether an entirely new entry has been created */
struct peer* insert_uname(struct packet_storage* ps, uint8_t addr[6], char uname[UNAME_LEN]){
    struct peer* peer;
    /* return NULL if peer already exists */
    if(lookup_peer(ps, addr, uname, &peer))return NULL;
    return peer;
}

_Bool is_duplicate(struct peer* peer, struct packet* p){
    /* this will always be zero due to calloc() call in prep_packets()
     * just being safe in case of future changes
     */
    _Bool built_backup = p->built;
    for(int i = 0; i < peer->n_stored_packets; ++i){
        /* this occurs when the buffer isn't completely
         * full and there are no duplicates
         */
        if(!peer->recent_packets[i]){
            return 0;
        }
        p->built = peer->recent_packets[i]->built;
        /* no need to reset built byte, packet will be discarded if duplicate */
        if(!memcmp(peer->recent_packets[i], p, BASE_PACKET_LEN))return 1;
    }
    p->built = built_backup;
    return 0;
}

char* build_message(struct peer* peer){
    /* TODO: this is a naive long term approach
     * i need to account for wrap-arounds
     */
    /* TODO: this should be calculated more precisely */
    char* ret = calloc(1, peer->ins_idx*DATA_BYTES);
    int ret_idx = 0;
    /* most recent packet is guaranteed to be here, as it
     * was inserted just before the call to build_message()
     * and the ps_lock has not been released
     */
    uint8_t mtype = peer->recent_packets[peer->ins_idx-1]->mtype;
    _Bool recording = 0;
    for(int i = 0; i < peer->ins_idx; ++i){
        if(peer->recent_packets[i]->beacon)continue;
        if(peer->recent_packets[i]->mtype != mtype)continue;
        if(!peer->recent_packets[i]->built)recording = 1;
        if(recording){
            strncpy(ret+ret_idx, (char*)peer->recent_packets[i]->data, DATA_BYTES);
            peer->recent_packets[i]->built = 1;
            /* move pointer to the NUL byte */
            for(; ret[ret_idx] != 0; ++ret_idx);
        }
    }

    return ret;
}

/* returns a complete message if one has been completed, sets valid_packet
 * to 0 if packet is a duplicate, from an unrecognized mac address, or
 * not part of ashnet
 */
char* insert_packet(struct packet_storage* ps, uint8_t addr[6], struct packet* p, _Bool* valid_packet){
    struct peer* peer = lookup_peer(ps, addr, NULL, NULL);
    char* ret = NULL;
    if(valid_packet)*valid_packet = 1;

    if(!peer){
        if(valid_packet)*valid_packet = 0;
        return NULL;
    }
    pthread_mutex_lock(&ps->ps_lock);
    /* TODO: do we really need to check sanity? i believe the problems occuring
     * were due to dropped packets, not malformed ones
     * because they were mostly resolved with an increase in pcap buffer size
     * might as well keep this for now, but look into this in the future
     */
    if(!sanity_check(p) || is_duplicate(peer, p)){
        pthread_mutex_unlock(&ps->ps_lock);
        if(valid_packet)*valid_packet = 0;
        return NULL;
    }
    p->built = 0;
    if(peer->ins_idx == peer->n_stored_packets)
        peer->ins_idx = 0;
    if(peer->recent_packets[peer->ins_idx]){
        /* if non-NULL and packet has already been broadcasted, free */
        if(atomic_fetch_add(&peer->recent_packets[peer->ins_idx]->free_opportunities, 1))
            free(peer->recent_packets[peer->ins_idx]);
    }
    peer->recent_packets[peer->ins_idx++] = p;
    if(!p->beacon && p->final_packet)ret = build_message(peer);

    pthread_mutex_unlock(&ps->ps_lock);

    return ret;
}

struct packet** prep_packets(uint8_t* raw_bytes, uint8_t local_addr[6], char* uname, int variety, uint8_t mtype){
    int n_packets, bytes_processed = 0;
    int bytelen = strlen((char*)raw_bytes);
    /* not sure why this is necessary */
    int dbytes = DATA_BYTES;
    n_packets = (bytelen/dbytes)+1;
    /* +2 - adding a beacon packet to [0], need space for NULL terminator */
    struct packet** packets = calloc(n_packets+2, sizeof(struct packet*));

    /* setting up beacon */
    (*packets) = calloc(1, sizeof(struct packet));
    (*packets)->beacon = 1;
    /* endianness doesn't usually matter for
     * variety int32, but BEACON_MARKER must
     * be consistent across platforms
     */
    (*packets)->variety = htonl(BEACON_MARKER);
    (*packets)->mtype = mtype;
    (*packets)->final_packet = 1;
    memcpy((*packets)->from_addr, local_addr, 6);
    memcpy((*packets)->data, uname, strlen(uname));
    /* although it's a bit more elegant to just compute
     * and set this value immediately before broadcasting
     * in broadcast_packet(), this makes more sense
     * because it allows us to insert_packet() for
     * packets being sent locally
     *
     * if we wait until broadcast_packet() to compute
     * and set, propogated packets will appear as new
     * because they will not be added to our storage
     * after being deemed invalid - this would
     * cause many issues
     * TODO: decide which method to use
     * this could also be solved by not doing validity
     * checks at all when *valid_packet is not set
     */
    (*packets)->sanity = htons(compute_sanity_check(*packets));
    
    for(int i = 1; i < n_packets+1; ++i){
        packets[i] = calloc(1, sizeof(struct packet));
        memcpy(packets[i]->from_addr, local_addr, 6);
        memcpy(packets[i]->data, raw_bytes+bytes_processed, MIN(DATA_BYTES, bytelen-bytes_processed));
        packets[i]->mtype = mtype;
        packets[i]->variety = variety;
        packets[i]->sanity = htons(compute_sanity_check(packets[i]));
        bytes_processed += DATA_BYTES;
    }
    /* n_packets-1 isn't the last index due to initial beacon */
    packets[n_packets]->final_packet = 1;
    return packets;
}
#if 0
struct packet* spoof_packet(char* str, _Bool final){
    struct packet* ret = calloc(1, sizeof(struct packet));
    int didx = 0;
    for(char* i = str; *i; ++i){
        /*printf("%c -> %i\n", *i, didx);*/
        ret->data[didx++] = *i;
    }
    ret->final_packet = final;
    return ret;
}

void p_cache(struct packet_storage* ps){
    for(int i = 0; i < 1531; ++i){
        if(ps->buckets[i]){
            for(struct peer* p = ps->buckets[i]; p; p = p->next){
                printf("uname: %s, %i saved\n", p->uname, p->ins_idx);
                for(int i = 0; i < p->ins_idx; ++i){
                    printf("%i: \"%s\" %i %i\n", i, p->recent_packets[i]->data, p->recent_packets[i]->final_packet, p->recent_packets[i]->built);
                }
            }
        }
    }
}

int main(){
    /*assert(sizeof(struct packet) == 32);*/
    /*printf("%i\n", sizeof(struct packet));*/
    struct packet_storage ps;
    char uname[UNAME_LEN] = "ahsyboy";
    char* built_msg;
    init_packet_storage(&ps);

    printf("%i\n", (_Bool)insert_uname(&ps, (uint8_t*)uname, uname));
    /*
     * uname[0] = 'z';
     * printf("%i\n", (_Bool)insert_uname(&ps, (uint8_t*)uname, uname));
     * printf("%s\n", lookup_peer(&ps, (uint8_t*)uname, NULL , NULL)->uname);
    */
    /*uname[0] = 'a';*/

    /*printf("%s\n", lookup_peer(&ps, (uint8_t*)uname, NULL , NULL)->uname);*/

    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("asher ", 0), NULL);
    if(built_msg)puts(built_msg);
    // this seg faults
    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("is ", 0), NULL);
    if(built_msg)puts(built_msg);
    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("a ", 0), NULL);
    if(built_msg)puts(built_msg);
    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("good ", 0), NULL);
    if(built_msg)puts(built_msg);
    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("guy ", 0), NULL);
    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("and ", 0), NULL);
    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("i like the fella", 1), NULL);
    if(built_msg)puts(built_msg);
    p_cache(&ps);
}
#endif
