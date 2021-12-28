#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "packet_storage.h"

int sum_addr(uint8_t addr[6]){
    int ret = 0;
    for(int i = 0; i < 6; ++i){
        ret += addr[i];
    }
    return ret;
}

void init_packet_storage(struct packet_storage* ps){
    pthread_mutex_init(&ps->ps_lock, NULL);
    memset(ps->buckets, 0, sizeof(struct peer*)*1531);
}

struct peer* lookup_peer(struct packet_storage* ps, uint8_t addr[6], char uname[UNAME_LEN], struct peer** created_peer){
    int idx = sum_addr(addr);
    struct peer* ret = ps->buckets[idx], * last = NULL;
    _Bool found = 0;
    if(!uname && !addr)return NULL;
    pthread_mutex_lock(&ps->ps_lock);
    for(; ret; ret = ret->next){
        if(!ret->next)last = ret;
        if((addr && memcmp(ret->addr, addr, 6)))continue;
        if((uname && memcmp(ret->uname, uname, UNAME_LEN)))continue;
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
    /*puts("CREATED");*/
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

struct peer* insert_uname(struct packet_storage* ps, uint8_t addr[6], char uname[UNAME_LEN]){
    struct peer* peer;
    /* return NULL if peer already exists */
    if(lookup_peer(ps, addr, uname, &peer))return NULL;
    return peer;
}

_Bool is_duplicate(struct peer* peer, struct packet* p){
    for(int i = 0; i < peer->n_stored_packets; ++i){
        /* this occurs when the buffer isn't completely
         * full and there are no duplicates
         */
        if(!peer->recent_packets[i])return 0;
        if(!memcmp(peer->recent_packets[i], p, sizeof(struct packet)))return 1;
    }
    return 0;
}

#if 0
need to think about how to store messages in progress
if my circular buffer wraps around it would be complicated
to work backwards
would a link list be better
i could potentially free up all data from list after each
completed message
and not even check for duplicates after the message is completed
do not think this is the best approach actually
#endif
char* build_message(struct peer* peer){
    /* TODO: this is a naive long term approach
     * i need to account for wrap-arounds
     */
    /* TODO: this should be calculated more precisely */
    char* ret = calloc(1, peer->ins_idx*DATA_BYTES);
    int ret_idx = 0;
    _Bool recording = 0;
    for(int i = 0; i < peer->ins_idx; ++i){
        if(peer->recent_packets[i]->beacon)continue;
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

/* returns a complete message if one has been completed */
/*
 * should provide info on duplicate status, peer doesn't exist
 * ACTUALLY we may not need to distinguish
 * can just set an invalid boolean flag
 * if invalid, free mem, don't propogate, ignore
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
    if(is_duplicate(peer, p)){
        pthread_mutex_unlock(&ps->ps_lock);
        if(valid_packet)*valid_packet = 0;
        return NULL;
    }
    p->built = 0;
    if(peer->ins_idx == peer->n_stored_packets)
        peer->ins_idx = 0;
    if(peer->recent_packets[peer->ins_idx]){
        /* if non-NULL, free */
        free(peer->recent_packets[peer->ins_idx]);
    }
    peer->recent_packets[peer->ins_idx++] = p;
    if(!p->beacon && p->final_packet)ret = build_message(peer);

    pthread_mutex_unlock(&ps->ps_lock);

    return ret;
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

    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("asher ", 0));
    if(built_msg)puts(built_msg);
    // this seg faults
    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("is ", 0));
    if(built_msg)puts(built_msg);
    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("a ", 0));
    if(built_msg)puts(built_msg);
    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("good ", 0));
    if(built_msg)puts(built_msg);
    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("guy ", 0));
    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("and ", 0));
    built_msg = insert_packet(&ps, (uint8_t*)uname, spoof_packet("i love the fella", 1));
    if(built_msg)puts(built_msg);
    p_cache(&ps);
}
#endif
