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
    struct peer* ret = ps->buckets[idx], * last;
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
        memcpy(last->addr, addr, 6);
        memcpy(last->uname, uname, UNAME_LEN);
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
#if 0

int main(){
    /*assert(sizeof(struct packet) == 32);*/
    /*printf("%i\n", sizeof(struct packet));*/
    struct packet_storage ps;
    char uname[UNAME_LEN] = "ahsyboy";
    init_packet_storage(&ps);

    printf("%i\n", (_Bool)insert_uname(&ps, (uint8_t*)uname, uname));
    uname[0] = 'z';
    printf("%i\n", (_Bool)insert_uname(&ps, (uint8_t*)uname, uname));
    printf("%s\n", lookup_peer(&ps, uname, NULL , NULL)->uname);
    uname[0] = 'a';

    printf("%s\n", lookup_peer(&ps, uname, NULL , NULL)->uname);
}
#endif
