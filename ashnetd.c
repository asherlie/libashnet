/*
ashnetd

this code should ~just work~ once broadcast_packet() and recv_packet() are implemented

TODO: solutions for setting uname and programmatically figuring out address
TODO: user should be able to specify kq keys
TODO: i need to stop using str(n)len() in favor of passing mq_entry->len fields
      meaningful data - this will make ashnetd more reliable

TODO: free all memory
TODO: exit safely
*/
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>

#include "mq.h"
#include "kq.h"
#include "packet_storage.h"

void init_queues(struct queues* q, key_t k_in, key_t k_out){
    init_mq(&q->ready_to_send);
    init_mq(&q->build_fragments);
    set_kq_key(q, k_in, k_out);
    memset(q->local_addr, 0, 6);
    strcpy(q->uname, "asher");
    *q->local_addr = 32;
    init_packet_storage(&q->ps);
}

/*
 * okay, this should return a malloc'd packet*, beacon packets must be identified and flagged
*/
struct packet* recv_packet(int* len){
    struct packet* ret = calloc(1, sizeof(struct packet));
    /* every 5th message should be a beacon */
    // hmm, when i get rid of this we're still getting duplicates
    /*ret->variety = time(NULL);*/
    // get rid of THIS
    // it's actually a great feature that BEACON_MARKER overwrites
    // the four variety bytes
    /**ret->flags = time(NULL)%2;*/
    if(time(NULL) % 2 == 0){
        ret->beacon = 1;
        ret->variety = BEACON_MARKER;
        ret->data[3] = 'e';
        ret->data[4] = 'r';
    }
    ret->addr[0] = 32;
    ret->data[0] = 'a';
    ret->data[1] = 's';
    ret->data[2] = 'h';
    ret->final_packet = 1;
    *len = 3;
    usleep(50000);
    return ret;
}

void broadcast_packet(struct packet* p, int len){
    /* TODO: should each call to broadcast_packet() make more than one broadcast? */
    printf("broadcasting%s \"%s\"\n", (p->beacon) ? " a beacon" : "", (char*)p->data);
    (void)len;
}

void* broadcast_thread(void* arg){
    struct queues* q = arg;
    struct mq_entry* e;
    while(1){
        e = pop_mq(&q->ready_to_send);
        broadcast_packet(e->data, e->len);
    }
}

void* process_kq_msg_thread(void* arg){
    struct queues* q = arg;
    uint8_t* bytes_to_send;
    struct packet** pp;
    int batch_num = 0;
    while(1){
        bytes_to_send = pop_kq(q->kq_key_in);
        /*
         * we now need to split this string into celing(strlen()/(32-sizeof(int)))
         * separate packets and add them to the ready_to_send mq
        */
        /* adding variety bytes in case this is identical to a recently sent message
         * if i don't do this, the following:
         * > hi
         * > hello
         * > hi
         * > hi
         *
         * would show up as:
         *
         * > hi
         * > hello
         *
         * this can be revisited, but for now duplicate detection is mostly meant
         * to simply be a base case to stop propogation 
         */
        pp = prep_packets(bytes_to_send, q->local_addr, q->uname, batch_num++);
        /* all sent packets are added to packet storage to be checked
         * against as a duplicate
         */
        /*
         * no need to check for validity, this is coming directly from
         * a kqueue - it won't be a bouncing message and certainly 
         * won't come from a nonexistent peer
         */
        /* len should not be DATA_BYTES, but used length of DATA_BYTES */
        for(struct packet** ppi = pp; *ppi; ++ppi){
            insert_mq(&q->ready_to_send, *ppi, DATA_BYTES);
        }
        free(pp);
    }
}

void* recv_packet_thread(void* arg){
    struct queues* q = arg;
    struct packet* p;
    int len;

    while(1){
        p = recv_packet(&len);
        insert_mq(&q->build_fragments, p, len);
    }
}

void* builder_thread(void* arg){
    struct queues* q = arg;
    char* built_msg;
    _Bool valid_packet;
    struct packet* p;

    while(1){
        p = (struct packet*)pop_mq(&q->build_fragments)->data;
        /* TODO: i likely need a better way of determining if packets
         * are beacons - something like two identical header fields
         * and a /uname string
         * WAIT we can just use the beacon bool and set variety int
         * to a unique value that only holds true for beacons
         * as well as setting a unique arrangement of values for
         * the other boolean flags
         */
        /* TODO: this order of operations allows all beacons to
         * pass through, even if they're duplicates
         */
        if(p->beacon && p->variety == BEACON_MARKER){
            insert_uname(&q->ps, p->addr, (char*)p->data);
        }
        if((built_msg = insert_packet(&q->ps, p->addr, p, &valid_packet))){
            insert_kq(built_msg, q->kq_key_out);
        }
        /* if this is not a duplicate packet and is valid,
         * it's time to propogate the message by adding it
         * to our ready to send queue
         */
        if(valid_packet){
            insert_mq(&q->ready_to_send, p, DATA_BYTES);
        }
    }
}

pthread_t spawn_thread(void* (*func)(void *), void* arg){
    pthread_t ret;
    pthread_create(&ret, NULL, func, arg);
    return ret;
}

int main(){
    struct queues q;
    pthread_t threads[4];
    init_queues(&q, 857123030, 857123040);
    printf("initialized kernel queues %i, %i\n", q.kq_key_in, q.kq_key_out);

    threads[0] = spawn_thread(broadcast_thread, &q);
    threads[1] = spawn_thread(process_kq_msg_thread, &q);
    threads[2] = spawn_thread(recv_packet_thread, &q);
    threads[3] = spawn_thread(builder_thread, &q);

    for(int i = 0; i < 4; ++i){
        pthread_join(threads[i], NULL);
    }
}
