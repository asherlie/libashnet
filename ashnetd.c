#if 0
note:
    i need to daemonize and allow clients to safely exit the daemon
    LOOK INTO SYSTEMD-IZING IT

    should daemon be with systemd?
    or should i fork() and build in functionality to ashnetd
    ashnetd -d for daemon
    ashnetd -k to kill running daemons?
    this might be necessary when porting over ashnetd for mac os/windows

    look through all TODOs, implement relevant ones

    MEMORY GROWS OVER TIME, AS SHOWN BY systemctl status
    WHY?
    are unames being added before verification?
    lack of free()d mem?

    it is likely just packet storage being used, after a while this storage should
    be static - once it is at capacity

    MORE is being used than it should be though. discarded packets MUST be taking up space

    we can keep print statements, they just end up being shown in systemctl status
    BUT they should be helpful
    they should only be "ADDED UNAME _ TO STORAGE" and "RECEIVED MESSAGE _, (PROPOGATING/FOUND TO BE A DUPLICATE)"

    TODO: mtype specification can be used to implement messageboards/semi-private rooms

    most important goals:
        get ashnetd working on raspberry pi
        clean up code - make it look nice, ESPECIALLY rf.c
        /*fix first message bug*/ - this has been ~somewhat~ solved - it is a sysv_ipc python issue
        a problem with the client kq interface. this code is working perfectly to send bytes from kq
#endif
/*
ashnetd

this code should ~just work~ once broadcast_packet() and recv_packet() are implemented

TODO: i might need to include a src_addr field that takes up more of our data
      bytes - pcap_inject(3) manual states: "source link-layer address, if the
      header contains such an address, might be changed to be the address
      assigned to the interface on which the packet it sent"
      MIGHT also have more luck with setting bssid field as true from_addr

TODO: solutions for setting uname and programmatically figuring out address
TODO: i can just use the strategy used in the original ashnet implementation
      to find local_addr, user will have to specify wifi interface so we can
      just use that
TODO: user should be able to specify kq keys
TODO: i need to stop using str(n)len() in favor of passing mq_entry->len fields
      meaningful data - this will make ashnetd more reliable

TODO: free all memory
TODO: exit safely
*/
#include <stdatomic.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>

#include "mq.h"
#include "kq.h"
#include "packet_storage.h"
#include "rf.h"

_Bool init_queues(struct queues* q, key_t k_in, key_t k_out, char* uname, char* iface){
    init_mq(&q->ready_to_send);
    init_mq(&q->build_fragments);
    set_kq_key(q, k_in, k_out);
    memset(q->uname, 0, UNAME_LEN);
    strcpy(q->uname, uname);
    get_local_addr(iface, q->local_addr);
    
    init_packet_storage(&q->ps);
    insert_uname(&q->ps, q->local_addr, q->uname);
    if(!(q->pcp = internal_pcap_init(iface)))return 0;
    return 1;
}

/*
 * okay, this should return a malloc'd packet*, beacon packets must be identified and flagged
*/
#if 0
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
#endif

#if 0
void broadcast_packet(struct packet* p, int len){
    /* TODO: should each call to broadcast_packet() make more than one broadcast? */
    printf("broadcasting%s \"%s\"\n", (p->beacon) ? " a beacon" : "", (char*)p->data);
    (void)len;
}
#endif

void* broadcast_thread(void* arg){
    struct queues* q = arg;
    struct mq_entry* e;
    while(1){
        e = pop_mq(&q->ready_to_send);
        /* TODO: find out why duplicates are being
         * sent. ~5 pairs of beacons/data are being
         * transmitted for each broadcast_packet() call
         * TODO: i believe i fixed this, look into it
         */
        memcpy(((struct packet*)e->data)->addr, q->local_addr, 6);
        broadcast_packet(q->pcp, e->data, e->len);
        /* if packet has been overwritten in storage and sent out, it's okay to
         * free up its memory as it's guaranteed not to be used anymore
         */
        if(atomic_fetch_add(&((struct packet*)e->data)->free_opportunities, 1))
            free(e->data);
        free(e);
    }
}

void* process_kq_msg_thread(void* arg){
    struct queues* q = arg;
    uint8_t mtype, * bytes_to_send;
    char* discard;
    struct packet** pp;
    int batch_num = 0;
    while(1){
        /* TODO: hmm, the first message of each session
         * doesn't get sent. could it be a problem with
         * prep_packets()?
         * with pop_kq()?
         */
        bytes_to_send = pop_kq(q->kq_key_in, &mtype);
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
        pp = prep_packets(bytes_to_send, q->local_addr, q->uname, batch_num++, mtype);
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
            /* free up memory from built self-sent messages
             * built can't be pre-set to 1 because insert_packet()
             * will overwrite that upon insertion
             * the most consistent solution is to just free built messages
             */

            /* it's safe to insert_mq() after insert_packet() because both are guaranteed
             * not to free packets until the other has given up control - this is done
             * using the _Atomic int free_opportunities
             */
            if((discard = insert_packet(&q->ps, (*ppi)->from_addr, *ppi, NULL)))free(discard);
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
        p = recv_packet(q->pcp, &len);
        insert_mq(&q->build_fragments, p, len);
    }
}

int construct_msg(char* buf, char* built_msg, struct packet* p, struct packet_storage* ps){
    struct peer* user = lookup_peer(ps, p->from_addr, NULL, NULL);

    memset(buf, 0, 1000);
    return snprintf(buf, 1000, "%hx:%hx:%hx:%hx:%hx:%hx,%s,%s",
                    p->from_addr[0], p->from_addr[1], p->from_addr[2], p->from_addr[3],
                    p->from_addr[4], p->from_addr[5], user->uname, built_msg);
}

void* builder_thread(void* arg){
    struct queues* q = arg;
    struct mq_entry* mqe;
    /* KQ_MAX */
    char* built_msg, constructed_msg[1000];
    _Bool valid_packet;
    struct packet* p;

    while(1){
        mqe = pop_mq(&q->build_fragments);
        p = mqe->data;
        free(mqe);
        /* TODO: this order of operations allows all beacons to
         * pass through, even if they're duplicates
         */
        if(p->beacon && p->variety == BEACON_MARKER){
            insert_uname(&q->ps, p->from_addr, (char*)p->data);
        }
        if((built_msg = insert_packet(&q->ps, p->from_addr, p, &valid_packet))){
            /* just like in process_kq_msg_thread(), it's now guaranteed that
             * p will not be freed after the above call to insert_packet()
             * this ensures that the subsequent construct_msg(), insert_kq(),
             * and insert_mq() calls will not seg fault even in case of very
             * high packet load where the packet storage buffer is overwhelmed
             */
            construct_msg(constructed_msg, built_msg, p, &q->ps);
            free(built_msg);
            insert_kq(constructed_msg, q->kq_key_out, p->mtype);
        }
        /* if this is not a duplicate packet and is valid,
         * it's time to propogate the message by adding it
         * to our ready to send queue
         */
        if(valid_packet)
            insert_mq(&q->ready_to_send, p, DATA_BYTES);
        else free(p);
    }
}

pthread_t spawn_thread(void* (*func)(void *), void* arg){
    pthread_t ret;
    pthread_create(&ret, NULL, func, arg);
    return ret;
}

/* returns whether or not we should run as a daemon */
_Bool parse_args(int a, char** b, char** uname, char** iface, key_t* k_in, key_t* k_out){
    _Bool set_uname = 0, set_iface = 0, set_k_in = 0, set_k_out = 0, daemon = 0;

    for(int i = 1; i < a; ++i){
        if(set_uname){
            *uname = b[i];
            set_uname = 0;
            continue;
        }
        if(set_iface){
            *iface = b[i];
            set_iface = 0;
            continue;
        }
        if(set_k_in){
            *k_in = atoi(b[i]);
            set_k_in = 0;
            continue;
        }
        if(set_k_out){
            *k_out = atoi(b[i]);
            set_k_out = 0;
            continue;
        }
        if(*b[i] == '-'){
            switch(b[i][1]){
                case 'D':
                case 'd':
                    daemon = 1;
                    break;
                case 'U':
                case 'u':
                    set_uname = 1;
                    break;
                case 'I':
                case 'i':
                    set_iface = 1;
                    break;
                case 'K':
                case 'k':
                    set_k_in |= b[i][2] == 'I';
                    set_k_in |= b[i][2] == 'i';
                    set_k_out |= b[i][2] == 'O';
                    set_k_out |= b[i][2] == 'o';
                    break;
            }
        }
    }
    return daemon;
}

int main(int a, char** b){
    struct queues q;
    /* initializing to 0 so that they're randomized by set_kq_key() if need be */
    key_t ki = 0, ko = 0;
    char* uname = NULL, * iface = NULL;
    pthread_t threads[4];

    parse_args(a, b, &uname, &iface, &ki, &ko);

    if(!(uname && iface)){
        puts("username and wifi interface must be provided");
        return 0;
    }
    if(!init_queues(&q, ki, ko, uname, iface)){
        puts("failed to initialize shared data... are you root?");
        return 0;
    }
    /* TODO: read from stdin */
    printf("initialized kernel queues %i, %i\n", q.kq_key_in, q.kq_key_out);

    threads[0] = spawn_thread(broadcast_thread, &q);
    threads[1] = spawn_thread(process_kq_msg_thread, &q);
    threads[2] = spawn_thread(recv_packet_thread, &q);
    threads[3] = spawn_thread(builder_thread, &q);

    for(int i = 0; i < 4; ++i){
        pthread_join(threads[i], NULL);
    }
}
