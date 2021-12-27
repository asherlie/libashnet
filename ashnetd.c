/*

ashnetd

we'll need to keep track of duplicates
    this should be done by building a hash map
    that indexes based on mac address
    we will store the most recent n messages from
    each address
    if addr, ssid are exactly the same, IGNORE


broadcast thread
    POPS FROM READY_QUEUE
        ready queue contains both packets cooked by bakery thread
        as well as propogations


    pops from a queue of messages
    this queue will contain both raw strings of arbitrary length
    and cooked packets that are being spread

    to keep it simple, there should be a custom mq that has cooked packets
    ready to be sent
    ready_queue

a 'bakery' thread will pop messages from sys v queue and split them into cooked packets
adding fragments into our ready_queue
this same ready_queue will be added to when messages are recieved in the msg_builder_thread

packet_receive_thread will receive raw messages, confirm they're part of our network, and
add them to our raw_packet_queue to be processed by packet_handler_thread

packet_handler_thread will pop messages from our internal raw_packet_queue, check if our
new messae is an exact duplicate of one already received, add usernames to
our address username lookup structure in the event of beacon packets
if message has no associated username, ignore it
we then insert our new packet into our message building structure
this insertion will return success/our new full packet in the event of a newly available
fully constructed packet
each time a full packet is constructed, the username and message contents are added to a sys v queue
for the user to read from
each received packet that is not a duplicate will be added to the ready_queue for propogation
*/
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <pthread.h>

#include "mq.h"
#include "kq.h"

void init_queues(struct queues* q, key_t k_in, key_t k_out){
    init_mq(&q->ready_to_send);
    init_mq(&q->build_fragments);
    set_kq_key(q, k_in, k_out);
}

void recv_packet(uint8_t* buf, int* len){
    *buf = 8;
    *len = 1;
}

void broadcast_packet(uint8_t* buf, int len){
    (void)buf;
    (void)len;
}

void* broadcast_thread(void* arg){
    struct queues* q = arg;
    struct mq_entry* e;
    while(1){
        puts("runnign b thread omg");
        e = pop_mq(&q->ready_to_send);
        broadcast_packet(e->data, e->len);
    }
}

pthread_t spawn_thread(void* (*func)(void *), void* arg){
    pthread_t ret;
    pthread_create(&ret, NULL, func, arg);
    return ret;
}

int main(){
    struct queues q;
    init_queues(&q, 857123030, 857123040);
    printf("initialized kernel queues %i, %i\n", q.kq_key_in, q.kq_key_out);

    spawn_thread(broadcast_thread, &q);
}
