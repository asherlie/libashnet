#pragma once
#include <pthread.h>

#include "packet_storage.h"

struct mq_entry{
    void* data;
    int len;

    struct mq_entry* next;
};

struct mq{
    struct mq_entry* entries, * last;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};

struct queues{
    key_t kq_key_in, kq_key_out;

    struct mq ready_to_send,
              /* raw recvd packets are added here after they 
               * are confirmed as part of the network */
              build_fragments;

    /* access to this isn't required by all pieces of code
     * that have access to queues struct, it's only needed
     * by process_kq_msg() and builder_thread()
     */
    struct packet_storage ps;

    char uname[DATA_BYTES-1];
    uint8_t local_addr[6];
};

void init_mq(struct mq* m);
void insert_mq(struct mq* m, void* data, int len);
struct mq_entry* pop_mq(struct mq* m);
