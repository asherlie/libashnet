#include <sys/msg.h>
#include <stdlib.h>

#include "mq.h"

#define KQ_MAX 1000

struct msgbuf{
    long mtype;
    char mdata[KQ_MAX];
};

void set_kq_key(struct queues* q, key_t kq_in, key_t kq_out){
    /* TODO: kqueues will be identical because time(NULL)
     * has one second granularity
     */
    if(kq_in > 0){
        q->kq_key_in = kq_in;
    }
    else{
        srand(time(NULL));
        q->kq_key_in = random();
    }

    if(kq_out > 0){
        q->kq_key_out = kq_out;
    }
    else{
        srand(time(NULL));
        q->kq_key_out = random();
    }

    /* create queues if they don't exist */
    msgget(q->kq_key_in, 0777 | IPC_CREAT);
    msgget(q->kq_key_out, 0777 | IPC_CREAT);
}
