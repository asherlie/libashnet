#include <sys/msg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mq.h"

#define KQ_MAX 1000

struct msgbuf{
    long mtype;
    char mdata[KQ_MAX+1];
};

void set_kq_key(struct queues* q, key_t kq_in, key_t kq_out){
    if(kq_in > 0){
        q->kq_key_in = kq_in;
    }
    else{
        /* subtracting a constant from time(NULL) to ensure
         * that this and the potential next call to time()
         * differ so that we are guaranteed two distinct kqueues
         */
        srand(time(NULL)-2391);
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

_Bool insert_kq(char* msg, key_t kq, uint8_t mtype){
    int msgid = msgget(kq, 0777);
    struct msgbuf buf = {0};
    buf.mtype = mtype;
    strncpy(buf.mdata, msg, KQ_MAX);

    /* TODO: don't use strnlen() here, insert_kq() should
     * require a len argument
     */
    return !msgsnd(msgid, &buf, strnlen(buf.mdata, KQ_MAX), 0);
}

uint8_t* pop_kq(key_t kq, uint8_t* mtype){
    int msgid = msgget(kq, 0777), br;
    struct msgbuf buf = {0};
    uint8_t* ret;

    br = msgrcv(msgid, &buf, KQ_MAX, 0, 0);
    ret = malloc(br+1);
    memcpy(ret, buf.mdata, br);
    ret[br] = 0;
    if(mtype)*mtype = buf.mtype;

    return ret;
}
