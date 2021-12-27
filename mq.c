#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "mq.h"

void init_mq(struct mq* m){
    pthread_mutex_init(&m->lock, NULL);
    pthread_cond_init(&m->cond, NULL);
    m->last = NULL;
    m->entries = NULL;
}

void insert_mq(struct mq* m, void* data, int len){
    struct mq_entry* e = calloc(1, sizeof(struct mq_entry));
    e->data = data;
    e->len = len;
    pthread_mutex_lock(&m->lock);
    if(!m->entries){
        m->entries = e;
    }
    else{
        m->last->next = e;
        m->last = e;
    }
    pthread_mutex_unlock(&m->lock);
    pthread_cond_signal(&m->cond);
}

struct mq_entry* pop_mq(struct mq* m){
    struct mq_entry* ret = NULL;
    pthread_mutex_t tmp_lock;

    pthread_mutex_init(&tmp_lock, NULL);

    while(!ret){
        pthread_mutex_lock(&tmp_lock);
        pthread_mutex_lock(&m->lock);

        if(m->entries){
            ret = m->entries;
            m->entries = m->entries->next;
            pthread_mutex_unlock(&m->lock);
            break;
        }

        pthread_mutex_unlock(&m->lock);

        pthread_cond_wait(&m->cond, &tmp_lock);

        /*pthread_mutex_unlock(&tmp_lock);*/

    }

    pthread_mutex_destroy(&tmp_lock);

    return ret;
}

int main(){
    struct mq m;
    init_mq(&m);

    insert_mq(&m, NULL, 50);

    printf("%i\n", pop_mq(&m)->len);
    pop_mq(&m);
}
