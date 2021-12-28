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
        m->last = e;
        m->entries = e;
    }
    else{
        m->last->next = e;
        m->last = e;
    }
    pthread_mutex_unlock(&m->lock);
    pthread_cond_broadcast(&m->cond);
    /*pthread_cond_signal(&m->cond);*/
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

        pthread_mutex_unlock(&tmp_lock);

    }

    pthread_mutex_destroy(&tmp_lock);

    return ret;
}

#if 0
#include <unistd.h>

void* delayed_add(void* mv){
    struct mq* m = mv;
    usleep(500000);
    for(int i = 0; i < 10; ++i){
        insert_mq(m, NULL, 923);
    }
    return NULL;
}

int main(){
    struct mq m;
    pthread_t pth;

    init_mq(&m);

    insert_mq(&m, NULL, 50);
    insert_mq(&m, NULL, 40);
    printf("%i\n", pop_mq(&m)->len);
    printf("%i\n", pop_mq(&m)->len);
    insert_mq(&m, NULL, 99);

    printf("%i\n", pop_mq(&m)->len);
    pthread_create(&pth, NULL, delayed_add, &m);
    printf("%i\n", pop_mq(&m)->len);
}
#endif
