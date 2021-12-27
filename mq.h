#include <pthread.h>

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

void init_mq(struct mq* m);
void insert_mq(struct mq* m, void* data, int len);
struct mq_entry* pop_mq(struct mq* m);
