#include <stdlib.h>

#include "mq.h"

void set_kq_key(struct queues* q, key_t kq_in, key_t kq_out);
uint8_t* pop_kq(key_t kq);
_Bool insert_kq(char* msg, key_t kq);
