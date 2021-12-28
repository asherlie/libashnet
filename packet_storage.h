#define UNAME_LEN 20
#define DATA_BYTES 32-sizeof(int)-4

struct __attribute__((__packed__)) packet{
    uint8_t data[DATA_BYTES];
    _Bool flags[4];
    int variety;
};

/* each peer struct represents one mac address
 * that belongs to the network
 */
struct peer{
    char uname[UNAME_LEN];
    uint8_t addr[6];

    struct peer* next;
};

struct packet_storage{
    /* this might be useless - do we even
     * access packet storage from different
     * threads?
     */
    //pthread_mutex_t ps_locks[50];
    pthread_mutex_t ps_lock;
    /* (0xff * 6) + 1 */
    struct peer* buckets[1531];
};

void init_packet_storage(struct packet_storage* ps);
struct peer* insert_uname(struct packet_storage* ps, uint8_t addr[6], char uname[UNAME_LEN]);
