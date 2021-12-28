#define UNAME_LEN 20
#define DATA_BYTES 32-sizeof(int)-4
#define PACKET_MEMORY 1000

struct __attribute__((__packed__)) packet{
    uint8_t data[DATA_BYTES];
    _Bool flags[1];
    _Bool beacon;
    _Bool built;
    _Bool final_packet;
    int variety;
};

/* each peer struct represents one mac address
 * that belongs to the network
 */
struct peer{
    char uname[UNAME_LEN];
    uint8_t addr[6];

    struct packet** recent_packets;
    /* ins idx is wrapped back to 0 when full */
    int n_stored_packets, ins_idx;

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
char* insert_packet(struct packet_storage* ps, uint8_t addr[6], struct packet* p);
