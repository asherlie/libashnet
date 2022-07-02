#include <stdint.h>
#include <sys/types.h>

/* this code is not used in ashnetd - it is provided as an abstraction on direct messages for the user it behaves similarly to sockets
 * as of now, there's no need for connect(), listen(), accept()
*/
typedef struct{
    uint8_t peer[6];
    int port;
}asock_t;

asock_t asocket();

ssize_t arecv(asock_t socket, void* buffer, size_t length, int flags);
ssize_t asend(asock_t socket, const void* buffer, size_t length, int flags);
create socket 11k
