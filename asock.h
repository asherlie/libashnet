#include <stdint.h>
#include <sys/types.h>

/* this code is not used in ashnetd - it is provided as an abstraction on direct messages for the user it behaves similarly to sockets
 * as of now, there's no need for connect(), listen(), accept()
 * TODO: should accept() be defined? could just wait for a new socket
 * TODO: i can test this on a single machine
*/
typedef struct{
    uint8_t peer[6];
    int port;
    
    key_t incoming, outgoing;
}asock_t;

asock_t asocket(key_t incoming, key_t outgoing);

ssize_t arecv(asock_t socket, void* buffer, size_t length, int flags);
ssize_t asend(asock_t socket, const void* buffer, size_t length, int flags);

create socket - sends a messsage with dest field and variety byte set as port and no body
this is done by sending a /SOCKET message
the caller is provided with a struct to represent this socket
the burden of avoiding duplicate port/addr pairs is on the programmer
