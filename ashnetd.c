/*

ashnetd

we'll need to keep track of duplicates
    this should be done by building a hash map
    that indexes based on mac address
    we will store the most recent n messages from
    each address
    if addr, ssid are exactly the same, IGNORE


broadcast thread
    POPS FROM READY_QUEUE
        ready queue contains both packets cooked by bakery thread
        as well as propogations


    pops from a queue of messages
    this queue will contain both raw strings of arbitrary length
    and cooked packets that are being spread

    to keep it simple, there should be a custom mq that has cooked packets
    ready to be sent
    ready_queue

a 'bakery' thread will pop messages from sys v queue and split them into cooked packets
adding fragments into our ready_queue
this same ready_queue will be added to when messages are recieved in the msg_builder_thread

packet_receive_thread will receive raw messages, confirm they're part of our network, and
add them to our raw_packet_queue to be processed by packet_handler_thread

packet_handler_thread will pop messages from our internal raw_packet_queue, check if our
new messae is an exact duplicate of one already received, add usernames to
our address username lookup structure in the event of beacon packets
if message has no associated username, ignore it
we then insert our new packet into our message building structure
this insertion will return success/our new full packet in the event of a newly available
fully constructed packet
each time a full packet is constructed, the username and message contents are added to a sys v queue
for the user to read from
each received packet that is not a duplicate will be added to the ready_queue for propogation
*/
#include <stdint.h>

void recv_packet(uint8_t* buf, int* len){
    *buf = 8;
    *len = 1;
}

void broadcast_packet(uint8_t* buf, int len){
    (void)buf;
    (void)len;
}

int main(){
}
