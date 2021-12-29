CC=gcc
CFLAGS= -Wall -Wextra -Wpedantic -Werror -O3 -pthread -lpcap

all: ashnetd

packet_storage.o: packet_storage.c packet_storage.h
rf.o: rf.c rf.h packet_storage.o
mq.o: mq.c mq.h packet_storage.o
kq.o: kq.c kq.h mq.o

ashnetd: ashnetd.c kq.o mq.o packet_storage.o rf.o

.PHONY:
clean:
	rm -f ashnetd *.o
