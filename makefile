CC=gcc
CFLAGS= -Wall -Wextra -Wpedantic -Werror -O3 -lpthread

all: ashnetd

packet_storage.o: packet_storage.c packet_storage.h
mq.o: mq.c mq.h packet_storage.o
kq.o: kq.c kq.h mq.o

ashnetd: ashnetd.c kq.o mq.o packet_storage.o

.PHONY:
clean:
	rm -f ashnetd *.o
