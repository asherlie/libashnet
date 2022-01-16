CC=gcc
prefix=/usr/local/bin
CFLAGS= -Wall -Wextra -Wpedantic -Werror -g3 -pthread -lpcap

all: ashnetd

packet_storage.o: packet_storage.c packet_storage.h
rf.o: rf.c rf.h packet_storage.o
mq.o: mq.c mq.h packet_storage.o
kq.o: kq.c kq.h mq.o

ashnetd: ashnetd.c kq.o mq.o packet_storage.o rf.o

.PHONY:
install: ashnetd
	install -m 0755 ashnetd $(prefix)

.PHONY:
systemd_service: install
	install ashnetd.service /etc/systemd/system

.PHONY:
start: systemd_service
	systemctl daemon-reload
	systemctl start ashnetd

.PHONY:
clean:
	rm -f ashnetd *.o

.PHONY:
run: ashnetd
	sudo ./ashnetd -ki 857123030 -ko 857123040 -u ASHER -i wlp3s0
