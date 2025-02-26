CC=gcc
prefix=/usr/local/bin
CFLAGS= -Wall -Wextra -Wpedantic -Werror -Wshadow -Wformat=2 -fno-common -g3 -pthread -lpcap 

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
	systemctl stop ashnetd
	systemctl start ashnetd
	systemctl enable ashnetd

.PHONY:
clean:
	rm -f ashnetd *.o

.PHONY:
run: ashnetd
	sudo ./ashnetd -ki 5 -ko 10 -u ASHER -i wlp3s0
