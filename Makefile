
all: nicedaemon

nicedaemon: nicedaemon.c fork_connector.c
	cc -O3 -Wall -ansi -pedantic -std=c99 nicedaemon.c -o nicedaemon

install:
	cp nicedaemon /usr/bin/
	cp nicedaemon.service /usr/lib/systemd/system/
	cp -n nicedaemon.conf /etc/nicedaemon.conf

remove:
	rm /usr/bin/nicedaemon
	rm /usr/lib/systemd/system/nicedaemon.service
