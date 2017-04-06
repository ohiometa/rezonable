STEM=rezonable
NOW := $(shell date +%Y%m%d.%H%M%S)

snap:
	tar cJf /tmp/$(STEM)-$(NOW).tar.xz --exclude=port53 .
	cp /tmp/$(STEM)* /home/me/Home
	mv /tmp/$(STEM)* /home/me/Downloads
	ls -l /home/me/Downloads
	sleep 5
	ls -l /home/me/Downloads

53: setcap

compile: port53.c makefile
	rm -f port53 || sudo rm port53
	gcc -Os -Wall -Wno-unused-result port53.c -o port53
	strip port53

setcap: compile
	chmod 774 port53
	sudo setcap 'cap_net_bind_service=+ep' port53

setuid: compile
	sudo chown root.root port53
	sudo chmod 4775 port53

test1:
	dig detectportal.firefox.com.

test2:
	dig start.ubuntu.com.

test3:
	dig self-repair.mozilla.org.

test4:
	dig ocsp.digicert.com.

test5:
	dig normandy-cloudfront.cdn.mozilla.net.

test6:
	dig a6-67.akam.net.

test7:
	dig a6-67.akam.net. ns
	echo THERE SHOULD BE NO NS RECORDS FOR THIS TEST ONLY.

test8:
	dig a0dsce4.akamaiedge.net.
	echo THERE SHOULD BE NO A RECORDS FOR THIS TEST ONLY.

test9:
	dig www.caltech.edu.

