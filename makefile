STEM=rezonable
NOW := $(shell date +%Y%m%d.%H%M%S)
BNAME := /tmp/$(STEM)-$(NOW).bundle

snap:
	git bundle create $(BNAME) --all
	cp $(BNAME) /home/me/Home
	mv $(BNAME) /home/me/Downloads

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

fresh:
	rm -f /var/tmp/rezonable-cache.pickle.gz
