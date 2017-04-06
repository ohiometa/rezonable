#!/usr/bin/python2

"""
Rezonable is a personal recursive DNS resolver that keeps its cache perpetually
updated. The idea is to flood the cache with nonsense so that eavesdroppers
can't determine anything from DNS traffic. UDP only. Terminology: we answer
queries from "customers" and query upstream from "suppliers". Would love
shorter words, but at least this is a start.

This module is only for "mainline" code:

	packet send and receive
	timeout hooks
	daemonization
	command line handling if any

We are NOT immune to Kaminsky's 2008 DNS vulnerability, but we escape most
of its punch by not allowing strangers to be customers.

Useful numbers:
	https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml


KNOWN BUGS
----------
- dig a6-67.akam.net. ns [should have lots of recs; we return server failure]
- dig a0dsce4.akamaiedge.net. [should have no A recs; we return server failure]
- dig a1e7.akamaiedge.net. [should have no A recs; we return server failure]
- sometimes the platform seems to hang, and we don't know why
- windows.com website?
- memory looks like it goes nuts, but without any witnesses
- requeries do not occur
- anecdotal evidence that NS records for '.' got removed, but
  we were doing gc stress test in an interactive session at tha ttime.


GOING TO DO (minutes to implement estimated)
--------------------------------------------
 30 test expiration
 30 really, "not implemented" and other errors is better than drops;
    for one thing, you can get Firefox to quit asking for AAAAs.
 30 packet length negotiation
 30 reduce susceptability to glue poisoning
 60 improved tracing, logging, and some alerts
 90 compression fully working
 10 pass case back to customer (do AFTER compression)
120 RFC 7873 cookies


WOULD CONSIDER IF THERE IS TIME
-------------------------------
a filter for sensitive names prematurely asked
do not query if firewall won't let responses in
look at misbehaviors of RFC 4697
look at all the interesting details in RFC 2308
test bench
nicer zone files


REFUSE TO DO
------------
DNSSEC: non-implementers, huge crypto library, CPU, RAM, overkill,
	duplicates benefits of TLS and HTTPs
LeET QueRieS: non-implementers, kludge, cookies better
source port randomization: non-implementers, kludge, cookies better


IMPORTANT "A" TEST QUERIES
--------------------------
detectportal.firefox.com.
start.ubuntu.com.
self-repair.mozilla.org.
ocsp.digicert.com.
normandy-cloudfront.cdn.mozilla.net.
a6-67.akam.net. (also check NS)
a0dsce4.akamaiedge.net. (domain should exist but have no A records)
www.caltech.edu.

Alexa top million sites: s3.amazonaws.com/alexa-static/top-1m.csv.zip
Supposedly updated daily.

"""

from __future__ import division, print_function
from os import environ, execve, fork, geteuid, setsid
if not geteuid():	# do this EARLY
	print('rezonable will not run as root!')
	raise SystemExit

from os.path import dirname, join
from select import select
from signal import signal, SIGTERM
from socket import fromfd, socket, timeout, AF_INET, SOCK_DGRAM
from sys import argv
from time import time

from atdq import atdq, ctda, tick
from cache import cacheDump, createBootstrapZone, loadCache, purgeCache, saveCache
import config as w
from hosts import *
from parsun import *
from tiny import *

# listen/respond loop with "timeout" hook
def run():

	# Execute a setcap or setuid C program that binds port 53 to fd 3,
	# and then restart this script after this step.
	if 'exec' not in argv:
		prog = join(dirname(argv[0]), 'port53')
		execve(prog, [prog] + argv + ['exec'], environ)
		print('abort!')

	g.loSock = fromfd(3, AF_INET, SOCK_DGRAM)
	g.hiSock = socket(AF_INET, SOCK_DGRAM)
	g.hiSock.bind(('', w.outgoingPort))

	pollCount = 0
	g.flow = time()
	g.now = int(g.flow)
	def handler(ign, igno): raise KeyboardInterrupt
	signal(SIGTERM, handler)

	argv.append('here')					# TODO rm
	if 'here' in argv:					# command arg 'here' prevents daemon
		print('\x1bc')					# unclutter screen
	else:
		# mini-daemonize
		if fork():						# I think the authbind mechanism
			raise SystemExit			# requires that port 53 already be
		setsid()						# bound before this daemonization.
		if fork():
			raise SystemExit

	createBootstrapZone()
	if 'fresh' not in argv:				# arg 'fresh' prevents cache load
		loadCache()

	while True:

		ready = select([g.loSock, g.hiSock], [], [], 0.1)[0]
		for sock in ready:
			data, replyTo = sock.recvfrom(2048)

			try:
				p = parse(data, replyTo)
			except Malformed:
				trace('malformed')
				continue

			if p.qr:						# process response
				ctda(p)

			else:							# process query

				# Filter queries from privileged ports (DoS + spoofing issue).
				if w.requireUserPort and replyTo[1] < 1024:
					continue

				# Filter queries from unconfigured customers.
				if replyTo[0] not in w.customers:
					continue

				atdq(p)

		if ready: continue
		# the clock has changed, and we aren't busy
		g.flow = time()
		g.now = int(g.flow)

		# Handle fine-grained timer tasks.
		tick()

		# Handle coarse-grained timer tasks.
		pollCount -= 1
		if pollCount <= 0:
			purgeCache()
			loadHosts()
			pollCount = 60			# times settimeout interval XXX longer
		continue

try:
	run()
except KeyboardInterrupt:				# SIGTERM also brings us here
	if 'stealth' not in argv:			# arg 'stealth' prevents cache save
		saveCache()
	cacheDump()

