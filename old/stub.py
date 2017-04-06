#!/usr/bin/python2
# An easy-to-start stub resolver for use during rezonable maintenance.

from __future__ import division, print_function
from os import environ, execve, fork, geteuid, setsid
if not geteuid():	# do this EARLY
	print('rezonable will not run as root!')
	raise SystemExit

from os.path import dirname, join
from select import select
from signal import signal, SIGTERM
from socket import fromfd, socket, timeout, AF_INET, SOCK_DGRAM
from struct import pack, unpack
from sys import argv
from time import time

from config import *
from tiny import *

queryDB = {}		# database of query objects indexed by query id
userQueries = []	# list of requests being worked on

# listen/respond loop with "timeout" hook
def run():

	# Execute a setcap or setuid C program that binds port 53 to fd 3,
	# and then restart this script after this step.
	if 'exec' not in argv:
		prog = join(dirname(argv[0]), 'port53')
		execve(prog, [prog] + argv + ['exec'], environ)
		print('abort!')
	print('rezonable stub resolver: love it or kill it')

	# 'sLo' is a low-numbered socket, like 53 (to/from user)
	# 'sHi' is a high-numbered socket, like 3553 (to/from external resolver)
	sLo = fromfd(3, AF_INET, SOCK_DGRAM)
	sHi = socket(AF_INET, SOCK_DGRAM)
	sHi.bind(('', outgoingPort))

	pollCount = 0
	def handler(ign, igno): raise KeyboardInterrupt
	signal(SIGTERM, handler)

	argv.append('here')					# TODO rm
	if 'here' not in argv:				# command arg 'here' prevents daemon
		# mini-daemonize
		if fork():						# I think the authbind mechanism
			raise SystemExit			# requires that port 53 already be
		setsid()						# bound before this daemonization.
		if fork():
			raise SystemExit

	nextSerial = 0

	# pathBack[remoteSerial] = (localSerial, (addr, port))	
	pathBack = {}

	while True:

		ready = select([sLo, sHi], [], [], 10)[0]

		# don't actually remember 65536 unresponded queries forever
		if not ready and len(pathBack) > 100:
			pathBack.clear()

		for sock in ready:
			data, who = sock.recvfrom(2048)
			if len(data) < 12: continue

			if sock == sLo:			# incoming request

				# remember who this is for, and what id they used
				ser = pack('!H', nextSerial)
				nextSerial = (nextSerial + 1) & 0xffff
				pathBack[ser] = data[:2], who

				# send to supplier with our own serial number
				sHi.sendto(ser + data[2:], (stubAddr, 53))

			else:					# incoming reply

				# retrieve who this was for, and they id they used
				try:
					ser, who = pathBack[data[:2]]
				except:
					continue

				# return to customer with their own serial number
				sLo.sendto(ser + data[2:], who)
				del pathBack[data[:2]]

try:
	run()
except KeyboardInterrupt:				# SIGTERM also brings us here
	pass
