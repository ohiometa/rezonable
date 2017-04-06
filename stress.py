#!/usr/bin/python

from __future__ import division, print_function

from bz2 import BZ2File as bopen
from os import system

try:
	rank, f = 0, bopen('/var/tmp/alexa-top-1M-27-mar-2017.bz2')
	while True:
		dom = f.readline().strip()
		rank += 1
		print('%i. %s' % (rank, dom))
		system('dig +time=5 +retry=0 %s' % dom)
except KeyboardInterrupt:
	print('\nHad enough?')

