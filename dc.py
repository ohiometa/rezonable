#!/usr/bin/python2
# Rezonable diagnostic console

from __future__ import division, print_function
from gc import get_objects
from sys import stdout
from thread import interrupt_main

from cache import cacheDump, saveCache
import config as w
from tiny import *

__all__ = 'consoleDo consoleThread'.split()

hello = 'Rezonable console\n'
prompt = '- '
typed = []							# lines typed by user into stdin

# Show counts of what garbage collector tracks.
def histo():
	names = {}
	try:
		for item in get_objects():
			n = type(item).__name__
			if n not in names:
				names[n] = 0
			names[n] += 1
	except: raise
	nl = list(names)
	nl.sort()
	print('MEMORY HISTOGRAM BY TYPE:')
	for n in nl:
		print('%6i %s' % (names[n], n))

# Loop and get user input
def consoleThread():
	try:
		print(hello, end='')
		print(prompt, end='')
		stdout.flush()
		while True:
			l = raw_input().strip()
			if not l: continue
			typed.insert(0, l)
	except EOFError, KeyboardInterrupt:
		interrupt_main()		

# Process user to do diagnostic things
def consoleDo():
	while typed:
		l = typed.pop()
		if False: pass
		elif l == 'c':
			print('\x1bc', end='')
		elif l == 'd':
			cacheDump()
		elif l == 'h':
			histo()
		elif l == 's':
			saveCache()
			print('saved cache to disk')
		else:
			print('Commands are: (c)lear (d)ump (h)isto (s)ave')
		print(prompt, end='')
		stdout.flush()

