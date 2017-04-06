# #!/usr/bin/python2
# query processing for Rezonable

# TODO
"""
This module's top BUGS are as follows.

  4. iffy integration with ask.py

  5. iffy integration with g.cache

  6. maximal.py should not exist anymore

  7. trace might hide some details needlessly

"""

from __future__ import division, print_function
from time import ctime, sleep

from ask import *
from cache import *
from dumper import *
from maximal import *
from parsun import *
from tiny import *

__all__ = 'doQuery kickQueries'.split()

activeQs = []						# user requests for DNS lookups

class Subtask(object):
	# XXX consider renaming expired
	waiting = -1					# status constants
	answered = 0
	expired = 1						# "expired" is also the initial condition
	failed = 2						# that gets us moving to start with.
	finished = 3

	def __init__(z, name, tipe):
		z.status = z.expired
		z.name = name
		z.tipe = tipe

		z.nearestZone = ''			# best zone to resolve z.name in
		z.tryNS = []				# [None, ns1, ns2, ...] for this zone
		z.thisNS = ''				# nameserver being tried right now
		z.tryAddr = []				# [None, addr1, addr2, ...] for thisNS

# We received a query, generally from a local user e.g., Firefox.
def doQuery(q, real = True):
	q.real = real						# indicates a reply should be sent
	name, tipe = q.Qs[0]				# already guaranteed q.nQ is 1
	red('user query', tipe, name)
	q.stack = [Subtask(name, tipe)]
	goGet(q.stack)				# a manual "kick" as a cache check
	if not q.stack:
		doQueryMaximal(q)				# cache answered everything
	else:
		activeQs.append(q)				# a remote lookup has started

# handle queries that need attention
def kickQueries():
	if not g.kickMe: return
	g.kickMe = False

	for name in g.requery:			# resurrect immortal domains
		q = AdHoc()
		q.Qs = [(name, 1)]
		doQuery(q, False)
	g.requery = []

	for q in activeQs[:]:			# process active queries
		goGet(q.stack)
		if not q.stack:
			if q.real: doQueryMaximal(q)
			activeQs.remove(q)

# Find the nearest-available nameserver records. Never an empty set.
# Returns the applicable zone name along with the records.
def findNearestNS(name):
	while True:
		while True:
			d = g.cache.get(name)
			if not d: break
			ns = d.get(2)
			if not ns: break
			return name, ns
		name = parentOfZone(name)

# go get whatever's at the top of the stack
def goGet(s):

	while s:
		t = s[-1]					# current subtask
		name, tipe = t.name, t.tipe

		if tracing:					# diagnostic
			width = 15
			print(' ' * len(s) + '+' + ' ' * (width - len(s)), end='')
			width = 30
			nm = name if len(name) <= width else name[:29] + '+'
			print('%2i  %-2s  %-*s  ' % \
				(t.status, rrTypes[tipe], width, nm), end='')

		# ---------------------------------------------------------------------
		# Start with checks that require the least knowledge, and work forward.
		# ---------------------------------------------------------------------

		# See if task already succeeded. This happens after we finish
		# processing a CNAME subtask. The original task has nothing left,
		# because it found the CNAME, but it had to stay on the stack
		# in order to detect loops.
		if t.status == t.finished:
			trace('already complete')
			s.pop()
			continue

		# See if someone got confused, put in a dotted quad instead of name.
		if name[0].isdigit() and parse_dotted_quad(name[:-1]) != None:
			trace('dotted quad')
			s.pop()
			continue

		# See if current task is part of a loop on the stack.
		looping = False
		for tt in s[:-1]:
			if tt.name == name and tt.tipe == tipe:
				looping = True
				break					# second-level continue construct
		if looping:
			# We have come to the same point.
			trace('loop')
			s.pop()
			continue

		# See if we have a CNAME for this name.
		d = g.cache.get(name)
		if d and 5 in d and d[5]:
			t.status = t.finished	# This task is still searchable, but
			cn = d[5][-1]			# it won't be restarted.
			trace('CNAME', cn)
			if tipe == 5:
				continue			# non-issue (it was a CNAME query)

			# New subtask: look up records for the discovered name.
			s.append(Subtask(cn, tipe))
			continue

		# See if the cache already has an answer.
		if d and tipe in d:
			s.pop()
			if tracing:				# this block is merely print formatting
				if d[tipe]:
					ans = d[tipe][-1]
					if tipe == 1: ans = dq(ans)
				else:
					ans = 'empty recordset'
				print(ans)
			continue

		# If a remote query is still pending, give it time.
		if t.status == t.waiting:
			print('\r', end='')
#			print('query pending')
			return

		# At this point status is either failed or expired.
		# XXX Right now there isn't a distinction in what happens next.

		# See if we have a closer delegation than we've been looking in.
		zone, zoneNS = findNearestNS(name)
		if len(zone) > len(t.nearestZone):

			# We've made progress and need to shift our attention.
			# The None marker distinguishes between having tried
			# all nameservers vs. not having obtained them yet.
			# Automatic retries are facilitated by 'queryRepeats'.
			t.nearestZone, t.tryNS = zone, [None] + queryRepeats * zoneNS
			t.thisNS, t.tryAddr = '', []
			trace('ns avail for ' + zone)
			continue

		# See if we have an address to send our query to.
		if t.tryAddr:
			ask = t.tryAddr.pop()
			if ask:								# watch for None
				askFor(name, tipe, ask, t)
				trace('asking', t.thisNS)
				continue
			# We drop out here after we've tried all addrs for this NS.

		# See if we have the name of a server to send our query to.
		if t.tryNS:

			# This is the NS we want to try, but we require its A records.
			ns = t.tryNS[-1]
			if ns:								# watch for None
				d = g.cache.get(ns)
				if d and 1 in d:# and d[1]:		TODO decide

					# We have them ready now, so we set them in order.
					# The None marker distinguishes between having tried
					# all addresses vs. not having obtained them yet.
					t.thisNS = t.tryNS.pop()
					t.tryAddr = [None] + d[1]
					trace('A records ready')
					continue
				
				# They are not ready, so we can't make further progress with t.
				# Create a subtask that will solve the problem, provided it's
				# not already on the stack.
				looping = False
				for tt in s:
					if tt.name == ns and tt.tipe == 1:
						looping = True
						break				# second-level continue construct

				if looping:
					bye = t.tryNS.pop()
					trace('skip over', bye)
					continue
				else:
					s.append(Subtask(ns, 1))
					trace('pursuing A for ' + ns)
					continue
			# We drop out here after we've tried all nameservers for this zone.

		# No NS queries worked where they should have.
		trace('exhausted options')
		s.pop()
		continue

