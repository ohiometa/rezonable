#!/usr/bin/python2
# rezonable resolution functions

# About CPython2 lists
#
# Insert at beginning runs nearly twice as long as insertion at end,
# but deletion at beginning runs hundreds of times as long as at end.
# Also, reading at [-1] is slightly cheaper than reading at [0].
# So if you want a cheap deque, .insert(0, blah) and .pop() are fine.

# Convention:
#
# 'q' is for local queries (LQs; to us, whether or not colocated)
# 'r' is for remote queries (RQs; from us to other resolvers)

from __future__ import division, print_function
from random import randrange
from sys import stdout
from time import sleep, strftime

from cache import *
import config as w
from parsun import *
from tiny import *

__all__ = 'atdq ctda tick unpurge'.split()

# new enums: CNAME, failure, no such domain, result, need more time
isCNAME, isRecursed, isFail, isNSD, isRecs, isWait = range(6)

# special rcode enum
rcodeTimeout = -1

waiter = []					# deque of remote queries by expire time
finder = {}					# dict of remote queries by 16-bit id

# Module entry point #1*:
# Accepts an LQ and someday returns an answer.
#
# Usual operation is when parentQuery is None, meaning we will send
# a reply for the LQ when we finish.
#
# If a parent query is supplied, just set up the fields and don't
# call attend(), because it will jump from parent to child on its own.
#
# If parentQuery is False, we call attend() but don't return a reply
# to any local query. The query was forced by a cache purge or by
# stress testing.
#
def atdq(q, parentQuery = None):
	q.gen = newResolver(q)	# does not execute, but returns a generator
	q.rcode = 0
	q.lastzone = ''
	q.origName = q.name
	q.cnames = [q.name]
	q.As, q.Auths, q.Addls = [], [], []
	q.parent = parentQuery
	if not parentQuery:
		attend(q)

# Module entry point #2**:
# An RQ has been answered and needs checked out.
# We leave all breadcrumbs in place until the RQ would have timed out.
def ctda(a):

	r = finder.get(a.id)
	if not r:
		return 'nothing pending for id %i' % a.id
	q = r.q
	if r.name != a.name or r.tipe != a.tipe:
		return 'wrong question answered'
	if r.replyTo != a.replyTo:
		return 'response from unexpected address'

	# We did not time out. Store obtained information in the cache.
	r.running = False
	r.q.rcode = a.rcode

	# Our goal here is to save as little as possible from the records
	# returned, not so much to save memory, but mostly to limit opportunities
	# for the cache to be poisoned.
	while True:									# does not loop

		# If we get an authoritative "no such domain," so cache.
		if a.aa and a.rcode == 3:
			for bye in 1, 2, 5:					# XXX kludge; want actual types
				setCache(a.name, bye)
			setCache(a.name, 65282, [], w.nsdTTL)	# XXX Prefer TTL from SOA.
			break

		# Any nonzero rcode at this point indicates failure.
		if a.rcode: break

		# If we get a relevant CNAME, store that AND NOTHING ELSE.
		recs = [(name, tipe, ttl, rdata) for (name, tipe, ttl, rdata) in a.As if tipe == 5 and name == a.name]
		if recs:
			setCache(a.name, 5, [recs[0][3]], ttl)
			break

		# If we get an authoritative "no records," store that AND NOTHING ELSE.
		# XXX TTL would be better from SOA.
		if a.aa and not a.As:
			setCache(a.name, a.tipe, [], w.nsdTTL)
			break

		# If we get relevant records, store them.
		minTTL = w.maxTTL
		recs = []
		for name, tipe, ttl, rdata in a.As:
			if name == a.name and tipe == a.tipe:
				recs.append(rdata)
				minTTL = min(ttl, minTTL)
		if recs:
			setCache(a.name, a.tipe, recs, minTTL)
			break

		# If we get nameserver records that pertain to our question, cache.
		closest = ''
		recs = []
		for name, tipe, ttl, rdata in a.Auths:
			if tipe != 2: continue
			if not withinZone(a.name, name): continue
			if len(name) > len(closest):
				closest = name
				recs = []
				minTTL = w.maxTTL
			recs.append(rdata)
			minTTL = min(ttl, minTTL)
		if recs:
			setCache(closest, 2, recs, minTTL)	# fall through
		else:
			break

		# If we get glue records for referenced nameservers that are
		# inside the zone we're looking up, cache. This is a big security
		# issue and what keeps the domain admin for us.af.mil. from
		# hijacking us.navy.mil.		# TODO make sure it works
		nsNames, recs = recs, []
		for name, tipe, ttl, rdata in a.Addls:
			if tipe not in (1, 28): continue
			if name not in nsNames: continue
			if not withinZone(name, closest): continue
			setCache(name, tipe, [rdata], ttl)
			# XXX That might work, but does not permit more than one A
			#     record per nameserver.

		break									# does not loop

	# Local query needs attention again.
	attend(r.q)

# Module entry point #3:
#
# Kick or delete timed-out RQs. Note LQs initiate 0 or more distinct RQs.
#
# The deque is very simplistic, with all RQs given the same lifespan that
# cannot be extended. Completed RQs aren't removed until they time out.
def tick():
	while waiter and g.flow >= waiter[-1].timeout:

		# this is the ONLY place we remove from finder and waiter
		r = waiter.pop()
		del finder[r.id]
		if r.running:		# no double-kicking
			r.q.rcode = rcodeTimeout
			attend(r.q)
		del r

# Continue an LQ that is ready for attention.
# This is the function that reaps ALL yielded values.
def attend(q):
	while True:
		try:
			flavor, ttl, food = q.gen.next()
		except StopIteration:
			return						# can occur if dupe packet received

		# deal with recursive side-query for address of nameserver
		if flavor == isRecursed:
			# food.parentQuery = q		# gone: now done in another way
			q = food
			continue

		# deal with CNAME
		if flavor == isCNAME:

			# add CNAME to answer section
			q.As.append((q.name, 5, ttl, food))

			# block to avoid CNAME loop
			if food not in q.cnames:
				q.cnames.append(food)
				if q.tipe == 5:			# CNAME query complete
					break
				q.name = food			# normal query keeps going
				q.lastzone = ''			# restart from root if needed
				continue

			# we get here if there is a CNAME loop
			flavor = isFail				# fall into next block

		# deal with failure
		if flavor == isFail:
			q.rcode = 2

		# deal with non-existent domain
		elif flavor == isNSD:
			q.rcode = 3					# XXX and might already be

		# query was successful
		elif flavor == isRecs:
			for rdata in food:
				q.As.append((q.name, q.tipe, ttl, rdata))

		# remote query pending
		elif flavor == isWait:
			return

		else: raise Bug
		break							# only isCNAME and isRecursed loop

	# Tail end recurse ): if this query has a parent.
	if q.parent:
		attend(q.parent)
		return

	# No reply is possible if this wasn't a local query.
	if q.parent is False: return

	# We are now able to respond to the user.
	a = AdHoc()
	a.rcode, a.cd, a.ad, a.z, a.ra, a.rd, a.aa, a.opcode, a.qr = \
		q.rcode, 0, 0, 0, 1, q.rd, 0, 0, 1
	a.id, a.replyTo, a.name, a.tipe = q.id, q.replyTo, q.origName, q.tipe
	a.As, a.Auths, a.Addls = q.As, [], []
	g.loSock.sendto(unparse(a), a.replyTo)

	# Any user query that made it this far will be immortal.
	if q.tipe == 1:
		g.immortal.add(q.origName)

# Recursive resolver implemented as a generator function.
# This is the ONLY function that yields.
# It's important to have fun while implementing this.
#
# The actual resolver is created by calling this, and stored at q.gen;
# it is run or continued by calling q.gen.next(). We can't set q.gen
# directly from here because of Python's generator semantics; we have
# to wait for this function (which again is NOT our resolver, although
# it might look that way) to return.
#
# The caller might have a lot of fields on 'q', but the only ones that
# are necessary are 'name', 'tipe', 'replyTo', and those set by atdq().
#
def newResolver(q):

	# Keep in mind we only get HERE (above the loop) once per LQ.
	while True:

		name, tipe = q.name, q.tipe

		# No such domain?
		# XXX The cache semantics needed are not implemented yet.
		# XXX TTL should realistically come from an SOA.
		if getCache(name, 65282) is not None:
			yield isNSD, w.nsdTTL, None
			return					# local query ends

		# CNAME? Hand it back.
		cname, ttl = getCacheTTL(name, 5)
		if cname:
			yield isCNAME, ttl, cname[0]
			continue

		# Found the record we want? Hand those back.
		recs, ttl = getCacheTTL(name, tipe)
		if recs is not None:
			yield isRecs, ttl, recs
			return					# local query ends

		# What we seek is not in the cache.
		# We will query the nearest nameserver(s) for help.
		zone, servers = nearestNameservers(name)

		if len(zone) == len(q.lastzone):
			# Successful nameserver query, but no progress.
			# This happens all the time because of references to names
			# that have no A records, and perhaps for other reasons.
			# It's not our problem to fix.
			q.rcode = 2
			yield isFail, None, None
			return					# local query ends
		q.lastzone = zone

		triple_continue = False
		for ns in w.queryRepeats * servers:
			addrs = getCache(ns, 1)
			if addrs is None:

				# A recursive query instance 'qq' is needed to get the
				# nameserver's A records. But first make sure we won't loop.
				who = q
				while who:
					if who.name == ns and who.tipe == 1:
						break						# double-continue
					who = who.parent
				if who: continue

				# This will be an "original" query, so it's okay to begin.
				qq = AdHoc()
				qq.name, qq.tipe, qq.replyTo = ns, 1, None
				atdq(qq, q)
				yield isRecursed, None, qq

				# The recursive query is finished. Magic!
				addrs = getCache(ns, 1)
				if addrs is None:
					yield isFail, None, None

			for addr in addrs:

				# Send query to addr about (name, tipe)
				enq(q, name, tipe, addr)
				yield isWait, None, None

				# Query succeeded. Continue at top of outermost loop.
				if q.rcode in (0, 3):
					triple_continue = True
					break

				# Query timed out (most common) or failed (less common).
				# Try the next nameserver.
				if q.rcode != rcodeTimeout:
					msg('failed: ns', ns, 'rcode', q.rcode, 'zone', zone, 'origName', q.origName, 'for', name, tipe)
				break				# continues to next ns

			if triple_continue: break
		if triple_continue: continue

		# Not a single nameserver responded successfully.
		msg('out of options at zone', zone, 'for', name, tipe)
		yield isFail, None, None
		return						# local query ends

# Send query to addr about (name, tipe)
def enq(q, name, tipe, addr):

	r = AdHoc()						# remote query
	r.rcode, r.cd, r.ad, r.z, r.ra, r.rd, r.aa, r.opcode, r.qr = \
		0, 0, 0, 0, 0, 0, 0, 0, 0
	r.name, r.tipe = q.name, q.tipe
	r.As, r.Auths, r.Addls = [], [], []
	r.running = True

	while True:
		r.id = randrange(0, 65536)
		if r.id not in finder: break

	# connections needed to find r and q later
	r.q = q
	r.timeout = g.flow + w.queryTimeout
	r.replyTo = dq(addr), 53

	# this is the ONLY place we add to finder or waiter
	finder[r.id] = r
	waiter.insert(0, r)

	# transmit packet
	g.hiSock.sendto(unparse(r), r.replyTo)

# Ask nearest nameservers for 'name'.
# Returns (zone, ['nameserver', ...]).
# At exhaustion, returns ('.', ['bootstrap']).
def nearestNameservers(name):
	while True:
		ns = getCache(name, 2)
		if ns:
			return name, ns
		name = parentOfZone(name)

# Resurrect immortal domains that were purged from the cache.
def unpurge():
	while g.requery:
		name = g.requery.pop()
		q = AdHoc()
		q.name, q.tipe, q.replyTo = name, 1, None
		atdq(q, False)

# *answer the damn question
# **check the damn answer
