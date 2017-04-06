# #!/usr/bin/python2
# ask remote servers for information

# This module now uses the conventional query strategy of asking everyone
# the same question, and following delegations. It's fast and avoids asking
# impertinent things of certain servers, but it has the drawback of possibly
# asking everyone from the root zone down for sensitive names.

from __future__ import division, print_function
from random import randint

from cache import *
from config import *
from dumper import *
from parsun import *
from tiny import *

__all__ = 'askFor checkAnswer forgetOldQueries'.split()

asked = {}			# pending requests of remote servers, by 16-bit id

# Create outgoing query: ONE name, ONE tipe, ONE server address, NO retries.
# Outcome will be indicated by changing 'task.status'.
def askFor(name, tipe, addr32, task):
	q = AdHoc()
	while True:							# create a "unique" id
		q.id = randint(0, 65535)
		if q.id not in asked: break
	expire = g.flow + queryTimeout
	q.name, q.tipe, q.who, q.expire, q.task = name, tipe, addr32, expire, task
	q.Qs = [(name, tipe)]
	p = setupPacket(q)					# p = q with all required fields
	dumpPacket(p)
	p = unparse(p)						# now in RFC (buffer) format
	to = dq(addr32), 53
	g.bigSock.sendto(p, to)
	asked[q.id] = q
	task.status = task.waiting

# Forget about queries that have run out of time.
def forgetOldQueries():
	for q in list(asked.itervalues()):
		if g.flow < q.expire: continue

		# Maybe this nameserver's a dud. Edit the zone's nameserver
		# list so it will be tried last next time.
		t = q.task
		d = g.cache.get(t.nearestZone, None)
		if d:
			nsl = d.get(2, None)
			if nsl and t.thisNS in nsl:
				green('disfavoring NS', t.thisNS, 'for zone', t.nearestZone)
				nsl.remove(t.thisNS)
				nsl.insert(0, t.thisNS)

		# Kill query, mark stack as ready for attention, recheck stacks
		del asked[q.id]
		t.status = t.expired
		g.kickMe = True

# Determine if a response seems legitimate on the surface.
# Returns an XXX error message or None if okay.
def checkAnswer(a):
	q, why = asked.get(a.id), None
	t = q.task
	addr32 = parse_dotted_quad(a.replyTo[0])
	if not q:
		return 'id has expired or never came from us'
	if a.nQ != 1:
		why = 'wrong number of questions'		
	elif (q.name, q.tipe) != a.Qs[0]:
		why = 'wrong question answered'
	elif addr32 != q.who:
		why = 'response from unexpected address'
	elif a.rcode != 0 and not (a.rcode == 3 and a.aa):
		why = 'remote indicates failure'
	if why:
		del asked[a.id]
		t.status = t.failed				# let requester try something else
		g.kickMe = True
		return why

	# Curious if answer is authoritative, and when it's not.
#	if not a.aa:
#		trace('non-authoritative answer')

	# Perhaps some names in the reply have NOTHING to do with our query.
	# Iteratively make a list of "related" names.
	a.name, a.tipe = a.Qs[0]
	related, counted = { a.name }, 1
	while True:
		for name, tipe, ttl, rdata in a.As + a.Auths + a.Addls:
			if name not in related: continue
			for addMe in rdataToDomain(rdata, tipe):
				related.add(addMe)
		if counted == len(related): break
		counted = len(related)

	# Unrelated names are foreign. We might opt to filter them later. XXX
	foreign = set()
	for name, tipe, ttl, rdata in a.As + a.Auths + a.Addls:
		for addMe in rdataToDomain(rdata, tipe) + [name]:
			if addMe not in related: foreign.add(addMe)
#	if foreign:
#		trace('foreign names:', ' '.join(foreign))

	# 1. Ask the same question to everyone, following delegations as needed.
	#    Less privacy, faster results, more conformity with existing practice.

	# There are empty recordsets, and there are empty recordsets.
	# What distinguishes are referrals and CNAMEs.
	haveNS, haveCNAME = False, False
	for name, tipe, ttl, rdata in a.Auths:
		if tipe == 2:
			haveNS = True
	for name, tipe, ttl, rdata in a.As:
		if tipe == 5:
			haveCNAME = True

	if a.aa:										# authoritative answer
		cacheOut(a.name, q.tipe)					# purge potential conflicts
		if a.rcode == 3:
			cacheIn(a.name, 65282, None, nsdTTL)	# NXDOMAIN yes
		else:
			if not (haveNS or haveCNAME):
				cacheIn(a.name, q.tipe, True, nsdTTL)	# recordset must exist
			cacheOut(a.name, 65282)					# NXDOMAIN no

	# Add what's here, whether or not authoritative.
	# TODO irrelevant information needs to be removed for security.
	for name, tipe, ttl, rdata in a.As + a.Auths + a.Addls:
		cacheIn(name, tipe, rdata, ttl)

	# Three kinds of progress need indicated.
	t.status = t.answered
	g.kickMe = True
	del asked[a.id]

