# #!/usr/bin/python2
# query processing for Rezonable

from __future__ import division, print_function

from cache import *
from dumper import *
from parsun import *
from tiny import *

__all__ = 'doQueryMaximal'.split()

"""
This might be a dated comment.

Here is our "what to include" logic. A = A, N = NS, C = CNAME.

Not shown in the table is the ANY (*) query tipe, which is going to need
a pseudo-tipe added to the class to indicate whether * has been queried
from the appropriate nameserver.

                 WANT
            A      N      C

   ...      1      1      1
   ..C      2      2      3
H  .N.      1      3      1
A  .NC      2      3      3
V  A..      3      1      1
E  A.C      3      1      3
   AN.      3      3      1
   ANC      3      3      3

1 locate the relevant nameserver and ask it
2 put CNAME in answer section, change name, continue lookup
3 return the requested record(s)

"""

# Answer a local user query using the cache alone.
# This generally follows query.py's recursive cache load.
def doQueryMaximal(q):

	# already guaranteed q.nQ is 1
	name, tipe = q.Qs[0]
	As, Auths, Addls, rcode, found = [], [], [], 0, False
	haveA, wantA = set(), set()			# glue record selection

	# CNAME resolution loop
	while True:

		d = g.cache.get(name)				# ever hear anything about this domain?
		if not d:
			rcode = 3
			break

		tipeSet = [tipe]				# provide for query tipe = *
		if tipe == 255:
			if 255 not in d:
				rcode = 3
				break
			else:
				tipeSet = [tipe for tipe in d if tipe >= 0 and tipe < 255]

		# loop through tipe(s) to collect, almost always just one
		for t in tipeSet:				# flags already excluded
			if t in d:
				ttl = getTTL(d, t)
				for rdata in d[t]:
					As.append((name, t, ttl, rdata))

					# collect domains for glue records
					if t == 1: haveA.add(name)
					for addMe in rdataToDomain(rdata, tipe):
						wantA.add(addMe)

				found = True
		if found: break

		# No recordsets (even empty) were found. Try to follow a CNAME.
		# Zones misconfigured with CNAME + tipe will not follow the CNAME.
		# Zones misconfigured with more than one CNAME will only follow one.
		if 5 in d and len(d[5]) > 0:
			ttl = getTTL(d, 5)
			firstCNAME = d[5][0]
			As.append((name, 5, ttl, firstCNAME))
			name = firstCNAME
			continue

		# No CNAME was available either.
		rcode = 3
		break

	# Try to indicate who the authoritative server is for this zone.
	qName, qTipe = q.Qs[0]

	# we like to know if we're authoritative
	aa, d = 0, g.cache.get(qName)
	if d:
		if 65281 in d:		# did we flag this zone as ours?
			aa = 1
			if 6 in d:		# can we send the SOA record? why not?
				for rdata in d[6]:
					ttl = getTTL(d, 6)
					Auths.append((name, 6, ttl, rdata))
					wantA.add(rdata[0])

		elif 2 in d and qTipe != 2:		# we know whose, but haven't said yet
			for rdata in d[2]:
				ttl = getTTL(d, 2)
				Auths.append((name, 2, ttl, rdata))
				wantA.add(rdata)

	if rcode == 3:						# XXX this is NXDOMAIN
		trace('nxdomain for', name, tipe)
	else:
		# we might have some glue (additional) records
		wantA -= haveA
		for name in wantA:
			d = g.cache.get(name)
			if not d: continue
			if 1 in d:
				ttl = getTTL(d, 1)
				for rdata in d[1]:
					Addls.append((name, 1, ttl, rdata))

	# create, unparse, and send a response
	parms = { 'qr':1, 'rcode':rcode, 'aa': aa, 'ra': 1,
		'As':As, 'Auths': Auths, 'Addls': Addls }
	r = setupPacket(q, parms)
	r = unparse(r)
	if packetTracing: print('response', repr(r))
	g.sock.sendto(r, q.replyTo)

	# if we could do all that, keep the record fresh forever
	if qTipe == 1:
		g.immortal.add(qName)

