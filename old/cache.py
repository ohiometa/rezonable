# #!/usr/bin/python2
# the Rezonable cache

from __future__ import division, print_function
from cPickle import load, dump
from gzip import open as gopen
from random import randrange

from config import *
from tiny import *

"""
The Rezonable cache tries to be as lightweight a mechanism as Python
will permit. It is flexible, allowing any record type, and lightweight,
having less overhead than a class. A small example explains the semantics.

	# create a zone for clique4.us with A and NS records,
	# along with combined minimum TTLs (as expiration times)
	# for A and NS records.
	newDom = {}
	newDom[1] = [int('64.85.165.88')]
	newDom[-1] = g.now + 3600
	newDom[2] = ['ns35.domaincontrol.com', 'ns36.domaincontrol.com']
	newDom[-2] = g.now + 3600
	cache['clique4.us'] = newDom

If no query has been done for A records, there are no [1] or [-1] items
in the zone dict. On the other hand if these records were queried from an
authoratative nameserver but no records were returned [1] will be [] and
[-1] will be a suitable expiration time. So an authoratative empty response
will prevent other nameservers from being asked, which is what we want.

Even though "rules" like at most one CNAME exists for zones, the cache does
not try to enforce any rules. That way, the cache will not conceal any
qwirks or misconfigurations in ways that lead to unexpected behavior.
Detection of "cache anomalies" (that are not in fact _cache_ anomalies) is
at the option and responsibility of the code that queries the cache.

By convention, zone record elements always occur in +/- pairs with the
data and the expiration time. These keys must always be ints, so that no
runtime surprises occur. And as a hedge against future changes to the
codebase, existence of the pair is always tested by querying the + variant,
never the - variant. Continuing the above example:

	if 5 in newDom:

is sufficient to see if a CNAME query was made, and if there was one, there
is guaranteed to be a -5 element with the expiration time of that information.
Of course one needs to examine newDom[5] to see if there were in fact any
CNAMES.

In addition to query results, the cache must impute records for queries
that never happened. For instance, a CNAME response to an A query creates
a +5/-5 pair for the CNAME response. (If that zone is configured correctly,
the +1/-1 pair will show no A records were returned.) Likewise, +2/-2
pairs will be create for NS responses to A queries, or even authoratative
empty responses to NS queries (which mean that the host asked happens to
be the NS).

I would have preferred that newDom be an association list rather than a
dict, but the former is not built in to Python (unless it's in CPython's
implementation for dicts that haven't grown to a certain size).

TTLs in the cache are recorded as expiration times. They are converted back
to TTLs when we decide to output something.

tiny.py lists some special tipe values for flags, such as showing authority
or indicating the zone comes from /etc/hosts.

"""

# store cache between runs
def saveCache():
	try:
		f = gopen(persistFile, 'w')
		dump(g.cache, f, -1)
		dump(g.immortal, f, -1)
		f.close()
	except:
		print('saveCache("%s") failed' % persistFile)

# load cache from previous run (all or nothing)
def loadCache():
	try:
		f = gopen(persistFile, 'r', 9)		# XXX can tweak level here
		hold = load(f)
		more = load(f)
		f.close()
	except:
		print('loadCache("%s") failed' % persistFile)
		return
	g.cache, g.immortal = hold, more

# Create bootstrap zone. It can be overridden by persistFile.
def createBootstrapZone():
	cacheIn('.', 2, bsZone, forever)
	cacheIn(bsZone, 2, myHostName, forever)
	cacheIn(bsZone, 255, None, forever)		# allow QTYPE = * in bootstrap.
	for addr in map(parse_dotted_quad, rootServers.split()):
		cacheIn(bsZone, 1, addr, forever)

# Add a resource record to the cache.
def cacheIn(name, tipe, value, ttl):
	if type(ttl) is not int:
		raise Bug
	if ttl > 1000000000 and ttl != forever:
		raise Bug('cacheIn needs ttl, not expire time')

	# find or create the domain record
	d = g.cache.get(name)
	if d is None:
		g.cache[name] = d = {}

	# Compute the "full" and "short" expire times.
	# Forever means forever, but other times are clamped to a range.
	# The "short" time is randomly up to 25% off the long time.
	if ttl == forever:
		full = short = ttl
	else:
		ottl = ttl
		ttl = max(min(maxTTL, ttl), minTTL)
		sttl = ttl - randrange(ttl // 4)
		full, short = g.now + ttl, g.now + sttl

	# Find or create list of values, as well as expiration time.
	# We use the "short" time, which is randomized, the first time
	# we do this, which will clamp the entire set to that shortened
	# value. Usually that is what we want, because most TTLs for
	# a given record will be the same.
	vals = d.get(tipe)
	if not vals:				# first record? need a recordset for it
		d[tipe] = vals = []
		d[-tipe] = short

	# Add value to list, but prevent duplicates.
	# There is a pseudo-value ironically named True that permits empty
	# recordsets to be cached.
	if value is not True and value not in vals:
		vals.append(value)
	d[-tipe] = min(d[-tipe], full)

# ensure that resource records do not exist in the cache
def cacheOut(name, tipe):
	d = g.cache.get(name)
	if d and tipe in d: del d[tipe], d[-tipe]

# Expunge expired records and domains from cache.
def purgeCache():
	byebye = []
	for name, d in g.cache.iteritems():
		bye = []
		for key, expire in d.iteritems():
			if key >= 0: continue
			if g.now >= expire:
				bye.append(key)
				if key == -1 and name in g.immortal:
					g.requery.append(name)
		for key in bye:
			del d[key], d[-key]
		if not d:
			byebye.append(name)
	for name in byebye:
		del g.cache[name]

	if g.requery:
		g.kickMe = True

# compute TTL for a cache record
def getTTL(d, tipe):
	if tipe < 0 or tipe >= 65280 or -tipe not in d:
		raise Bug
	exp = d[-tipe]
	return hostsTTL if exp == forever else max(0, exp - g.now)

