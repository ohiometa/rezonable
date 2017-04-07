# #!/usr/bin/python2
# the Rezonable cache
# use is about 1.2 kilobytes per key (50 website test)

from __future__ import division, print_function
from cPickle import load, dump
from gzip import open as gopen
from random import randrange

import config as w
from tiny import *

__all__ = '''cacheDump cacheSize createBootstrapZone getCache getCacheTTL loadCache purgeCache
saveCache setCache'''.split()

# (name, tipe) -> ([records], expire)
# First element can be an empty list.
# Second element can be None.
cache = {}

# Save cache to filesystem between runs.
def saveCache():
	try:
		f = gopen(w.persistFile, 'w')
		dump(cache, f, -1)
		dump(g.immortal, f, -1)
		f.close()
	except:
		msg('saveCache("%s") failed' % w.persistFile)

# Load cache from previous run. All or nothing.
def loadCache():
	global cache
	try:
		f = gopen(w.persistFile, 'r', 9)		# XXX can tweak level here
		hold = load(f)
		more = load(f)
		f.close()
	except:
		msg('loadCache("%s") failed' % w.persistFile)
		return
	cache, g.immortal = hold, more

# Store a recordset in the cache. Any old recordset is replaced.
# The recordset can be empty, NOT the same as not being in the cache.
# To force not even an empty recordset, use None for 'recs'.
# TTL is randomized within a permitted range and cached as an expire time.
# If 'ttl' is None, it will always retrieve as w.hostsTTL.
def setCache(name, tipe, recs = None, ttl = None):

	if recs is None:
		try: del cache[(name, tipe)]
		except: pass
		return

	if ttl is None:
		expire = None
	else:
		ttl = max(min(w.maxTTL, ttl), w.minTTL)
		ttl -= randrange(ttl // 4)
		expire = g.now + ttl

	cache[(name, tipe)] = recs, expire

	if tipe != 65282:							# XXX kludge; perf?
		try: del cache[(name, 65282)]			# domain exists if we have recs
		except KeyError: pass

# Retrieve a perhaps-empty recordset from the cache, or None if nothing.
def getCache(name, tipe):
	try:
		return cache[(name, tipe)][0]
	except:
		return None

# Same as getCache, but returns ([records], ttl) or (None, None).
# 'ttl' will always be a non-negative integer.
def getCacheTTL(name, tipe):
	try:
		recs, expire = cache[(name, tipe)]
	except:
		return None, None
	ttl = w.hostsTTL if expire is None else max(0, expire - g.now)
	return recs, ttl

# Create bootstrap zone. It can be overridden by persistFile.
def createBootstrapZone():
	rootAddrs =  map(parse_dotted_quad, w.rootServers.split())
	setCache('.', 2, [w.bsZone])
	setCache(w.bsZone, 1, rootAddrs)
	setCache(w.bsZone, 2, [w.myHostName])

	# XXX test NXDOMAIN queries; other NXDOMAIN support still absent
	setCache('not.here.', 65282, [])		# TODO rm

# Expunge expired records from cache.
# Immortal domains will have their A and NXDOMAIN records requeried.
def purgeCache():
	bye = []
	for (name, tipe), (recs, exp) in cache.iteritems():
		if exp is not None and g.now >= exp:
			bye.append((name, tipe))
			if name in g.immortal and tipe in (1, 65282):
				g.requery.append(name)
	for name_tipe in bye:
		del cache[name_tipe]

# diagnostic
def cacheSize():
	return len(cache)

# diagnostic
def cacheDump():

	# collect record count by domain name, and universe of tipes
	names, tipes, rTotal = set(), set(), 0
	for (name, tipe), (recs, exp) in cache.iteritems():
		tipes.add(tipe)
		names.add(name)
		rTotal += len(recs)

	tipes = list(tipes)
	tipes.sort()
	names = list(names)
	names.sort(key = domainSortKey)
	print('NAMES IN CACHE:')
	for n in names:
		print(n)
	print()
	print('tipe universe:', tipes)
	print('%i recs for %i names' % (rTotal, len(names)))

# key for sorting domains
def domainSortKey(name):
	name = name.split('.')
	name.reverse()
	return name
