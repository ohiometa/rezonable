# #!/usr/bin/python2
# read /etc/hosts for Rezonable
# XXX This is a limited format. We can't do MX records, etc.

from __future__ import division, print_function
from os import stat
from time import gmtime, strftime

from cache import *
from tiny import *

__all__ = 'loadHosts parse_dotted_quad'.split()

lastTimeLoaded = 0					# avoid needless reloads

# Load from /etc/hosts if it might have changed.
# XXX We do not purge information on these hosts that came from other sources.
# XXX We do not create NS records that point to the Rezonable node.
def loadHosts():
	global lastTimeLoaded

	# Get modification time from /etc/hosts.
	try:
		mtime = int(stat(hostsFile).st_mtime)
		if mtime < lastTimeLoaded:
			return
		f = open(hostsFile).read()
	except:
		# Note if hosts cannot be read, no changes are made to cache.
		print('cannot stat or cannot read %s' % hostsFile)
		return

	# SOA nitpicking, because it's fun - XXX some fixed constants
	serial = int(strftime('%y%j%H%M', gmtime(mtime)))
	soaRR = [myHostName, myEmail, serial, 900, 900, 3600, 90]

	# remove anything that came from /etc/hosts from the cache
	for name in [name for name, d in g.cache.iteritems() if 65280 in d]:
		del g.cache[name]

	# add records from file
	f = f.lower().splitlines()
	for l in f:
		t = l.strip()
		if not t or t.startswith('#'): continue		# blank or comment
		t = t.split()
		if ':' in t[0]: continue					# ipv6 not implemented

		# check line syntax
		names = t[1:]
		a32 = parse_dotted_quad(t[0])
		ok = map(hostname_syntax_ok, names)
		if a32 is None or not all(ok):
			print('bad line in /etc/hosts:\n  ', end='')
			print(l)
			continue

		# domain names in cache end with '.'
		names = map(lambda x: x + '.', names)

		# add records to database
		if names:
			name = names[0]
			cacheIn(name, 1, a32, forever)			# A record
			cacheIn(name, 6, soaRR, forever)		# SOA record
			if name != myHostName:					# NS records
				cacheIn(name, 2, myHostName, forever)
			cacheIn(name, 255, None, forever)		# allow QTYPE = *
			cacheIn(name, 65280, None, forever)		# /etc/hosts origin
			cacheIn(name, 65281, None, forever)		# we are authoritative
		for alias in names[1:]:
			cacheIn(alias, 5, names[0], forever)
			cacheIn(alias, 255, None, forever)		# allow QTYPE = *
			cacheIn(alias, 65280, None, forever)	# /etc/hosts origin
			cacheIn(alias, 65281, None, forever)	# we are authoritative

	# we do not need to redo this for a while
	lastTimeLoaded = g.now

