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
namesLoaded = []					# what to delete, when necessary	# TODO not complete

# Load from /etc/hosts if it might have changed.
# Any names therein are at the mercy of this module.
def loadHosts():
	global lastTimeLoaded

	# Get modification time from /etc/hosts.
	try:
		mtime = int(stat(w.hostsFile).st_mtime)
		if mtime < lastTimeLoaded:
			return
		f = open(w.hostsFile).read()
	except:
		# Note if hosts cannot be read, no changes are made to cache.
		msg('cannot stat or cannot read %s' % w.hostsFile)
		return

	# SOA nitpicking, because it's fun - XXX some fixed constantsz
	serial = int(strftime('%y%j%H%M', gmtime(mtime)))
	soaRR = [w.myHostName, w.myEmail, serial, 900, 900, 3600, 90]

	# Remove anything mentioned in the last /etc/hosts load from the cache.
	for tipe in 1, 2, 5, 6:
		for name in namesLoaded:
			setCache((name, tipe))

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
			msg('bad line in /etc/hosts:\n  ', end='')
			msg(l)
			continue

		# domain names in cache end with '.'
		names = map(lambda x: x + '.', names)

		# add records for this host to database
		# XXX This doesn't handle multiple addresses for a name, e.g. rotor.
		if names:
			name = names[0]
			setCache(name, 1, [a32])		# A record
			if name != w.myHostName:		# NS records
				setCache(name, 2, [w.myHostName])
			setCache(name, 6, [soaRR])		# SOA record

		# add this host as the CNAME for any aliases given
		for alias in names[1:]:
			setCache(alias, 5, names[0:1])

	# we do not need to redo this for a while
	lastTimeLoaded = g.now

