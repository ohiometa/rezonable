# #!/usr/bin/python2
# tiny things we need around

from __future__ import division, print_function
from resource import getrusage, RUSAGE_SELF
from sys import stdout

import config as w

class AdHoc(object): pass
class Bug(Exception): pass
class Malformed(Exception): pass

g = AdHoc()				# global variables
g.flow = 0.				# current time as float
g.now = 0				# current time as int
g.loSock = None			# socket for port 53
g.hiSock = None			# socket for port 5353
g.cache = {}			# initial cache situation
g.immortal = set()		# names that need A records forever
g.requery = []			# list of names to requery
cache = now = flow = sock = Bug	# catch typos for a spell

# resource record type forward and reverse mappings
rrTypes = {
	1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 11:'WKS', 12:'PTR', 13:'HINFO', 
	15:'MX', 16:'TXT', 28:'AAAA', 41:'OPT', 252:'AXFR', 253:'MAILB', 255:'*',

	# IANA private use range is 65280-65534.
	65280:'loaded from /etc/hosts',
	65281:'this rezonable instance is authoritative for this zone',
	65282:'no such domain',
}
for k in list(rrTypes): rrTypes[rrTypes[k]] = k

# a marker in the year 4147 when /etc/hosts records "expire"
# (note the file gets a restat about every minute)
forever = 1 << 36

# make a dotted quad from a uint32
def dq(u):
	return '%i.%i.%i.%i' % tuple(u >> s & 0xff for s in (24, 16, 8, 0))

# parse a dotted quad into a uint32; malformed returns None
def parse_dotted_quad(q):
	q = q.split('.')
	if len(q) != 4: return
	if not all(map(lambda x: x.isdigit(), q)): return
	q = map(int, q)
	if not all(map(lambda x: x >= 0 and x <= 255, q)): return
	return q[0] << 24 | q[1] << 16 | q[2] << 8 | q[3]

# check hostname syntax
def hostname_syntax_ok(n):
	if len(n) > 255: return False
	n = n.lower()
	for c in n:
		if not c.isalnum() and c not in '.-': return False
	n = n.split('.')
	for label in n:
		if not label or len(label) > 63 or label.startswith('-') or \
				label.endswith('-') or '--' in label:
			return False
	return True

# Given a zone name, return its parent. Identity for root zone.
# TODO - as you can see, we didn't put the identity in, and
# it looks like cache expiration created a situation where we
# looked for the parent of root. Result: exception. TODO
def parentOfZone(z):
	if z == '.': return None
	z = z[1+z.index('.'):]
	return z if z else '.'

# diagnostics
def red(*_):
	if not w.tracing: return
	print('\x1b[1;31m', end='')
	print(*_)
	print('\x1b[m', end='')
	stdout.flush()

# diagnostics
def green(*_):
	if not w.tracing: return
	print('\x1b[1;32m', end='')
	print(*_)
	print('\x1b[m', end='')
	stdout.flush()

# diagnostics
def trace(*_):
	if not w.tracing: return
	print(*_)

# maximum size of this process, kb
def kilos():
	return getrusage(RUSAGE_SELF).ru_maxrss
