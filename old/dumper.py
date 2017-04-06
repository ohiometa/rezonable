#!/usr/bin/python2
# Diagnostic formatting of already-parsed DNS packets for rezonable.

from __future__ import division, print_function
from sys import stdout

from cache import *
from tiny import *

__all__ = 'dumpCache dumpPacket'.split()

def dumpCache():
	page = ['CACHE:']
	names = list(g.cache)
	names.sort(key = domainSortKey)
	for name in names:
		d = g.cache[name]
		tipes = list(d)
		tipes = [t for t in tipes if t >= 0 and t < 65280]
		tipes.sort()
		for t in tipes:
			ttl = getTTL(d, t)
			for rec in d[t]:
				if t == 1: rec = dq(rec)
				page.append('%s\t%s\t%s\t%s' % \
						(name, rrTypes.get(t, '?'), ttl, rec))
	page.append('')
	printWithTabs(page)

def dumpPacket(h):
	# list of lines to print after calculating tabs
	if not packetTracing: return
	r = ['RESPONSE:' if h.qr else 'QUERY:']
	l = '  id=%i (%04x) from=%s' % (h.id, h.id, h.replyTo[0])
	r.append(l)
	t = []
	t.append('  opcode=%i' % h.opcode)
	t.append('rcode=%i' % h.rcode)
	if h.qr: t.append('qr')
	if h.aa: t.append('aa')
	if h.tc: t.append('tc')
	if h.rd: t.append('rd')
	if h.ra: t.append('ra')
	if h.z: t.append('z')
	if h.ad: t.append('ad')
	if h.cd: t.append('cd')
	r.append(' '.join(t))

	r.append('QUESTION SECTION:')
	for name, tipe in h.Qs:
		tipe = rrTypes.get(tipe, '?')
		r.append('%s\t%s' % (name, tipe))

	for k, a in \
			[('ANSWER', h.As), ('AUTHORITY', h.Auths), ('ADDITIONAL', h.Addls)]:
		r.append(k + ' SECTION:')
		for rr in a:
			r.append(rrFormat(rr))

	r.append('')
	print('\x1b[32m', end='')
	printWithTabs(r)
	print('\x1b[m', end='')
	stdout.flush()

# format a resource record for human consumption
def rrFormat(rr):
	name, tipe, ttl, rdata = rr
	if tipe == 1: rdata = dq(rdata)		# A record formatting
	if tipe == 28: rdata = '(ipv6)'		# AAAA
	if type(rdata) is not list:
		rdata = [rdata]
	rdata = ' '.join(map(str, rdata))
	tipe = rrTypes.get(tipe, '?')
	return '%s\t%s\t%i\t%s' % (name, tipe, ttl, rdata)

# nicely print a list of lines that contain tabs
def printWithTabs(page, sep = 3):
	ts = 16 * [0]		# max 16 columns

	# get width of each column
	for l in page:
		if '\t' not in l: continue
		for i, col in enumerate(l.split('\t')):
			ts[i] = max(ts[i], len(col))

	# print us out
	for l in page:
		if '\t' not in l:
			print(l)
			continue
		line = ''
		for i, col in enumerate(l.split('\t')):
			line += col + ' ' * (ts[i] - len(col) + sep)
		print(line.rstrip())

# key for sorting domains
def domainSortKey(name):
	name = name.split('.')
	name.reverse()
	return name
