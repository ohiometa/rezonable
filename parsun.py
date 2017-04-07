#!/usr/bin/python2
# message parsing and assembly for Rezonable

from __future__ import division, print_function
from struct import pack, unpack

#import config as w
from tiny import *

__all__ = '''packBits parse rdataToDomain 
	setupPacket unpackBits unparse'''.split()

# field formats for resource records
# 1 = UINT1, 2 = uint2, 4 = uint4, C = char_string_255, D = domain_name,
# R = remainder_of_rec, M = catenated_char_strings, B = char_buf_65535
fFmts = {
	1:'4', 2:'D', 5:'D', 6:'DD44444', 11:'41R', 12:'D', 13:'CC', 15:'2D',
	16:'M', 41:'R'
}

# Break uint into unsigned bit fields.
# Both lists are ordered as [leastSigBits, ..., mostSigBits],
# so they are "backwards" in relation to the uint.
def unpackBits(u, widths):
	out = []
	for width in widths:
		out.append(u & (1 << width) - 1)
		u >>= width
	return out

# Combine unsigned bit fields into an unsigned int.
# Both lists are ordered as [leastSigBits, ..., mostSigBits],
# so they are "backwards" in relation to the returned uint.
def packBits(fields, widths):
	u = 0
	shift = 0
	for width, f in zip(widths, fields):
		f &= (1 << width) - 1		# clamp to range
		f <<= shift					# set in place
		u |= f						# combine
		shift += width				# next place
	return u

# Unpack a resource record or resource record-like buffer.
# The process is table-driven; see 'fFmts'.
# Note intern(), which I anticipate could save a lot of memory. XXX test?
# Although Malformed will be raised if the length and format do not
# agree, using the R field format can be used to strip prefixes.
def unpackRR(d, fmt, origD = None):
	out = []
	for f in fmt:
		l = len(d)
		if f == '1':
			if l < 1: raise Malformed('too short for uint8')
			out.append(ord(d[0]))
			d = d[1:]
		elif f == '2':
			if l < 2: raise Malformed('too short for uint16')
			a, d = unpack('!H', d[:2])[0], d[2:]
		elif f == '4':
			if l < 4: raise Malformed('too short for uint32')
			a, d = unpack('!L', d[:4])[0], d[4:]
		elif f == 'C':
			if l < 1: raise Malformed('too short for <character-string>')
			l_ = ord(d[0])
			if l < 1 + l_: raise Malformed('<character-string> is truncated')
			a, d = intern(d[1:1 + l_]), d[1 + l_:]
		elif f == 'B':
			if l < 2: raise Malformed('too short for <character-buf>')
			l_ = unpack('!H', d[:2])[0]
			if l < 2 + l_: raise Malformed('<character-buf> is truncated')
			a, d = intern(d[2:2 + l_]), d[2 + l_:]
		elif f == 'D':
			a, d = unpackDomain(d, origD)
			a = intern(a)
		elif f == 'M':					# allow >= 0 strs; RFC 1035 says >= 1
			a = []
			while d:
				s, d = unpackRR(d, 'C')
				a.append(s)
		elif f == 'R':
			a, d = d, ''
		else: raise Bug
		out.append(a)
	if d: raise Malformed('garbage at end')
	if len(out) is 1: out = out[0]		# convention for singletons
	return out

# Parses a <domain-name> from packet per RFC 1035, including decompression.
# Output format is now dotted; e.g., '.' (root zone), 'example.com.', etc.
# Returns <domain-name>, <remaining-d>.
def unpackDomain(d, origD, depth = 0):
	if depth > 5:
		raise Malformed('deep decompression')
	name = ''
	while True:
		if not d:
			raise Malformed('null label is missing')
		l = ord(d[0])
		if l > 63:
			# compressed record case - have fun!
			if origD is None: raise Malformed('no decompression reference')
			o, d = unpackRR(d, '2R')
			o &= 0x3ff
			more, ignored = unpackDomain(origD[o:], origD, 1 + depth)
			if name or not more: name += '.'
			name += more
			return name, d
		if len(d) < 1+l:
			raise Malformed('label is truncated')
		label, d = d[1:1+l].lower(), d[1+l:]
		if name or not label: name += '.'
		name += label
		if not l: break
	return name, d

# Parse an incoming packet. Raises Malformed if that happens
# XXX klass is unchecked and should be 1.
def parse(d, replyTo):
	h = AdHoc()						# header (and misc.) object for query
	oMsg = d						# preserve original message
	h.replyTo = replyTo				# who to respond to

	# id, various flags, # questions, # answers, # nameservers, # additional
	h.id, flags, h.nQ, h.nA, h.nAuth, h.nAddl, d = unpackRR(d, '222222R')

	# nobody of note supports multiple questions
	if h.nQ != 1: raise Malformed('got %i questions' % h.nQ)

	# unpack flags - see 4.1.1 in RFC 1035
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	# |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
	# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	#  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
	h.rcode, h.cd, h.ad, h.z, h.ra, h.rd, h.tc, h.aa, h.opcode, h.qr \
		= unpackBits(flags, (4, 1, 1, 1, 1, 1, 1, 1, 4, 1))

	# we don't support and won't answer inverse queries, etc.
	if h.opcode: raise Malformed

	h.As, h.Auths, h.Addls = [], [], []
	h.name, h.tipe, klass, d = unpackRR(d, 'D22R', oMsg)
	for a, n in zip \
			((h.As, h.Auths, h.Addls), (h.nA, h.nAuth, h.nAddl)):
		for i in range(n):
			name, tipe, klass, ttl, rdata, d = unpackRR(d, 'D224BR', oMsg)
			if tipe not in w.tipeWhiteList: continue		# filter
			rdata = unpackRR(rdata, fFmts.get(tipe, 'R'), oMsg)
			a.append((name, tipe, ttl, rdata))

	return h

# Set up a packet to send, but do not assemble it.
# In other words, return the same kind of object that parse() does.
# Everything in the created packet is 0 / empty except as specified by
# the caller. d1 overrides these defaults, and d2 overrides d1.
# They can either be a parse()-type object or a small dict.
def setupPacket(d1 = None, d2 = None):
	d = {}
	for n in 'id rcode cd ad z ra rd tc aa opcode qr nQ nA nAuth nAddl tipe' \
			.split():
		d[n] = 0
	for n in 'As Auths Addls'.split():
		d[n] = []
	d['replyTo'] = '127.0.0.1', 53
	d['name'] = ''
	for changes in d1, d2:
		if changes is None: continue
		if type(changes) is not dict:
			changes = changes.__dict__
		for k, v in changes.iteritems():
			if k.startswith('__'): continue
			if k not in d: continue			# much extra baggage around
			if type(v) is list: v = v[:]	# don't reference lists; copy them
			d[k] = v
	o = AdHoc()
	for k, v in d.iteritems():
		setattr(o, k, v)
	o.ad = 0								# XXX no DNSSEC authenticated data
	o.nQ = 1
	o.nA, o.nAuth, o.nAddl = map(len, (o.As, o.Auths, o.Addls))
	return o

# Assemble (unparse) a packet. For this to succeed, 'p' requires fields:
#   header section:  id rcode cd ad z ra rd aa opcode qr
#   everything else: name, tipe, As, Auths, Addls
def unparse(p):

	# Pseudo-header until we know the truncation outcome.
	d = 12 * ' '
	fitted = [0, 0, 0]	# count of As, Auths, Addls that fit

	# Append (name, tipe, klass) for question.
	more = compressDomain(p.name, d) + pack('!HH', p.tipe, 1)
	d += more
	truncTo = len(d)		# truncation granularity is a complete record

	# Append (name, tipe, klass, ttl, rdlength, rdata) for As, Auths, Addls
	for sect, section in enumerate([p.As, p.Auths, p.Addls]):
		for name, tipe, ttl, rdata in section:

			# Because a packet offset into the name might be helpful for
			# compressing the rdata, the record is appended in two portions.
			more = compressDomain(name, d) + pack('!HHL', tipe, 1, ttl)
			d += more

			# rdata is tricky and gets relegated.
			more = unparseRR(rdata, tipe, d)
			d += pack('!H', len(more)) + more
			if len(d) <= w.maxPacketLen:
				truncTo = len(d)
				fitted[sect] += 1

	# Truncate if this response is too long.
	if len(d) != truncTo:
		p.tc, d = 1, d[:truncTo]
	else: p.tc = 0

	# Pack up the flags. See chart in parse().
	fields = p.rcode, p.cd, p.ad, p.z, p.ra, p.rd, p.tc, p.aa, p.opcode, p.qr
	widths = 4, 1, 1, 1, 1, 1, 1, 1, 4, 1
	flags = packBits(fields, widths)

	# Insert the real header.
	p.nA, p.nAuth, p.nAddl = fitted
	d = pack('!HHHHHH', p.id, flags, 1, p.nA, p.nAuth, p.nAddl) + d[12:]
	return d

# Compress a domain. 'clique4.us.' becomes '\x07clique4\x02us\x00'.
def compressDomain(name, d):
	if type(name) is not str: raise Bug(name)
	if '..' in name or not name.endswith('.'): raise Bug(name)
	name = '\0' if name == '.' else \
			''.join(map(lambda x: chr(len(x)) + x, name.split('.')))

	# compression per 4.1.4. of RFC 1035
	oname = name
	comp = ''
	while name != '\0':							# this name can't compress
		o = d.find(name)						# look for name within d
		if o >= 0 and o <= 0x3fff:
			comp += pack('!H', 0xc000 + o)		# just point into d
			name = ''							# last '\0' is included
			break
		ll = ord(name[0])						# break off first label
		label, name = name[:ll+1], name[ll+1:]	# and use it as-is
		comp += label
	comp += name								# final '\0' if needed
	return comp

# Pack a resource record. Process is table-driven; see fFmts.
def unparseRR(rdata, tipe, d):
	print('UPRR', rdata, tipe)
	out = ''
	if type(rdata) is not list: rdata = [rdata]
	fmt = fFmts.get(tipe, 'R')

	for f, rd in zip(fmt, rdata):
		if f == '1':
			out += chr(rd)
		elif f == '2':
			out += pack('!H', rd)
		elif f == '4':
			out += pack('!L', rd)
		elif f == 'C':
			out += chr(len(rd)) + rd
		elif f == 'B':
			out += pack('!H', len(rd)) + rd
		elif f == 'D':
			out += compressDomain(rd, d)
		elif f == 'M':					# allow >= 0 strs; RFC 1035 says >= 1
			for s in rd:
				out += chr(len(s)) + s
		elif f == 'R':
			out += rd
		else: raise Bug
	return out

# Consistently extract "relevant" domain records from rdata.
# Always returns a list. Happens to be empty or singleton at present.
def rdataToDomain(rdata, tipe):
	l = []
	if tipe in (2, 5, 12): l.append(rdata)
	elif tipe == 6: l.append(rdata[0])
	elif tipe == 15: l.append(rdata[1])
	return l

