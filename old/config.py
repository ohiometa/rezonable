# #!/usr/bin/python2
# Rezonable configuration settings

queryRepeats = 2			# lookups per server before query fails
queryTimeout = 10			# seconds before a lookup fails
hostsTTL = 75				# TTL for responses from /etc/hosts
minTTL = 6 * 3600			# quarter day
maxTTL = 168 * 3600			# week
nsdTTL = minTTL				# TTL for domain does not exist XXX
maxPacketLen = 4096			# XXX unsuitable for remote work; compression broken
bsZone = 'bootstrap.'		# name of bootstrap zone (careful: gets persisted)
myHostName = 'localhost.'	# NS record name for bootstrap and /etc/hosts
myEmail = 'rezonable.marcabel.com.'	# email address for server admin
tracing = True				# diagnostic
packetTracing = False		# diagnostic
requireUserPort = True		# drop all queries from ports < 1024 (DoS issue)
outgoingPort = 3553			# no randomization; keep sync'd with firewall
stubAddr = '8.8.8.8'		# where to send stub queries to

# list of permitted customers
customers = '192.168.1.112 65.28.224.117'.split()

# the system hosts file, and a file to hold our cache between runs
hostsFile = '/etc/hosts'
persistFile = '/var/tmp/rezonable-cache.pickle.gz'

# ignore all but these RR types
tipeWhiteList = [1, 2, 5]

# root server addresses
# retrieved March 9, 2017 from https://www.internic.net/zones/named.cache
rootServers = '''198.41.0.4 192.228.79.201 192.33.4.12 199.7.91.13
192.203.230.10 192.5.5.241 192.112.36.4 198.97.190.53 192.36.148.17
192.58.128.30 193.0.14.129 199.7.83.42 202.12.27.33'''
