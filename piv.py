#!/usr/bin/python

from __future__ import division, print_function
from random import randrange

def pivot(a):
	p = a[randrange(0, len(a))]
	lo = 0
	hi = len(a) - 1
	print('pivoting on', p)
	for i in range(len(a)):
		while True:
			print(a)
			if a[i] < p:
				a[lo], a[i] = a[i], a[lo]
				lo += 1
			elif a[i] > p:
				a[hi], a[i] = a[i], a[hi]
				hi -= 1
			else:
				break
	print(a)
	return p

def test():
	a = [randrange(0,100) for i in range(10)]
	print('before', a)
	p = pivot(a)
	print('pivoted on', p, a)			
