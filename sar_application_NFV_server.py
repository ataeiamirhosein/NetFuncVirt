from collections import Counter
from scapy.all import *
import time 
from datetime import datetime
from threading import Thread, Lock
import numpy as np
import csv
import os.path
from os import path
import BinaryNode
import MultibitNode
import timeit
times = []


binary_root = BinaryNode.Create("0")
multibit_root = MultibitNode.Create()

sum_time = 0
# 888888888888888888888888888888888888888888888888888888888888
class MonitoringThread(Thread):
	def __init__(self, src, dst, iface):
		Thread.__init__(self)
		self.src = src
		self.dst = dst
		self.iface = iface
		print 'Ready to monitoring'
		print '>>>>>>>>>>>>>>>>>>>'
		print '<<<<<<<<<<<<<<<<<<<'

# 8888888888888888888888888888888888888888888888888888888888888
	def convert_in_bin(self, address):
		return ''.join([bin(int(x)+256)[3:] for x in address.split('.')])
# 8888888888888888888888888888888888888888888888888888888888888
	def binary_lookup(self, packet):
		global sum_time

		# start = timeit.default_timer()
	
		if "IP" in packet:
			# timestamp_arrival = time.time()
			data = (packet["Raw"].load).split(',')[1]
			# print ("Lookup request received for : " + str(data))#src, dst, data
			#data1 = str(data)
			# print ("Longest prefix found, IP is = " + str(binary_root.Lookup(self.convert_in_bin(data), "0")))		
			start_time = time.time()
			binary_root.Lookup(self.convert_in_bin(data), "0")
			end_time = time.time()
			sum_time = sum_time + (end_time - start_time)
			print("--- %s Single Lookup ---" % (end_time - start_time))
			print("--- %s Sum of all Lookups ---" % sum_time)		
		# end = timeit.default_timer() - start
		# times.append(end * 1000)
		# print("binary_trie (avg per lookup): " + str(sum(times)/len(times)) + "	ms")
		# print("binary_trie (sum of all times): " + str(sum(times)) + "	ms")
		print ("=========================================================")
# 88888888888888888888888888888888888888888888888888888888888888888
	def multibit_lookup(self, packet):
		global sum_time
		# sum_time = 0
		# start = timeit.default_timer()

		
		# main()
		
		

		if "IP" in packet:
			# timestamp_arrival = time.time()
			data = (packet["Raw"].load).split(',')[1]			
			# print ("Lookup request received for : " + str(data))#src, dst, data
			#data1 = str(data)
			
			# print ("Longest prefix found, IP is = " + str(multibit_root.LookupNonRecursive(self.convert_in_bin(data), "0")))
		
			start_time = time.time()
			multibit_root.LookupNonRecursive(self.convert_in_bin(data), "0")
			end_time = time.time()
			sum_time = sum_time + (end_time - start_time)
			print("--- %s Single Lookup ---" % (end_time - start_time))
			print("--- %s Sum of all Lookups ---" % sum_time)	

		# end = timeit.default_timer() - start
		# times.append(end * 1000)
		# # print("multibit_trie (avg per lookup): " + str(sum(times)/len(times)) + "	ms")
		# # print("multibit_trie (sum of all times): " + str(sum(times)) + "	ms")
		print ("=========================================================")
# 888888888888888888888888888888888888888888888888888888888888888888888
	def run(self):
		print "Select \n 1- Binary lookup \n 2- Multibit lookup :"
		input_choose = input()
		print "Waiting for incoming request ..."
		if input_choose == 2:
			sniff(filter="udp", iface=self.iface, prn=self.multibit_lookup)
		if input_choose == 1:
			sniff(filter="udp", iface=self.iface, prn=self.binary_lookup)
# 888888888888888888888888888888888888888888888888888888888888888888888
thread1 = MonitoringThread("10.0.0.3", "10.0.0.2", "enp0s3")
thread1.start()