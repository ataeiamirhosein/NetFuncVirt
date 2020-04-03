
from collections import Counter
from scapy.all import *
import time 
from datetime import datetime
from threading import Thread, Lock
import numpy as np
import csv
import os.path
from os import path


stats_1 = []
stats_2 = []

class MonitoringThread(Thread):
	def __init__(self, src, dst, iface):
		Thread.__init__(self)
		self.src = src
		self.dst = dst
		self.iface = iface
		print 'Ready to monitoring'


	def custom_action(self, packet):
		if "IP" in packet:
			timestamp_arrival = time.time()
			src = packet["IP"].src
			dst = packet["IP"].dst
			data = float(packet["Raw"].load)
			delay = timestamp_arrival - data
			print src, dst, delay


	def run(self):
		global stats_1
		global stats_2
		conf.L3socket = L3RawSocket
		sniff(filter="icmp", iface=self.iface, prn=self.custom_action)


thread1 = MonitoringThread("10.0.0.3", "10.0.0.2", "enp0s3")
thread1.start()
