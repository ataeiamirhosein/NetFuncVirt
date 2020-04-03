#!/usr/bin/python2

from scapy.all import *
import time 
from datetime import datetime
from threading import Thread


class MonitoringThread(Thread):
	def __init__(self, src, dst, tos, iface):
		Thread.__init__(self)
		self.src = src
		self.dst = dst
		self.tos = tos
		self.iface = iface
		self.max_number_pkts = 10		
		self.given_time = 1
		self.start_time=time.time()
		self.timestamp_origin = 0
		self.flag = 0

	def monitoring_app(self):
		while True:
			actual_time = int((time.time() - self.start_time) % 60.0)					
			if actual_time == self.given_time:
				print actual_time, self.given_time, self.iface
				if self.flag == 0:
					self.timestamp_origin = time.time()
					self.flag = 1					
				data = str(time.time())
				send(IP(src=self.src, dst=self.dst, tos=self.tos)/ICMP()/data) 

				self.given_time = self.given_time + 1
				if self.given_time == 60:
					self.given_time = 1


	def run(self):
		conf.L3socket = L3RawSocket
		self.monitoring_app()


thread2 = MonitoringThread("10.0.0.3", "10.0.0.2", 4, "enp0s3")
thread2.start()

