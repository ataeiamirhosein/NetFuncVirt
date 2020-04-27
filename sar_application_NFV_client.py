from scapy.all import *
import time
from datetime import datetime
from threading import Thread

file1 = open('tosearch1.txt', 'r') 
my_list = file1.readlines() 



class MonitoringThread(Thread):
	
	def __init__(self, src, dst, iface):
		Thread.__init__(self)
		self.src = src
		self.dst = dst
		self.iface = iface
	
	def monitoring_app(self):
		for entry in my_list:
			# binary_address = entry.split(',')[1]
			data = entry# str(binary_address)
			# print (data)
			send(IP(dst=self.dst)/UDP(sport=1610,dport=1610)/data)
		
		# while 1:
			
		# 	input1 = input()
		# 	send(IP(dst=self.dst)/UDP(sport=1610,dport=1610)/str(input1))

	def run(self):
		self.monitoring_app()

thread2 = MonitoringThread("10.0.0.3", "10.0.0.2", "enp0s3")
thread2.start()