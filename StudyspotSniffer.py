#!/usr/bin/env python
from __future__ import print_function
from scapy.all import *
import time

class StudySniffer():

	def __init__(self):
		self.interface = "mon0"
		self.clients = []
		self.clientTypes = (0, 2, 4)

		self.initTime = time.time()
		self.COUNT_INTERVAL = 10
		self.DISCO_INTERVAL = 30

	def getInterface(self):
		return self.interface

	def sniffWifi(self, packet):
		isUnique = True
		index = 0
		if (time.time()-self.initTime > self.COUNT_INTERVAL):
			self.initTime = time.time()
			print("Client count: " + str(len(self.clients)))
		if packet.haslayer(Dot11):
			if packet.type == 0 and packet.subtype in self.clientTypes:
				if(len(self.clients) == 0):
					self.addClient(packet)
				for clientMac, clientSignal, clientTime  in self.clients:
					if (time.time()-clientTime > self.DISCO_INTERVAL):
						print("Disassociate: " + clientMac)
						self.clients.pop(index)
					if packet.addr2 == clientMac:
						isUnique = False
						self.clients[index][2]=time.time()
					index = index + 1
				if (isUnique):
					self.addClient(packet)

	def addClient(self, packet):
		mac = packet.addr2
		signal = -(256 - ord(packet.notdecoded[14]))
		originTime = time.time()
		self.clients.append([mac, signal, originTime])
		print(mac + "\t" + str(signal) + "dB" + "\t" + str(originTime))

if __name__ == "__main__":
	sniffer = StudySniffer()
	sniff(iface=sniffer.getInterface(), prn=sniffer.sniffWifi)	