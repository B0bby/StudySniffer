#!/usr/bin/env python
from __future__ import print_function, division
from scapy.all import *
import time
import json
import hashlib
import urllib2
import urllib

class StudySniffer():
	clientInfoDictStack[];

	def __init__(self):
		self.clients = []
		self.clientTypes = (0, 2, 4)
		self.initTime = time.time()

		self.COUNT_INTERVAL = 10
		self.DISCO_INTERVAL = 30
		self.INTERFACE = "mon0"
		self.SERVER = "192.168.1.1"
		self.LOCATION = "The Moon"
		self.DEVICE = "A computer"
		self.REMOTE_URL = "http://change.this.please.com/packets"

		self.loadConfig()

	def loadConfig(self):
		config = open("sniffer.conf", "r")
		for line in config:
			if (not "#" in line and ":" in line):
				option = line.split(":")[0].strip().lower()
				setting = line.split(":")[1].strip().lower()

				if option == "interface":
					self.INTERFACE = setting
				if option == "server":
					self.SERVER = setting
				if option == "location":
					self.LOCATION = setting
				if option == "device":
					self.DEVICE = setting
				if option == "disco_interval":
					self.DISCO_INTERVAL = setting
				if option == "count_interval":
					self.COUNT_INTERVAL = setting
				if option == "remote_url":
					self.REMOTE_URL = "http://" + setting

	def getInterface(self):
		return self.INTERFACE

	def isTimeForDissociate(self, clientTime):
		return time.time()-clientTime > self.DISCO_INTERVAL

	def noClientsInArray(self):
		return len(self.clients) == 0

	def isTimeToPrintStatistics(self):
		return time.time()-self.initTime > self.COUNT_INTERVAL

	def sniffWifi(self, packet):
		isUnique = True
		index = 0
		if (len(clientInfoDictStack) > 0):
			sendClientDataToServer();
		if (self.isTimeToPrintStatistics()):
			self.initTime = time.time()
		if packet.haslayer(Dot11):
			if packet.type == 0 and packet.subtype in self.clientTypes:
				if (self.noClientsInArray()):
					self.addClient(packet)
				for clientMac, clientSignal, clientTime  in self.clients:

					if (self.isTimeForDissociate(clientTime)):
						self.clients.pop(index)
						print(len(self.clients))
						if (index >= len(self.clients)):
							break
					if packet.addr2 == clientMac:
						isUnique = False
						self.clients[index][1]=clientSignal
						self.clients[index][2]=time.time()

					index = index + 1

				if (isUnique):
					self.addClient(packet)

	def addClient(self, packet):
		mac = packet.addr2
		signal = -(256-ord(packet.notdecoded[-4:-3]))
		originTime = time.time()
		self.clients.append([mac, signal, originTime])

		clientInfoDict = createClientInfoDict(mac, signal, originTime)

		clientInfoDictStack.append(clientInfoDict)
		self.logClientInfo(clientInfoDict)
		self.pushClientInfoToServer(clientInfoDict)
		self.printClientInfoToStdOut(mac, signal, originTime)

	def logClientInfo(self, clientInfoDict):
		# TODO: format should be changed to be more log friendly. 
		dictionaryOut = open("json-output.txt", "a")
		dictionaryOut.write(str(clientInfoDict))
		dictionaryOut.write("\n")
		dictionaryOut.close()

	def sendClientDataToServer(self):
		for x in range(0,len(clientInfoDictStack)):
			try:
				urllib2.urlopen(self.REMOTE_URL, urllib.urlencode(clientInfoDictStack[x]))
				clientInfoDictStack.pop(x)
			except:
				print("Couldn't contact server. Will re-attempt.")
				break

	def printClientInfoToStdOut(self, mac, signal, originTime):
		print(mac + "\t" + str(signal) + "dB" + "\t" + str(originTime))

	def createClientInfoDict(self, mac, signal, time):
		oui = mac[0:8]
		hashMac = hashlib.sha512(mac).hexdigest()
		clientInfoDict = {"id":hashMac, 
					  "oui":oui, 
					  "signal":signal, 
					  "time":time, 
					  "location":self.LOCATION, 
					  "device": self.DEVICE }
		return clientInfoDict


if __name__ == "__main__":
	sniffer = StudySniffer()
	sniff(iface=sniffer.getInterface(), prn=sniffer.sniffWifi, store=0)
