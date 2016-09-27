#!/usr/bin/python

from socket import *

serverPort = 12000
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(('', serverPort))
print("The server is ready to receive")
while True:
	message, clientAddress = serverSocket.recvfrom(2048)
	modifiedMessage = "Yeah, well " + message + " is a bitch."
	serverSocket.sendto(modifiedMessage.encode(), clientAddress)
