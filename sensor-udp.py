#!/usr/bin/python

import getopt, sys, socket

serverAddress = ''
serverPort = 0

def main(argv):
	print("main")
	try:
	  opts, args = getopt.getopt(argv,"s:p:",[])
	except getopt.GetoptError:
	  print 'test.py -s <serverAddress> -p <serverPort>'
	  sys.exit(2)
	for opt, arg in opts:
	  if opt == '-h':
	     print 'test.py -s <serverAddress> -p <serverPort>'
	     sys.exit()
	  elif opt in ("-s"):
	     serverAddress = arg
	  elif opt in ("-p"):
	     serverPort = arg
	print 'Server address is "', serverAddress
	print 'Server port is "', serverPort

# clientSocket = socket(AF_INET, SOCK_DGRAM)
# message = raw_input('Who is your best friend? ')
# clientSocket.sendto(message.encode(), (serverAddress, serverPort))
# modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
# print(modifiedMessage.decode())
# clientSocket.close()
