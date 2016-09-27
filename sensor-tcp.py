#!/usr/bin/python

import socket		# for networking with sockets
import sys			# for exiting
import getopt		# for parsing command-line args
import hashlib		# for MD5 hash

# Default server, port, username, password, and sensor recording
server = ''
port = 80
username = 'lukenewman'
password = 'password'
recording = 0.0

# ============= Parse Command-Line Arguments ==============

try:
    opts, args = getopt.getopt(sys.argv[1:],"hs:p:u:c:r:",["server=", "port=", "username=", "password=", "recording="])
except getopt.GetoptError:
    print 'Please specify a server (-s), port (-p), username (-u), password (-c), and sensor recording (-r).'
    sys.exit()
for opt, arg in opts:
    if opt == '-h':
        print 'usage: ' + sys.argv[0] + ' -s <server> -p <port> -u <username> -c <password> -r <sensor recording>'
        sys.exit()
    elif opt in ("-s", "--server"):
        server = arg
        # print 'Server: ' + server
    elif opt in ("-p", "--port"):
        port = int(arg)
        # print 'Port: ' + arg
    elif opt in ("-u", "--username"):
        username = arg
        # print 'Username: ' + username
    elif opt in ("-c", "--password"):
        password = arg
        # print 'Password: ' + password
    elif opt in ("-r", "--recording"):
        recording = float(arg)
        # print 'Recording: ' + arg

# ======== Create an INET, STREAMing socket (TCP) ========

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
    print 'Failed to create socket.'
    sys.exit()

print 'Socket created.'

# ================== Connect to Server ===================

try:
    s.connect((server, port))
except socket.error, msg:
    print 'Failed to connect to ' + server + ':' + str(port) + '. (Error code: ' + str(msg[0]) + ' | Message: ' + msg[1] + ')'
    sys.exit()

print 'Socket connected to ' + server + ':' + str(port)

# ============= Challenge Response Algorithm =============

# 1. Send "Authentication Request" message.

try:
    s.sendall("yo")
except socket.error:
    print 'Authentication Request failed to send.'
    sys.exit()

# 2. Receive challenge value (random 64-character string).

challenge = s.recv(4096)
print 'Challenge received: ' + challenge

# 3. Compute MD5 hash (username, password, challenge)

md5 = hashlib.md5()
md5.update(username)
md5.update(password)
md5.update(challenge)
md5_hash = md5.digest()

# 4. Send clear text username and hash.

# TODO - Determine protocol for this data (how the server will extract username and hash from data)

try:
    s.sendall(md5_hash)
except socket.error:
    print 'MD5 Hash failed to send.'
    sys.exit()

# 5. Receive authentication results.
