#!/usr/bin/python

import socket		# for networking with sockets
import sys			# for exiting
import getopt		# for parsing command-line args
import random		# for creating the challenge string
import string		# for creating the challenge string
import hashlib		# for MD5 hash
import csv			# for parsing the password file

# Default host, port, and filename
host = ''
port = 12000
filename = ''

# ============= Parse Command-Line Arguments ==============

try:
    opts, args = getopt.getopt(sys.argv[1:],"hp:f:",["port=", "file="])
except getopt.GetoptError:
    print 'Please specify a port (-p) and password file (-f).'
    sys.exit()
for opt, arg in opts:
    if opt == '-h':
        print 'Usage: ' + sys.argv[0] + ' -p <port> -f <password file>'
        sys.exit()
    elif opt in ("-p", "--port"):
        port = int(arg)
        # print 'Port: ' + arg
    elif opt in ("-f", "--file"):
        filename = arg
        # print 'Filename: ' + filename

# ================= Parse Password File ==================

password_file = open(filename)
reader = csv.reader(password_file)
credentials = list(reader)
# credentials are stored in the following format:
#         [[username1, password1],
#          [username2, password2],
#          [username3, password3],
#          ...]

# find_password will return the password corresponding to 'username'
# 		or 'INVALID_CREDENTIALS' if credentials are invalid
def find_password(username):
	for credential in credentials:
		if credential[0] == username:
			return credential[1]
	return "INVALID_CREDENTIALS"

# ======== Create an INET, STREAMing socket (TCP) ========

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
	print 'Failed to create socket.'
	sys.exit()

print 'Socket created.'

# =============== Bind the socket and host ===============

try:
	s.bind((host, port))
except socket.error, msg:
	print 'Bind failed. Error code: ' + str(msg[0]) + ' | Message: ' + msg[1]
	sys.exit()

print 'Socked bind complete.'

# ================== Listen on the port ==================

try:
	s.listen(port)
except socket.error, msg:
	print 'Socket listen failed.  Error code: ' + str(msg[0]) + ' | Message: ' + msg[1]
	sys.exit()

print 'Socket listening on port ' + str(port)

while 1:

	conn, addr = s.accept()
	print 'Connected with ' + addr[0] + ':' + str(addr[1])

	# ============= Challenge Response Algorithm =============

	# 1. Receive "Authentication Request" message.

	auth_request = conn.recv(1024)
	print 'Received Authentication Request: ' + auth_request

	# 2. Compute and send challenge value (random 64-character string).

	challenge = ''.join(random.choice(string.ascii_uppercase + string.digits) for i in range(64))
	try:
	    conn.sendall(challenge)
	except socket.error:
	    print 'Challenge failed to send.'
	    sys.exit()

	# 3. Receive username and hash from client.

	md5_hash = conn.recv(1024)
	# TODO - Pull out username from md5_hash
	username = ''
	print 'Received MD5 hash: ' + md5_hash

	# 4. Find password corresponding to username and perform same MD5 hash. Compare the two hashes.

	password = find_password(username)
	if password == "INVALID_CREDENTIALS":
		# TODO - Send invalid notice to client -- how to restart CRA?
 	else:
		md5 = hashlib.md5()
		md5.update(username)
		md5.update(password)
		md5.update(challenge)
		correct_hash = md5.digest()

		# 5. Send appropriate authentication message.

		if md5_hash == correct_hash:
			print 'Correct hash. Sending authentication.'
			# TODO - Send authentication
		else:
			print 'Incorrect hash. Sending error.'
			# TODO - Send non-authentication
