#!/usr/bin/python

import socket		# for networking with sockets
import sys			# for exiting
import getopt		# for parsing command-line args
import random		# for creating the challenge string
import string		# for creating the challenge string
import hashlib		# for MD5 hash
import csv			# for parsing the password file

# Default host, port, filename, and debug mode
host = ''
port = 1234
filename = ''
debug = False

# ==================== Helper Methods =====================

# find_password will return the password corresponding to 'username'
# 		or 'INVALID_CREDENTIALS' if credentials are invalid
def find_password(username):
	if debug:
		print "Finding password for username '" + username + "'"
	for credential in credentials:
		if debug:
			print str(credential)
		if credential[0] == username:
			return credential[1]
	return "INVALID_CREDENTIALS"

# trim_argument will trim the argument from the untrimmed form
#		i.e. trim_argument('password=1234asdf', 'password') -> '1234asdf'
def trim_argument(untrimmed, name):
	# Find and validate '='
    pos_equals = untrimmed.find("=")
    if pos_equals == -1: return ''

    # Validate argument name
    argument_name = untrimmed[0:pos_equals]
    if name not in argument_name:
        return ''

	# Return argument after '='
    return untrimmed[pos_equals + 1:len(untrimmed)]

# ============= Parse Command-Line Arguments ==============

try:
    opts, args = getopt.getopt(sys.argv[1:], "hdp:f:", ["debug=", "port=", "file="])
except getopt.GetoptError:
    print 'Please specify a port (-p) and password file (-f). Use -d for debug printing.'
    sys.exit()
for opt, arg in opts:
	if opt == '-h':
		print 'Usage: ' + sys.argv[0] + ' -p <port> -f <password file>'
		sys.exit()
	elif opt in ("-d", "--debug"):
		debug = True
	elif opt in ("-p", "--port"):
		port = int(arg)
		if debug:
			print 'Port: ' + arg
	elif opt in ("-f", "--file"):
		filename = arg
		if debug:
			print 'Filename: ' + filename

# ========================================================

# ================= Parse Password File ==================

# Credentials are stored in the following format:
#         [[username1, password1],
#          [username2, password2],
#          [username3, password3],
#          ...]

password_file = open(filename)
reader = csv.reader(password_file)
credentials = list(reader)

# ========================================================

# ======== Create an INET, STREAMing socket (TCP) ========

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
	print 'Failed to create socket.'
	sys.exit()

if debug:
	print 'Socket created.'

# ========================================================

# =============== Bind the Socket and Host ===============

try:
	s.bind((host, port))
except socket.error, msg:
	print 'Bind failed. Error code: ' + str(msg[0]) + ' | Message: ' + msg[1]
	sys.exit()

if debug:
	print 'Socked bind complete.'

# ========================================================

# ================== Listen on the Port ==================

try:
	s.listen(port)
except socket.error, msg:
	print 'Socket listen failed.  Error code: ' + str(msg[0]) + ' | Message: ' + msg[1]
	sys.exit()

if debug:
	print 'Socket listening on port ' + str(port)

# ========================================================

# =========== Protocol Constants and Variables ===========

INVALID_AUTH_TO_CLIENT = 'HMMM... DISQUALIFIED'
VALID_AUTH_REQUEST_FROM_CLIENT = 'SHOW ME WHAT YOU GOT'
challenge = ''
username = 'asdf'
challenge_hash = ''

# ========================================================

# ========= Challenge Response Algorithm Methods =========

# receive_auth_request receives and verifies the auth request sent by
#		the client to begin the CRA authentication
# NOTE: Protocol here is for client to send "SHOW_ME_WHAT_YOU_GOT"
def receive_auth_request():
	auth_request = conn.recv(4096)

	# Verify the authentication request
	if auth_request != VALID_AUTH_REQUEST_FROM_CLIENT:
		# Client improperly requested auth -- send invalid auth message
		conn.sendall(INVALID_AUTH_TO_CLIENT)
		print 'Authentication failed for client' # TODO - Add client details

	if debug:
		print 'Received Authentication Request: ' + auth_request

# compute_and_send_challenge computes the 64-character random string and sends
#		it to the client
# NOTE: Protocol here is for server to send 'challenge=<64-character random string>'
def compute_and_send_challenge():
	challenge = 'challenge=' + ''.join(random.choice(string.ascii_uppercase + string.digits) for i in range(64))
	if debug:
		print 'Sending Challenge: ' + challenge
	try:
	    conn.sendall(challenge)
	except socket.error:
	    print 'Challenge failed to send.'
	    sys.exit()

# ========================================================

while 1:

	conn, addr = s.accept()
	if debug:
		print 'Connected with ' + addr[0] + ':' + str(addr[1])

	# ============= Challenge Response Algorithm =============

	# 1. Receive "Authentication Request" message.
	receive_auth_request()

	# 2. Compute and send challenge value (random 64-character string).
	compute_and_send_challenge()

	# 3. Receive username and hash from client.
	# NOTE: Protocol here is for client to send 'username=<username>&hash=<hash>'
	md5_hash = conn.recv(4096)

	# Split the message into arguments
	arguments = md5_hash.split('&')

	# TODO - Verify order of arguments

	# Validate and trim arguments
	trimmed_arguments = []
	expected_arguments = ['username', 'hash']
	for i in range(len(arguments)):
		trimmed_arguments.append(trim_argument(arguments[i], expected_arguments[i]))

	if debug:
		print 'trimmed_arguments: ' + str(trimmed_arguments)
		print 'len(arguments) = ' + str(len(arguments))

	if len(trimmed_arguments) == 2:
		username = trimmed_arguments[0]
		challenge_hash = trimmed_arguments[1]
		if debug:
			print 'Received Valid MD5 Hash: ' + md5_hash
			print 'username: ' + username
			print 'hash: ' + challenge_hash

	else:
		# Client sent invalid hash -- send invalid auth message
		conn.sendall(INVALID_AUTH_TO_CLIENT)

	# 4. Find password corresponding to username and perform same MD5 hash.

	if debug:
		print 'Finding password for username ' + username
	password = find_password(username)
	if debug:
		print 'Password: ' + password
	if password == "INVALID_CREDENTIALS":
		print 'Invalid credentials'
		# TODO - Send invalid notice to client -- how to restart CRA?
		# Client improperly requested auth -- send invalid auth message
		conn.sendall(INVALID_AUTH_TO_CLIENT)
 	else:
		md5 = hashlib.md5()
		md5.update(username)
		md5.update(password)
		md5.update(challenge)
		correct_hash = md5.hexdigest()

		# 5. Compare the two hashes. Send the appropriate message to client.

		if debug:
			print 'Comparing hashes -- ' + challenge_hash + ' vs ' + correct_hash
		if challenge_hash == correct_hash:
			# TODO - Process sensor recording and send the OK to the client
			conn.sendall('yay you did it')
			if debug:
				print 'Correct hash.'
		else:
			# Client improperly requested auth -- send invalid auth message
			conn.sendall(INVALID_AUTH_TO_CLIENT)
			if debug:
				print 'Incorrect hash.'

	# ========================================================

	# ============== Receiving the Sensor Data ===============

	# NOTE: Protocol here is for client to send 'recording=<recording>'
	sensor_data = conn.recv(4096)
	sensor_recording = trim_argument(sensor_data, 'recording')
	print 'sensor_recording: ' + sensor_recording

	conn.sendall('yo i got your sensor stuff')

	# ========================================================
