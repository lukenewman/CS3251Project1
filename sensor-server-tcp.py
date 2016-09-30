#!/usr/bin/python

import socket		# for networking with sockets
import sys			# for exiting
import getopt		# for parsing command-line args
import random		# for creating the challenge string
import string		# for creating the challenge string
import hashlib		# for MD5 hash
import csv			# for parsing the password file
import datetime     # for time-stamping sensor data

# Default host, port, filename, and debug mode
host = ''
port = 1234
filename = ''
debug = False

# ==================== Helper Methods =====================

# find_password will return the password corresponding to 'username'
# 		or 'INVALID_USERNAME' if username doesn't exist
def find_password(username):
	if debug:
		print "Finding password for username '" + username + "'"
	for credential in credentials:
		if credential[0] == username:
			return credential[1]
	return "INVALID_USERNAME"

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

def format_sensor_statistics(sensor_statistics):
    arguments = sensor_statistics.split('&')
    trimmed_arguments = []
    expected_arguments = ['sensor', 'recorded', 'time', 'sensor_min', 'sensor_avg', 'sensor_max', 'all_avg']
    for i in range(len(arguments)):
        trimmed_arguments.append(trim_argument(arguments[i], expected_arguments[i]))

    output = 'Sensor: ' + trimmed_arguments[0]
    output += ' recorded: ' + trimmed_arguments[1]
    output += ' time: ' + trimmed_arguments[2]
    output += ' sensorMin: ' + trimmed_arguments[3]
    output += ' sensorAvg: ' + trimmed_arguments[4]
    output += ' sensorMax: ' + trimmed_arguments[5]
    output += ' allAvg: ' + trimmed_arguments[6]

    return output

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
		try:
			port = int(arg)
		except ValueError:
			print 'Invalid port. Exiting.'
			sys.exit()
	elif opt in ("-f", "--file"):
		filename = arg

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

# =================== Sensor Database ====================

# Sensor information is stored in the following format:
#		{ 'username1': [ x, y, z... ],
#		  'username2': [ x, y, z... ],
#		  'username3': [ x, y, z... ],
#		  ...}

sensor_database = {}
for sensor in credentials:
	stats = []
	sensor_database[sensor[0]] = stats

# amend_statistics takes a sensor name and a new value and returns the new
#		statistics (min, avg, max) of the sensor in the format: { 'min': x,
#		'avg': y, 'max': z, 'all_avg': w } (note that this also includes the
#		average of every sensor's recordings)
def amend_statistics(sensor_name, new_value):
	sensor = sensor_database[sensor_name]
	sensor.append(float(new_value))
	min_stat = min(sensor)
	avg_stat = reduce(lambda x, y: x + y, sensor) / len(sensor)
	max_stat = max(sensor)
	return { 'min': min_stat, 'avg': avg_stat, 'max': max_stat,
			 'all_avg': get_all_average() }

def get_all_average():
	count = 0
	total = 0
	for sensor in credentials:
		sensor_name = sensor[0]
		sensor_values = sensor_database[sensor_name]
		count += sum(sensor_values)
		total += len(sensor_values)
	return count / total

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
AUTH_SUCCESSFUL_MESSAGE = 'I LIKE WHAT YOU GOT. GOOD JOB.'

challenge = ''
username = ''
challenge_hash = ''

# ========================================================

# ========= Challenge Response Algorithm Methods =========

if debug:
	print 'Beginning Challenge Response Authentication'

# ========================================================

while 1:

	conn, addr = s.accept()
	if debug:
		print 'Connected with ' + addr[0] + ':' + str(addr[1])

	# ============= Challenge Response Algorithm =============

	# 1. Receive "Authentication Request" message.
	# NOTE: Protocol here is for client to send "SHOW_ME_WHAT_YOU_GOT"
	auth_request = conn.recv(4096)

	# Verify the authentication request
	if auth_request != VALID_AUTH_REQUEST_FROM_CLIENT:
		# Client improperly requested auth
		print 'User authentication failed for client: ' + str(addr) + ' username: ' + username
		conn.sendall(INVALID_AUTH_TO_CLIENT)

	if debug:
		print 'Received Authentication Request: ' + auth_request

	# 2. Compute and send challenge value (random 64-character string).
	# NOTE: Protocol here is for server to send 'challenge=<64-character random string>'
	challenge = 'challenge=' + ''.join(random.choice(string.ascii_uppercase + string.digits) for i in range(64))
	if debug:
		print 'Sending Challenge: ' + challenge
	try:
	    conn.sendall(challenge)
	except socket.error:
	    print 'Challenge failed to send.'
	    sys.exit()

	# 3. Receive username and hash from client.
	# NOTE: Protocol here is for client to send 'username=<username>&hash=<hash>'
	md5_hash = conn.recv(4096)

	# Split the message into arguments
	arguments = md5_hash.split('&')

	# Validate number of arguments
	if len(arguments) != 2:
		# Client sent invalid MD5 hash
		print 'User authentication failed for client: ' + str(addr) + ' username: ' + username
		conn.sendall(INVALID_AUTH_TO_CLIENT)

	# Validate order of arguments
	if 'username' not in arguments[0] or 'hash' not in arguments[1]:
		# Client sent wrong order of arguments
		print 'User authentication failed for client: ' + str(addr) + ' username: ' + username
		conn.sendall(INVALID_AUTH_TO_CLIENT)

	# Trim arguments
	trimmed_arguments = []
	expected_arguments = ['username', 'hash']
	for i in range(len(arguments)):
		trimmed_arguments.append(trim_argument(arguments[i], expected_arguments[i]))

	if len(trimmed_arguments) == 2:
		username = trimmed_arguments[0]
		challenge_hash = trimmed_arguments[1]
		if debug:
			print 'Received Valid MD5 Hash: ' + md5_hash
	else:
		# Client sent invalid hash -- send invalid auth message
		print 'User authentication failed for client: ' + str(addr) + ' username: ' + username
		conn.sendall(INVALID_AUTH_TO_CLIENT)
		continue

	# 4. Find password corresponding to username and perform same MD5 hash.
	password = find_password(username)
	if debug:
		print 'Password for ' + username + ' is ' + password + '.'
	if password == "INVALID_USERNAME":
		print 'User authentication failed for client: ' + str(addr) + ' username: ' + username
		# Client improperly requested auth -- send invalid auth message
		conn.sendall(INVALID_AUTH_TO_CLIENT)
		continue
 	else:
		md5 = hashlib.md5()
		md5.update(username)
		md5.update(password)
		md5.update(challenge)
		correct_hash = md5.hexdigest()

		# 5. Compare the two hashes. Send the appropriate message to client.
		if challenge_hash == correct_hash:
			# Client properly requested auth -- send success message
			conn.sendall(AUTH_SUCCESSFUL_MESSAGE)
			if debug:
				print 'Correct hash.'
		else:
			# Client improperly requested auth -- send failure message
			conn.sendall(INVALID_AUTH_TO_CLIENT)
			print 'User authentication failed for client: ' + str(addr) + ' username: ' + username
			continue

	# ========================================================

	# ============== Receiving the Sensor Data ===============

	# NOTE: Protocol here is for client to send 'recording=<recording>'
	sensor_data = conn.recv(4096)
	sensor_recording = trim_argument(sensor_data, 'recording')
	if debug:
		print 'sensor_recording: ' + sensor_recording

	# ========================================================

	# ====== Processing & Returning Sensor Statistics ========

	# Incorporate sensor recording into "database."
	sensor_statistics = amend_statistics(username, sensor_recording)

	# Send statistics to client.
	# NOTE: Protocol here is for server to send 'sensor=<username>&recorded=<recording>&
	#		time=<time>&sensor_min=<sensor_min>&sensor_avg=<sensor_avg>&sensor_max=<sensor_max>
	#		&all_avg=<all_avg>'

	# Create the timestamp
	time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

	sensor_response = 'sensor=' + username + '&recorded=' + str(sensor_recording) + '&time=' + time + '&sensor_min=' + str(sensor_statistics['min']) + '&sensor_avg=' + str(sensor_statistics['avg']) + '&sensor_max=' + str(sensor_statistics['max']) + '&all_avg=' + str(sensor_statistics['all_avg'])

	conn.sendall(sensor_response)

	print format_sensor_statistics(sensor_response)

	# ========================================================
