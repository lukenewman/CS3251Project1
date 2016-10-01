#!/usr/bin/python

import socket		# for networking with sockets
import sys			# for exiting
import getopt		# for parsing command-line args
import random		# for creating the challenge string
import string		# for creating the challenge string
import hashlib		# for MD5 hash
import csv			# for parsing the password file
import datetime		# for time-stamping sensor data

# Default host, port, filename, and debug mode
host = ''
port = 1234
filename = ''
debug = False

# ==================== Helper Methods =====================

# find_password will return the password corresponding to 'username'
# 		or 'INVALID_CREDENTIALS' if credentials are invalid
def find_password(username):
	if debug: print "Finding password for username '" + username + "'"
	for credential in credentials:
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

# format_sensor_statistics takes in the sensor statistics received by the server,
#       extracts and trims the arguments and returns them in a formatted way
# NOTE: Protocol here is for server to send 'sensor=<username>&recorded=<recording>&
#		time=<time>&sensor_min=<sensor_min>&sensor_avg=<sensor_avg>&sensor_max=<sensor_max>
#		&all_avg=<all_avg>'
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

# user_auth_failed prints the failure message with client details on the server
#		side as well as telling the client that its authentication attempt failed
def user_auth_failed(client_metadata):
	client_address = client_metadata['client_address']
	# Client improperly requested auth -- send invalid auth message
	print 'User authentication failed for client: ' + str(client_address)
	s.sendto(INVALID_AUTH_TO_CLIENT, client_address)

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

# =================== Client Database ====================

# Client database holds a dictionary of metadata about communications with
# 		different clients. Client metadata is stored in the following format:
#		[ { 'client_address': <client address>,
#		    'challenge_sent': <challenge sent to client after auth request>,
#		    'challenge_response': <challenge hash received from client>,
#		    'username': <username pulled out of the challenge_response>,
#		    'challenge_hash': <hash pulled out of the challenge_response>,
#		},... ]

client_database = []

# Constant returned when a metadata key is not found
KEY_NOT_FOUND = 'KEY_NOT_FOUND'

# is_new_client takes in a client's address and determines if it is a new client or not
def is_new_client(new_address):
	potential_new_client = get_client(new_address)
	if not potential_new_client:
		return True
	return False

# get_client takes in a client address and returns the client's metadata if it
#		exists in the client database
def get_client(client_address):
	for metadata in client_database:
		if metadata['client_address'][0] == client_address[0] and metadata['client_address'][1] == client_address[1]:
			return metadata
	return {}

# create_new_client takes in a client address and creates new client metadata,
#		storing it in the database
def create_new_client(new_address):
	client_database.append({ 'client_address': new_address })
	return get_client(new_address)

# set_value takes in a key, value, and client address and stores the [key: value]
#		pair in the client's metadata
def set_value(key, value, client_address):
	client_metadata = get_client(client_address)
	client_metadata[key] = value

# set_challenge_sent sets in the client's metadata the challenge string it was sent
def set_challenge_sent(challenge_sent, client_address):
	set_value('challenge_sent', challenge_sent, client_address)

# get_challenge_sent returns the challenge string the client was sent
def get_challenge_sent(client_metadata):
	if 'challenge_sent' in client_metadata:
		return client_metadata['challenge_sent']
	else:
		return KEY_NOT_FOUND

# set_challenge_sent sets in the client's metadata the challenge response that was
#		sent by the client
def set_challenge_response(challenge_response, client_address):
	set_value('challenge_response', challenge_response, client_address)

# get_challenge_sent returns the challenge response the client sent
def get_challenge_response(client_metadata):
	if 'challenge_response' in client_metadata:
		return client_metadata['challenge_response']
	else:
		return KEY_NOT_FOUND

# set_challenge_sent sets in the client's metadata the username the client sent
def set_username(username, client_address):
	set_value('username', username, client_address)

# get_challenge_sent returns the username the client sent
def get_username(client_metadata):
	if 'username' in client_metadata:
		return client_metadata['username']
	else:
		return KEY_NOT_FOUND

# set_challenge_sent sets in the client's metadata the challenge hash the client sent
def set_challenge_hash(challenge_hash, client_address):
	set_value('challenge_hash', challenge_hash, client_address)

# get_challenge_sent returns the challenge hash the client sent
def get_challenge_hash(client_metadata):
	if 'challenge_hash' in client_metadata:
		return client_metadata['challenge_hash']
	else:
		return KEY_NOT_FOUND

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

# get_all_average returns the average of all sensor values recorded in the database
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

# ======== Create an INET, DATAGRAM socket (TCP) =========

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error:
	print 'Failed to create socket.'
	sys.exit()

# TODO: Figure out timeouts for the server side of things
# Set a timeout of 15 seconds
# s.settimeout(15.0)

if debug: print 'Socket created.'

# ========================================================

# =============== Bind the Socket and Host ===============

try:
	s.bind((host, port))
except socket.error, msg:
	print 'Bind failed. Error code: ' + str(msg[0]) + ' | Message: ' + msg[1]
	sys.exit()

if debug: print 'Socked bind complete.'

# ========================================================

# =========== Protocol Constants and Variables ===========

INVALID_AUTH_TO_CLIENT = 'HMMM... DISQUALIFIED'
VALID_AUTH_REQUEST_FROM_CLIENT = 'SHOW ME WHAT YOU GOT'
AUTH_SUCCESSFUL_MESSAGE = 'I LIKE WHAT YOU GOT. GOOD JOB.'

TIMEOUT_MESSAGE = 'Network timed out. Exiting.'

# ========================================================

# ===================== CRA Methods ======================

# compute_and_send_challenge takes in client_metadata, computes a 64-character
#		challenge string, sets the challenge_sent in the client's metadata,
#		and sends it to the client
def compute_and_send_challenge(client_metadata):
	if debug: print 'Beginning Challenge Response Authentication'

	challenge = ''.join(random.choice(string.ascii_uppercase + string.digits) for i in range(64))
	if debug: print 'Sending Challenge: ' + challenge

	# Get the client's address
	client_address = client_metadata['client_address']

	# Set the challenge in the client's metadata
	set_challenge_sent(challenge, client_address)

	# Send the challenge to the client
	# NOTE: Protocol here is for server to send 'challenge=<64-character random string>'
	try:
	    s.sendto('challenge=' + challenge, client_address)
	except socket.error:
	    print 'Challenge failed to send.'
	    sys.exit()

# is_valid_challenge_response returns True or False depending on if the
#		client_message is a valid challenge response hash
# NOTE: Protocol here is for client to send 'username=<username>&hash=<hash>'
def is_valid_challenge_response(client_message, client_metadata):
	# Split the message into arguments
	arguments = client_message.split('&')

	# Validate number of arguments (should be 2)
	if len(arguments) != 2:
		return False

	# Validate order of arguments (should be username, then hash)
	if 'username' not in arguments[0] or 'hash' not in arguments[1]:
 		return False

	# Trim arguments
	trimmed_arguments = []
	expected_arguments = ['username', 'hash']
	for i in range(len(arguments)):
		trimmed_arguments.append(trim_argument(arguments[i], expected_arguments[i]))

	if len(trimmed_arguments) == 2:
		client_address = client_metadata['client_address']

		# Set the username and challenge_hash
		username = trimmed_arguments[0]
		set_username(username, client_address)
		challenge_hash = trimmed_arguments[1]
		set_challenge_hash(challenge_hash, client_address)
		if debug: print 'Received MD5 Hash: ' + client_message
		return True
	else:
		return False

# compare_challenge_hashes takes in a client's metadata, computes the correct hash,
#		and compares it to the hash the client sent, sending the appropriate resposne
#		to the client
def compare_challenge_hashes(client_metadata):
	# Get client's username, challenge, and challenge_hash
	username = get_username(client_metadata)
	if username == KEY_NOT_FOUND:
		if debug: print 'Username not found.'
		user_auth_failed(client_metadata)
		return
	challenge_hash = get_challenge_hash(client_metadata)
	if challenge_hash == KEY_NOT_FOUND:
		if debug: print 'Challenge Hash not found.'
		user_auth_failed(client_metadata)
		return
	challenge = get_challenge_sent(client_metadata)
	if challenge == KEY_NOT_FOUND:
		if debug: print 'Challenge Sent not found.'
		user_auth_failed(client_metadata)
		return

	# Find password corresponding to username and perform same MD5 hash.
	password = find_password(username)
	if debug: print 'Password for ' + username + ' is ' + password + '.'
	if password == "INVALID_CREDENTIALS":
		user_auth_failed(client_metadata)
		return
 	else:
		md5 = hashlib.md5()
		md5.update(username)
		md5.update(password)
		md5.update(challenge)
		correct_hash = md5.hexdigest()

		# Compare the two hashes. Send the appropriate message to client.
		if debug: print 'Comparing hashes -- ' + challenge_hash + ' vs ' + correct_hash
		if challenge_hash == correct_hash:
			# Client properly requested auth -- send success message
			s.sendto(AUTH_SUCCESSFUL_MESSAGE, client_address)
			if debug: print 'Correct hash.'
		else:
			if debug: print 'Incorrect hash.'
			user_auth_failed(client_metadata)
			return

# is_valid_sensor_data takes in a client message and returns True if the message
#		is formatted properly for sensor data or False if it is not
def is_valid_sensor_data(client_message):
	# NOTE: Protocol here is for client to send 'recording=<recording>'
	# Split the message into arguments
	arguments = client_message.split('&')

	# Validate number of arguments (should be 1)
	if len(arguments) != 1:
		return False

	# Validate name of arguments (should be recording)
	if 'recording' not in arguments[0]:
 		return False

	return True

# incorporate_statistics takes in valid sensor_data and a client's metadata,
#		amends the server's sensor statistics database, and sends a summary response
#		to the client
def incorporate_statistics(sensor_data, client_metadata):
	sensor_recording = trim_argument(sensor_data, 'recording')
	if debug: print 'Received sensor recording: ' + sensor_recording

	username = get_username(client_metadata)
	if username == KEY_NOT_FOUND:
		if debug: print 'Username not found.'
		user_auth_failed(client_metadata)
		return

	# Incorporate sensor recording into "database."
	sensor_statistics = amend_statistics(username, sensor_recording)

	# Send statistics to client.
	# NOTE: Protocol here is for server to send 'sensor=<username>&recorded=<recording>&
	#		time=<time>&sensor_min=<sensor_min>&sensor_avg=<sensor_avg>&sensor_max=<sensor_max>
	#		&all_avg=<all_avg>'

	time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

	sensor_response = 'sensor=' + username + '&recorded=' + str(sensor_recording) + '&time=' + time + '&sensor_min=' + str(sensor_statistics['min']) + '&sensor_avg=' + str(sensor_statistics['avg']) + '&sensor_max=' + str(sensor_statistics['max']) + '&all_avg=' + str(sensor_statistics['all_avg'])

	client_address = client_metadata['client_address']
	s.sendto(sensor_response, client_address)

	print format_sensor_statistics(sensor_response)

# ========================================================

while 1:

	# Receive a message from a client and route it.
	client_message, client_address = s.recvfrom(2048)

	client = {}

	# Get the existing client metadata or create a new client's metadata
	if is_new_client(client_address):
		client = create_new_client(client_address)
		if client_message == VALID_AUTH_REQUEST_FROM_CLIENT:
			compute_and_send_challenge(client)
	else:
		client = get_client(client_address)

		# Perform the next step in the client's CRA
		if is_valid_challenge_response(client_message, client):
			compare_challenge_hashes(client)
		elif is_valid_sensor_data(client_message):
			incorporate_statistics(client_message, client)
		else:
			user_auth_failed(client)
			continue
