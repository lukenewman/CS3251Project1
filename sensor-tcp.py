#!/usr/bin/python

import socket		# for networking with sockets
import sys			# for exiting
import getopt		# for parsing command-line args
import hashlib		# for MD5 hash

# Default server, port, username, password, and sensor recording
server = '172.17.0.2'
port = 1235
username = 'username1'
password = 'password1'
recording = 50.0
debug = False

# ==================== Helper Methods =====================

# parse_argument will trim the argument from the untrimmed form
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

# ========================================================

# ============= Parse Command-Line Arguments ==============

try:
    opts, args = getopt.getopt(sys.argv[1:],"hds:p:u:c:r:",["server=", "port=", "username=", "password=", "recording=", "debug="])
except getopt.GetoptError:
    print 'Please specify a server (-s), port (-p), username (-u), password (-c), and sensor recording (-r). Use -d for debug printing.'
    sys.exit()
for opt, arg in opts:
    if opt == '-h':
        print 'Usage: ' + sys.argv[0] + ' -s <server> -p <port> -u <username> -c <password> -r <sensor recording>'
        sys.exit()
    elif opt in ("-d", "--debug"):
        debug = True
    elif opt in ("-s", "--server"):
        server = arg
        try:
            socket.inet_aton(arg)
        except socket.error:
            print 'Invalid server address. Exiting.'
            sys.exit()
    elif opt in ("-p", "--port"):
        try:
            port = int(arg)
        except ValueError:
            print 'Invalid port. Exiting.'
            sys.exit()
    elif opt in ("-u", "--username"):
        username = arg
    elif opt in ("-c", "--password"):
        password = arg
    elif opt in ("-r", "--recording"):
        try:
            recording = float(arg)
        except ValueError:
            print 'Invalid recording. Exiting.'
            sys.exit()

# ========================================================

# ======== Create an INET, STREAMing socket (TCP) ========

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
    print 'Failed to create socket.'
    sys.exit()

if debug: print 'Socket created.'

# ========================================================

# ================== Connect to Server ===================

try:
    s.connect((server, port))
except socket.error, msg:
    print 'Failed to connect to ' + server + ':' + str(port) + '. (Error code: ' + str(msg[0]) + ' | Message: ' + msg[1] + ')'
    sys.exit()

if debug: print 'Socket connected to ' + server + ':' + str(port)

# ========================================================

# =========== Protocol Constants and Variables ===========

INVALID_AUTH_RESPONSE_FROM_SERVER = 'HMMM... DISQUALIFIED'
AUTH_REQUEST_FOR_SERVER = 'SHOW ME WHAT YOU GOT'
AUTH_SUCCESSFUL_MESSAGE = 'I LIKE WHAT YOU GOT. GOOD JOB.'

FAILURE_MESSAGE = 'User authentication failed!'

challenge_message = ''
challenge = ''

# ========================================================

# ============= Challenge Response Algorithm =============

if debug: print 'Beginning Challenge Response Authentication'

# 1. Send authentication request.
if debug: print 'Sending authentication request.'

# NOTE: Protocol here is for client to send "SHOW_ME_WHAT_YOU_GOT"
try:
    s.sendall(AUTH_REQUEST_FOR_SERVER)
except socket.error:
    print 'Authentication Request failed to send.'
    sys.exit()

# 2. Receive challenge.
# NOTE: Protocol here is for server to send 'challenge=<64-character random string>'
challenge_message = s.recv(4096)

# Check for invalid authentication message and exit if necessary.
if challenge_message == INVALID_AUTH_RESPONSE_FROM_SERVER:
    print FAILURE_MESSAGE
    sys.exit()

# Check for invalid challenge message.
if 'challenge' not in challenge_message:
    print 'Invalid challenge received. Exiting.'
    sys.exit()

# Extract the challenge string from the message.
challenge = trim_argument(challenge_message, 'challenge')

# Check for invalid challenge.
if len(challenge) != 64:
    print 'Invalid challenge received. Exiting.'
    sys.exit()

if debug: print 'Challenge received: ' + challenge

# 3. Compute and send challenge response.
md5 = hashlib.md5()
md5.update(username)
md5.update(password)
md5.update(challenge)
md5_hash = md5.hexdigest()

challenge_response = 'username=' + username + '&hash=' + md5_hash

if debug: print 'Challenge response: ' + challenge_response

# NOTE: Protocol here is for client to send 'username=<username>&hash=<hash>'
try:
    s.sendall(challenge_response)
except socket.error:
    print 'Challenge Response failed to send.'
    sys.exit()

# 4. Receive authentication results.
auth_results = s.recv(4096)

# Alert user of auth results.
if auth_results == INVALID_AUTH_RESPONSE_FROM_SERVER:
    print FAILURE_MESSAGE
    sys.exit()
elif auth_results == AUTH_SUCCESSFUL_MESSAGE:
    if debug: print 'User authentication succeeded!'

# ========================================================

# =============== Sending the Sensor Data ================

if debug: print 'Sending sensor data.'

# NOTE: Protocol here is for client to send 'recording=<recording>'
sensor_data = 'recording=' + str(recording)
try:
    s.sendall(sensor_data)
except socket.error:
    print 'Sensor data failed to send.'
    sys.exit()

# NOTE: Protocol here is for server to send 'sensor=<username>&recorded=<recording>&
#		time=<time>&sensor_min=<sensor_min>&sensor_avg=<sensor_avg>&sensor_max=<sensor_max>
#		&all_avg=<all_avg>'
sensor_statistics = s.recv(4096)

# TODO - Check for invalid sensor statistics.

print format_sensor_statistics(sensor_statistics)

# ========================================================

s.close()
