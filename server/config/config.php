<?php
/**
 * To add additional users for this chat group, edit the $userConfig array and 
 * add additional users. There must be between 2-7 users listed in the array 
 * which are part of this chat group. The following are currently the only 
 * valid users:
 * alpha, bravo, charlie, delta, echo, foxtrot, golf
 * 
 * For example here is a group of 5 users:
 * $userConfig = array('alpha', 'bravo', 'charlie', 'delta', 'echo');
 * 
 * The server key is used to sign all data going to or from the server using 
 * the skein-512 hash. This key will be entered into the client application and 
 * exported for each user with their one-time pads so they can connect to the 
 * server to send/receive messages.
 * 
 * Make sure the server key is random hexadecimal symbols (0-9, a-f) of 128 
 * hexadecimal symbols in length which is a 512 bit key. The client program can 
 * generate a truly random 512 bit server key for you. This can be done after 
 * the one-time pads have been generated. One of the export options will allow 
 * creation of the server key as well. From there you can copy and paste it into 
 * this configuration file.
 */

// Valid users for this chat group - add more users as required!
$users = array('alpha', 'bravo');

// The 512 bit server key in hexadecimal symbols - change this value!
$serverKey = '68f7d8675928635867086720617a56174101bf2ea5d3dd9449769e717638e17341e67df0efc5d9b851ec5a72493b7df1846a9901e8758cd1b132c6afacb3ebe9';

// Database config - Credentials for PHP to access the MySQL server database
$databaseConfig = array(
	'password' => 'covert',        # Database password - change this value!
	'username' => 'root',          # Database username (generally default of root will be fine)
	'hostname' => '127.0.0.1',     # The hostname (generally on same machine so you probably do not need to edit this)
	'port' => 3306,                # The port (generally 3306 is the default MySQL port so probably do not need to edit this)
	'unix_socket' => '',           # The socket for the connection if not using hostname and port (generally not required, only add if required if not using a VPS and your webhost does not allow ports)
	'database' => 'jericho',       # Name of the database (generally default is fine, unless you are making a new chat group on the server and modified the SQL installation script)
);

// Application config - some settings specific to testing
$applicationConfig = array(
	'testResponseHeaders' => false		# Enables messages in the HTTP 403 error responses for debug purposes - make sure this is false for a live server!
);
