<?php
// Server API config - Credentials for users to connect to the server API to send/receive messages
$serverConfig = array(
	'username' => 'jackoneill',		# Server username - set this value
	'password' => 'stargatesg-1'	# Server password - set this value
);

// Database config - Credentials for PHP to access the MySQL server database
$databaseConfig = array(
	'username' => 'root',			# Database username - set this value
	'password' => '',				# Database password - set this value
	'hostname' => '127.0.0.1',		# The hostname
	'port' => 3306,					# The port
	'unix_socket' => '',			# The socket for the connection if not using hostname and port
	'database' => 'jericho',		# Name of the database
	'persistent' => false,
	'errorMode' => PDO::ERRMODE_EXCEPTION
); 