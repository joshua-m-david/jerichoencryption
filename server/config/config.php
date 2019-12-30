<?php
/**
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2019  Joshua M. David
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation in version 3 of the License.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see [http://www.gnu.org/licenses/].
 */


// Valid users for this chat group (currently only 2, 3, 4, 5, 6 or 7 are supported)
$numberOfUsers = 2;

// The 512 bit server key in lowercase hexadecimal symbols e.g. 'c7ba48d...' (128 hex characters in length).
// This is automatically replaced by the server installation script.
$serverKey = 'jerichoserverkey';

// Database config - Credentials for PHP to access the PostgreSQL server database
$databaseConfig = array(

	// Database password (replaced by server installation script)
	'password' => 'jerichopassword',

	// Database username (generally default of jerichouser will be fine so you probably do not need to edit this)
	'username' => 'jerichouser',

	// The hostname (generally PostgreSQL is on the same machine so you probably do not need to edit this)
	'hostname' => '127.0.0.1',

	// The port (generally 5432 is the default PostgreSQL port so you probably do not need to edit this)
	'port' => 5432,

	// Name of the database (generally default is fine, unless you are making a new
	// chat group on the server and modified the SQL installation script as well)
	'database' => 'jerichodb',
);

// Application config - some settings specific to testing
$applicationConfig = array(

	// Enables messages in the HTTP 200 header responses for debug purposes - make sure this is false for a live server!
	'testResponseHeaders' => false
);
