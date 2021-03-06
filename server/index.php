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


/**
 * This file bootstraps the PHP API, receives requests from the client app, validates the
 * authentication on them and responds accordingly to the client with an authenticated response
 */


use Jericho\Database as Database;
use Jericho\Api as Api;


// Include code for libraries
require_once 'library/database.php';
require_once 'library/query.php';
require_once 'library/api.php';

// Load the config into memory
require_once 'config/config.php';


// Initialise the database and API objects
$db = new Database($databaseConfig);
$api = new Api($db, $numberOfUsers, $serverKey, $applicationConfig);

// Connect to the database
$api->connectToDatabase();

// Authenticate the API request from the client using the sent nonce, timestamp and MAC.
// A correctly authenticated request will continue executing past here and perform the API action.
$api->performClientRequestAuthentication();

// Delete read messages and old nonces from the database after a valid request. We do not want an
// attacker sending multiple requests to the server and a database query being run every invalid request.
$api->performCleanup();

// Perform the request API action and send JSON response back to client
$api->performRequestedApiAction();
