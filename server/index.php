<?php
/**
 * Jericho Chat - Information-theoretically secure communications
 * Copyright (C) 2013-2014  Joshua M. David
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation in version 3 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see [http://www.gnu.org/licenses/].
 */


/* --------------------------------------- */
/* File to bootstrap the PHP application
/* --------------------------------------- */

// Application settings to make everything UTF-8
ini_set('default_charset', 'UTF-8');
mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');

// Application PHP settings
error_reporting(E_ALL | E_STRICT | E_NOTICE | E_DEPRECATED | E_PARSE);

// Include code for libraries
require_once 'lib/database.php';
require_once 'lib/query.php';
require_once 'lib/api.php';

// Load the config into memory
require_once 'config/config.php';

// Initialise the database and API objects
$db = new Database($databaseConfig);
$api = new Api($db, $users, $serverKey, $applicationConfig);

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