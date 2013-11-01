<?php
/*
	Jericho Chat - Information-theoretically secure communications.
	Copyright (C) 2013  Joshua M. David

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation in version 3 of the License.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see [http://www.gnu.org/licenses/].
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

// Connect to the database
$db = new Database($databaseConfig);
$api = new Api($db);

// Check the API credentials, incorrect login credentials will throw an error response to the client.
// Correct login credentials will continue executing past here to the page that included this file.
$api->checkApiCredentials($serverConfig);