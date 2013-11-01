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


/* -------------------------------------------------------------------- */
/* REST API to test the server and database connection from the client
/* -------------------------------------------------------------------- */

// Load configuration
require_once 'config/bootstrap.php';

// Check the connection works
$jsonResult = $api->testDatabaseConnection();

// Output the response to the client
$api->outputJson($jsonResult);