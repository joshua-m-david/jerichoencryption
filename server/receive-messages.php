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
/* REST API to receive messages for a user
/* --------------------------------------- */

// Load configuration
require_once 'config/bootstrap.php';

// Check if auto nuke was initiated
$api->checkIfAutoNukeInitiated();

// Check messages sent to this user
if (isset($_POST['to']))
{	
	$jsonResult = $api->getMessagesForUser($_POST['to']);
}
else {
	// Show error
	$jsonResult = array(
		'success' => false,
		'statusMessage' => 'Not all variables received from the AJAX request.'
	);
}

// Output response
$api->outputJson($jsonResult);