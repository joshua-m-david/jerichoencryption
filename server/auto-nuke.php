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
/* Initiate the auto nuke functionality
/* -------------------------------------------------------------------- */

// Load configuration
require_once 'config/bootstrap.php';

// Initialise response
$jsonResult = array(
	'success' => false,
	'statusMessage' => 'Not all variables received from the AJAX request.'
);

// Make sure all message variables are set
if (isset($_POST['autoNuke']))
{
	$jsonResult = $api->initiateAutoNuke();
}

// Output response
$api->outputJson($jsonResult);