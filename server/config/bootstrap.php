<?php
/*
	Jericho Encrypted Chat
	Copyright (c) 2013 Joshua M. David

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software, design and associated documentation files (the "Software"), 
	to deal in the Software including without limitation the rights to use, copy, 
	modify, merge, publish, distribute, and to permit persons to whom the Software 
	is furnished to do so, subject to the following conditions:

	1) The above copyright notice and this permission notice shall be included in
	   all copies of the Software and any other software that utilises part or all
	   of the Software (the "Derived Software").
	2) Neither the Software nor any Derived Software may be sold, published, 
	   distributed or otherwise dealt with for financial gain without the express
	   consent of the copyright holder.
	3) Derived Software must not use the same name as the Software.
	4) The Software and Derived Software must not be used for evil purposes.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
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