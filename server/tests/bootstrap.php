<?php
/**
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2024  Joshua M. David
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation in version 3 of the License.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see [http://www.gnu.org/licenses/].
 */


/**
 * This file bootstraps the PHPUnit test suite
 */

// Application settings to make everything UTF-8
ini_set('default_charset', 'UTF-8');
mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');

// Load common constants
require_once(realpath(__DIR__ . '/../library/constants/common-constants.php'));

// Load data storage classes
require_once(realpath(__DIR__ . '/../library/data-classes/response.php'));
require_once(realpath(__DIR__ . '/../library/data-classes/transaction-query.php'));
require_once(realpath(__DIR__ . '/../library/data-classes/validated-request.php'));

// Load helper classes
require_once(realpath(__DIR__ . '/../library/helper-classes/cleanup.php'));
require_once(realpath(__DIR__ . '/../library/helper-classes/converter.php'));
require_once(realpath(__DIR__ . '/../library/helper-classes/database.php'));
require_once(realpath(__DIR__ . '/../library/helper-classes/network-cipher.php'));

// Load main functionality classes
require_once(realpath(__DIR__ . '/../library/api.php'));
require_once(realpath(__DIR__ . '/../library/request-auth.php'));
require_once(realpath(__DIR__ . '/../library/response-auth.php'));

// Application PHP settings
error_reporting(E_ALL);
