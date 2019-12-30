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


// Bootstrap the PHPUnit test suite
require_once(realpath(__DIR__ . '/../library/database.php'));
require_once(realpath(__DIR__ . '/../library/api.php'));
require_once(realpath(__DIR__ . '/../library/query.php'));
require_once(realpath(__DIR__ . '/../tests/config.php'));

// Application settings to make everything UTF-8
ini_set('default_charset', 'UTF-8');
mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');

// Application PHP settings
error_reporting(E_ALL);
