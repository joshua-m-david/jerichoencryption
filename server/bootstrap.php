<?php
/**
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2016  Joshua M. David
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

// Bootstrap the PHPUnit test suite
include_once(__DIR__ . '/lib/database.php');
include_once(__DIR__ . '/lib/api.php');
include_once(__DIR__ . '/lib/query.php');

// Application settings to make everything UTF-8
ini_set('default_charset', 'UTF-8');
mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');

// Application PHP settings
error_reporting(E_ALL | E_STRICT | E_NOTICE | E_DEPRECATED | E_PARSE);