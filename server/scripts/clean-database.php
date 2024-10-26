#!/usr/bin/php
<?php

namespace Jericho;

// Application settings to make everything UTF-8
ini_set('default_charset', 'UTF-8');
mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');

// Load common constants
require_once realpath(__DIR__ . '/../library/constants/common-constants.php');

// Load helper classes
require_once realpath(__DIR__ . '/../library/helper-classes/cleanup.php');
require_once realpath(__DIR__ . '/../library/helper-classes/converter.php');
require_once realpath(__DIR__ . '/../library/helper-classes/database.php');

// Initialise the script, first get the absolute path to the live config file e.g. /var/www/html/config/config.json
$configFilePath = realpath(__DIR__ . '/../config/config.json');

// Load the JSON file configuration and decode it into an array
$converter = new Converter();
$config = $converter->loadAndDecodeConfig($configFilePath);
$databaseConfig = $config['databaseConfig'];
$groupConfigs = $config['groupConfigs'];

// Initialise the database class and the request authentication
$db = new Database($databaseConfig);

// Authenticate and decrypt the API request from the client.
$cleanup = new Cleanup($db, $groupConfigs);
$cleanup->performCleanup();
