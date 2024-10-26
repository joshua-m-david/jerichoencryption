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


use Jericho\Api;
use Jericho\Cleanup;
use Jericho\Converter;
use Jericho\Database;
use Jericho\NetworkCipher;
use Jericho\RequestAuth;
use Jericho\ResponseAuth;

use PHPUnit\Framework\TestCase;


/**
 * All tests for testing the cleanup of the database
 */
class CleanupTest extends TestCase
{
	/**
	 * @var Database $db The Database class object
	 */
	private $db;

	/**
	 * @var Api $api The API class object
	 */
	private $api;

	/**
	 * @var NetworkCipher $networkCipher The Network Cipher class object
	 */
	private $networkCipher;

	/**
	 * @var RequestAuth $requestAuth The Request Auth class object
	 */
	private $requestAuth;

	/**
	 * @var ResponseAuth $responseAuth The Response Auth class object
	 */
	private $responseAuth;

	/**
	 * @var Cleanup $cleanup The Cleanup class object
	 */
	private $cleanup;

	/**
	 * @var Array $testGroupConfig The test group configuration for use in some tests
	 */
	private $testGroupConfig;

	/**
	 * Main setup which is run for each unit test
	 */
	protected function setUp(): void
	{
		// Load the common helper functions
		$this->converter = new Converter();

		// Get the absolute path to the test configuration file e.g. /var/www/html/tests/config/config.json
		$configFilePath = realpath(__DIR__ . '/config/config.json');

		// Load the configuration into memory
		$config = $this->converter->loadAndDecodeConfig($configFilePath);
		$databaseConfig = $config['databaseConfig'];
		$groupConfigs = $config['groupConfigs'];

		// Initialise classes and the API
		$this->db = new Database($databaseConfig);
		$this->api = new Api($this->db);
		$this->networkCipher = new NetworkCipher($this->converter);
		$this->requestAuth = new RequestAuth($this->db, $this->converter, $this->networkCipher);
		$this->responseAuth = new ResponseAuth($this->converter, $this->networkCipher);
		$this->cleanup = new Cleanup($this->db, $groupConfigs);

		// Get the test database name from the group config.
		// NB: there is only one group config in the config file
		$testGroupConfig = $config['groupConfigs'][0];
		$testDatabaseName = $testGroupConfig['groupDatabaseName'];

		// Connect to the database
		$this->db->updateConfigDatabaseName($testDatabaseName);
		$this->db->connect();

		// Store the test database config
		$this->testGroupConfig = $testGroupConfig;
	}

	/**
	 * Cleanup after each test
	 */
	protected function tearDown(): void
	{
		// Truncate the nonces and messages tables for each test to run cleanly
		$this->db->preparedUpdate('TRUNCATE TABLE nonces');
		$this->db->preparedUpdate('TRUNCATE TABLE messages');
	}

	public function testCleanupOldNonces()
	{
		// Get the current timestamp
		$currentTimestamp = time();

		// Add some test nonces into the database with varying timestamps
		$nonceHex = $this->responseAuth->generateNonce();
		$timestamp = $currentTimestamp;
		$result = $this->requestAuth->addSentNonceToDatabase($nonceHex, $timestamp);
		$validNonceId = $this->db->getLastInsertedId();
		$this->assertTrue($result);

		// Timestamp on verge of being cleaned up
		$nonceHex = $this->responseAuth->generateNonce();
		$timestamp = $currentTimestamp - Cleanup::NONCE_EXPIRY_TIME_SECONDS;
		$result = $this->requestAuth->addSentNonceToDatabase($nonceHex, $timestamp);
		$invalidNonceId = $this->db->getLastInsertedId();
		$this->assertTrue($result);

		// Timestamp that should be definitely cleaned up
		$nonceHex = $this->responseAuth->generateNonce();
		$timestamp = $currentTimestamp - Cleanup::NONCE_EXPIRY_TIME_SECONDS - 1;
		$result = $this->requestAuth->addSentNonceToDatabase($nonceHex, $timestamp);
		$definitelyInvalidNonceId = $this->db->getLastInsertedId();
		$this->assertTrue($result);

		// Cleanup the old nonces
		$result = $this->cleanup->cleanupOldNonces($currentTimestamp);
		$this->assertTrue($result);

		// Try retrieve the still valid nonce from the database
		$query = 'SELECT * FROM nonces WHERE nonce_id = :nonce_id';
		$params = array('nonce_id' => $validNonceId);
		$result = $this->db->preparedSelect($query, $params);
		$this->assertNotEmpty($result);

		// Try retrieve the invalid nonce from the database
		$query = 'SELECT * FROM nonces WHERE nonce_id = :nonce_id';
		$params = array('nonce_id' => $invalidNonceId);
		$result = $this->db->preparedSelect($query, $params);
		$this->assertEmpty($result);

		// Try retrieve the invalid nonce from the database (it should be deleted)
		$query = 'SELECT * FROM nonces WHERE nonce_id = :nonce_id';
		$params = array('nonce_id' => $definitelyInvalidNonceId);
		$result = $this->db->preparedSelect($query, $params);
		$this->assertEmpty($result);
	}

	public function testCleanupReadMessages()
	{
		// Add some test messages to the database
		$this->api->saveMessagesToDatabase('alpha', ['abc']);
		$this->api->saveMessagesToDatabase('bravo', ['def']);
		$this->api->saveMessagesToDatabase('charlie', ['ghi']);

		// Set the message to read by all users, this will be cleaned up
		$query = "UPDATE messages "
		       . "SET read_by_alpha = :read_by_alpha, "
		       . "read_by_bravo = :read_by_bravo, "
		       . "read_by_charlie = :read_by_charlie "
		       . "WHERE from_user = :from_user";
		$params = array(
			'read_by_alpha' => true,
			'read_by_bravo' => true,
			'read_by_charlie' => true,
			'from_user' => 'alpha'
		);
		$result = $this->db->preparedUpdate($query, $params);
		$this->assertSame(1, $result);

		// Set the message to read by alpha and bravo, this will not be cleaned up as not read by all people
		$query = "UPDATE messages "
		       . "SET read_by_alpha = :read_by_alpha, "
		       . "read_by_bravo = :read_by_bravo "
		       . "WHERE from_user = :from_user";
		$params = array(
			'read_by_alpha' => true,
			'read_by_bravo' => true,
			'from_user' => 'bravo'
		);
		$result = $this->db->preparedUpdate($query, $params);
		$this->assertSame(1, $result);

		// Run cleanup and test query ran successfully
		$result = $this->cleanup->cleanupReadMessages($this->testGroupConfig['groupNumberOfUsers']);
		$this->assertTrue($result);

		// Check how many messages are remaining in the database now
		$result = $this->db->preparedSelect('SELECT * from messages');
		$this->assertCount(2, $result);
	}

	public function testPerformCleanup()
	{
		// Run the overall cleanup for all groups
		$result = $this->cleanup->performCleanup();
		$this->assertTrue($result);
	}
}
