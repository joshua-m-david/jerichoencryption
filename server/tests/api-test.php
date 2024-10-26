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
use Jericho\CommonConstants;
use Jericho\Converter;
use Jericho\Database;
use Jericho\ValidatedRequest;
use Jericho\Response;

use PHPUnit\Framework\TestCase;


/**
 * All tests for testing the API
 */
class ApiTest extends TestCase
{
	/**
	 * @var Database $db The Database object
	 */
	private $db;

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

		// Initialise classes and the API
		$this->db = new Database($databaseConfig);
		$this->api = new Api($this->db);

		// Get the test database name from the group config.
		// NB: there is only one group config in the config file
		$testGroupConfig = $config['groupConfigs'][0];
		$testDatabaseName = $testGroupConfig['groupDatabaseName'];

		// Connect to the database
		$this->db->updateConfigDatabaseName($testDatabaseName);
		$this->db->connect();
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

	public function testApiActionTestDatabaseConnection()
	{
		$successResponse = $this->api->testDatabaseConnection();

		$this->assertSame(Response::RESPONSE_SUCCESS, $successResponse->responseCode);
	}

	public function testApiActionSaveMessagesToDatabase()
	{
		// Add some test messages to the database
		$oneMessageResponse = $this->api->saveMessagesToDatabase('alpha', ['abc']);
		$twoMessagesResponse = $this->api->saveMessagesToDatabase('bravo', ['abc', 'def']);
		$threeMessagesResponse = $this->api->saveMessagesToDatabase('charlie', ['abc', 'def', 'ghi']);

		// Test failure responses
		$noMessageResponse = $this->api->saveMessagesToDatabase('alpha', []);
		$badUserResponse = $this->api->saveMessagesToDatabase('bob', ['abc']);

		$this->assertSame(Response::RESPONSE_SUCCESS, $oneMessageResponse->responseCode);
		$this->assertSame(Response::RESPONSE_SUCCESS, $twoMessagesResponse->responseCode);
		$this->assertSame(Response::RESPONSE_SUCCESS, $threeMessagesResponse->responseCode);

		$this->assertSame(Response::RESPONSE_ERROR_NO_MESSAGES_SENT, $noMessageResponse->responseCode);
		$this->assertSame(Response::RESPONSE_ERROR_DB_QUERY_FAILED, $badUserResponse->responseCode);
	}

	public function testApiActionGetMessagesForUser()
	{
		// Add some test messages to the database
		$this->api->saveMessagesToDatabase('alpha', ['abc']);
		$this->api->saveMessagesToDatabase('bravo', ['def']);
		$this->api->saveMessagesToDatabase('charlie', ['ghi']);

		// Get the messages for user alpha, there should be two not from alpha
		$response = $this->api->getMessagesForUser('alpha');
		$this->assertSame(Response::RESPONSE_SUCCESS, $response->responseCode);
		$this->assertCount(2, $response->userMessagePackets);

		// Try get the messages again and they should have been marked read, so none left to get
		$response = $this->api->getMessagesForUser('alpha');
		$this->assertSame(Response::RESPONSE_SUCCESS_NO_MESSAGES, $response->responseCode);
		$this->assertCount(0, $response->userMessagePackets);

		// Get the messages for user bravo, there should be two not from user bravo
		$response = $this->api->getMessagesForUser('bravo');
		$this->assertSame(Response::RESPONSE_SUCCESS, $response->responseCode);
		$this->assertCount(2, $response->userMessagePackets);

		// Try get the messages again and they should have been marked read, so none left to get
		$response = $this->api->getMessagesForUser('bravo');
		$this->assertSame(Response::RESPONSE_SUCCESS_NO_MESSAGES, $response->responseCode);
		$this->assertCount(0, $response->userMessagePackets);

		// Get the messages for user charlie, there should be two not from user charlie
		$response = $this->api->getMessagesForUser('charlie');
		$this->assertSame(Response::RESPONSE_SUCCESS, $response->responseCode);
		$this->assertCount(2, $response->userMessagePackets);

		// Try get the messages again and they should have been marked read, so none left to get
		$response = $this->api->getMessagesForUser('bravo');
		$this->assertSame(Response::RESPONSE_SUCCESS_NO_MESSAGES, $response->responseCode);
		$this->assertCount(0, $response->userMessagePackets);
	}

	public function testPerformRequestedApiAction()
	{
		// Test successful Test API action
		$validatedRequestA = new ValidatedRequest(true, '', CommonConstants::API_ACTION_TEST);
		$responseA = $this->api->performRequestedApiAction($validatedRequestA);
		$expectedResponseCodeA = Response::RESPONSE_SUCCESS;

		// Test successful Send API action to send 2 messages
		$validatedRequestB = new ValidatedRequest(true, '', CommonConstants::API_ACTION_SEND, 'alpha', ['abc', 'def']);
		$responseB = $this->api->performRequestedApiAction($validatedRequestB);
		$expectedResponseCodeB = Response::RESPONSE_SUCCESS;

		// Test successful Receive API action to receive 2 messages
		$validatedRequestC = new ValidatedRequest(true, '', CommonConstants::API_ACTION_RECEIVE, 'bravo');
		$responseC = $this->api->performRequestedApiAction($validatedRequestC);
		$numOfResponseMessagesC = count($responseC->userMessagePackets);
		$expectedResponseCodeC = Response::RESPONSE_SUCCESS;
		$expectedNumberOfMessagesC = 2;

		// Test invalid API action
		$invalidApiActionValidatedRequest = new ValidatedRequest(true, '', 'invalid');
		$invalidApiActionResponse = $this->api->performRequestedApiAction($invalidApiActionValidatedRequest);
		$expectedInvalidApiActionResponseCode = Response::RESPONSE_ERROR_INVALID_API_ACTION;

		$this->assertSame($expectedResponseCodeA, $responseA->responseCode);
		$this->assertSame($expectedResponseCodeB, $responseB->responseCode);
		$this->assertSame($expectedResponseCodeC, $responseC->responseCode);
		$this->assertSame($expectedNumberOfMessagesC, $numOfResponseMessagesC);

		$this->assertSame($expectedInvalidApiActionResponseCode, $invalidApiActionResponse->responseCode);
	}
}