<?php
/**
 * Jericho Chat - Information-theoretically secure communications
 * Copyright (C) 2013-2014  Joshua M. David
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

/**
 * To run tests, install PHPUnit by following instructions here:
 * http://phpunit.de/getting-started.html
 * 
 * Then change directory (cd) to the jericho server directory (where this file is located) and run this on the command line:
 * phpunit tests.php
 */

/* All tests */
class Tests extends PHPUnit_Framework_TestCase
{
	// Configs
	private $users = null;
	private $serverKey = null;
	private $databaseConfig = null;
	private $applicationConfig = null;
		
	// Database and API objects
	private $db;
	private $api;
	
	// Test data
	private $dbConnectionSuccess = false;
	private $staticRequestData = array();
		
	// Main setup
    public function setUp()
	{		
		// Valid users for this chat group that are allowed to connect to the server API to send/receive messages
		$this->users = array('alpha', 'bravo', 'charlie');

		// The server key
		$this->serverKey = '68f7d8675928635867086720617a56174101bf2ea5d3dd9449769e717638e17341e67df0efc5d9b851ec5a72493b7df1846a9901e8758cd1b132c6afacb3ebe9';

		// Database config - Credentials for PHP to access the MySQL server database
		$this->databaseConfig = array(
			'username' => 'root',					# Database username - set this value
			'password' => 'covert',					# Database password - set this value
			'hostname' => '127.0.0.1',				# The hostname (generally on same machine so you probably do not need to edit this)
			'port' => 3306,							# The port (generally 3306 is the default MySQL port so probably do not need to edit this)
			'unix_socket' => '',					# The socket for the connection if not using hostname and port (only add if required)
			'database' => 'jericho_test',			# Name of the database (name of the database as set in the SQL installation script)
		);

		// Application config - some settings specific to testing
		$this->applicationConfig = array(
			'testResponseHeaders' => true			# Enables error messages in the responses for debug purposes (make sure this is false for a live server)
		);
		
		// Connect to the database and initalise the API
		$this->db = new Database($this->databaseConfig);
		$this->api = new Api($this->db, $this->users, $this->serverKey, $this->applicationConfig);
		
		// Store database connection result to test later
		$this->dbConnectionSuccess = $this->db->connect();
		
		// If the connection fails output an error to the console and stop further tests from running
		if ($this->dbConnectionSuccess === false)
		{
			echo "Check database connection settings inside the testing code. " . $this->db->getErrorMsg() . "\n\n";
			exit;
		}
		
		// Static test data to mock a request
		$data = array(
			'user' => 'alpha',
			'apiAction' => 'receiveMessages',
			'timestamp' => '1397354254',
			'nonce' => 'da180c28f78d7487f47bb6910bbdc4436a812f65bfbb22249b0ecb705ff1b2f11bea1ecc4299ef83f7f2f5e7c2ab9c9907e0ad9d828f016a8250af6dcccaa2fd',
			'msg' => 'a9c5e65eabc900f170ca1ce2e246bff6b4939aaf557a78fc4657565f7626cb89743fb15728ac0127bb512d1f9b29b1783ad4d72a8594425fea17eb287be1ccd29d5394ffbb10a6537be5c042e02f5817a023d11e9622a74df9532737cb4b9e31e2a51a66cafd6f801e289d250291437578c1e0ca0d71849d7f32956dccad09d23311ac6e35498e6cb2acca400b141328c4548e6aa12a607f6f1897ad7cafd9db2f3de5bafa453c433d2299f850a6a02bae99c07aa1e4d53f74a233c347f9c0ef'
		);
			
		// Convert the data to JSON, then hexadecimal, then convert the key and data to binary
		$dataJson = json_encode($data);
		$dataHex = bin2hex($dataJson);
		$binaryKeyAndData = pack("H*", $this->serverKey . $dataHex);
		$mac = skein_hash_hex($binaryKeyAndData);
		
		// Store test data
		$this->staticRequestData['data'] = $dataJson;
		$this->staticRequestData['mac'] = $mac;
    }
	
	public function testConnectToDatabase()
	{
		// Check the database initialised successfully
		$this->assertTrue($this->dbConnectionSuccess);
		
		// Test that a database query runs successfully
		$result = $this->api->testDatabaseConnection();
		$this->assertTrue($result['success']);
		
		// Run a bad query
		$result = $this->db->select('SELECT * FROM nonexistant_table');
		$this->assertFalse($result);
	}
		
    public function testGetDataKeyIfExists()
    {
		// Check MAC key exists
		$data = json_decode($this->staticRequestData['data'], true);
		$user = $this->api->getDataKeyIfExists('user', $data);
		$this->assertEquals('alpha', $user);
		
		// Check missing key
		$user = $this->api->getDataKeyIfExists('other', $this->staticRequestData);
        $this->assertFalse($user);
    }
	
	public function testCheckOversizeRequest()
	{
		// Test valid request params with valid lengths
		$lengthCheck = $this->api->checkOversizeRequest($this->staticRequestData['data'], $this->staticRequestData['mac']);
		$this->assertTrue($lengthCheck);
				
		// Test oversize data
		$data = $this->staticRequestData['data'] . 'a9c5ead3';
		$lengthCheck = $this->api->checkOversizeRequest($data, $this->staticRequestData['mac']);
		$this->assertFalse($lengthCheck);
		
		// Test no mac
		$mac = '';
		$lengthCheck = $this->api->checkOversizeRequest($this->staticRequestData['data'], $mac);
		$this->assertFalse($lengthCheck);
		
		// Test undersize mac
		$mac = substr($this->staticRequestData['mac'], 0, 127);
		$lengthCheck = $this->api->checkOversizeRequest($this->staticRequestData['data'], $mac);
		$this->assertFalse($lengthCheck);
		
		// Test oversize mac
		$mac = $this->staticRequestData['mac'] . 'a';
		$lengthCheck = $this->api->checkOversizeRequest($this->staticRequestData['data'], $mac);
		$this->assertFalse($lengthCheck);
	}
		
	public function testFilterNonHexadecimalChars()
	{
		// Check valid string
		$mac = $this->api->filterNonHexadecimalChars($this->staticRequestData['mac']);
		$this->assertEquals($this->staticRequestData['mac'], $mac);
		
		// Check removal of all invalid chars
		$result = $this->api->filterNonHexadecimalChars('!"#$%&()*+-,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ ');
		$this->assertEquals('0123456789abcdef', $result);
	}
	
	/**
	 * Test vectors for Skein-512-512 from http://www.skein-hash.info/sites/default/files/skein1.3.pdf - spaces removed for simplicity
	 */
	public function testSkein()
	{
		// Lowercase the test hexadecimal input so consistent with output, then pack into binary format for PHP
		$testVector = strtolower('FF');
		$testVectorBinary = pack("H*", $testVector);
		$result = skein_hash_hex($testVectorBinary);
		$correctResult = strtolower('71B7BCE6FE6452227B9CED6014249E5BF9A9754C3AD618CCC4E0AAE16B316CC8CA698D864307ED3E80B6EF1570812AC5272DC409B5A012DF2A579102F340617A');
		$this->assertEquals($result, $correctResult);
		
		$testVector = strtolower('FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0');
		$testVectorBinary = pack("H*", $testVector);
		$result = skein_hash_hex($testVectorBinary);
		$correctResult = strtolower('45863BA3BE0C4DFC27E75D358496F4AC9A736A505D9313B42B2F5EADA79FC17F63861E947AFB1D056AA199575AD3F8C9A3CC1780B5E5FA4CAE050E989876625B');
		$this->assertEquals($result, $correctResult);
		
		$testVector = strtolower('FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180');
		$testVectorBinary = pack("H*", $testVector);
		$result = skein_hash_hex($testVectorBinary);
		$correctResult = strtolower('91CCA510C263C4DDD010530A33073309628631F308747E1BCBAA90E451CAB92E5188087AF4188773A332303E6667A7A210856F742139000071F48E8BA2A5ADB7');
		$this->assertEquals($result, $correctResult);
	}
	
	public function testConstantTimeStringCompare()
	{
		$testA = $this->api->constantTimeStringCompare($this->serverKey, '68f7d8675928635867086720617a56174101bf2ea5d3dd9449769e717638e17341e67df0efc5d9b851ec5a72493b7df1846a9901e8758cd1b132c6afacb3ebe9');
		$this->assertTrue($testA);
		
		$testB = $this->api->constantTimeStringCompare($this->serverKey, '68f7d8675928635867086720617a56174101bf2ea5d3dd9449769e717638e17341e67df0efc5d9b851ec5a72493b7df1846a9901e8758cd1b132c6afacb3ebe90');
		$this->assertFalse($testB);
		
		$testC = $this->api->constantTimeStringCompare($this->serverKey, '08f7d8675928635867086720617a56174101bf2ea5d3dd9449769e717638e17341e67df0efc5d9b851ec5a72493b7df1846a9901e8758cd1b132c6afacb3ebe9');
		$this->assertFalse($testC);
	}
	
	public function testValidateDataMac()
	{
		// Check a valid request
		$key = $this->serverKey;
		$dataToMac = $this->staticRequestData['data'];
		$mac = $this->staticRequestData['mac'];
		$validRequest = $this->api->validateDataMac($dataToMac, $key, $mac);
		$this->assertTrue($validRequest);
				
		// Check an invalid request by modifying the data
		$key = $this->serverKey;
		$dataToMac = $this->staticRequestData['data'] . '0';
		$mac = $this->staticRequestData['mac'];
		$invalidRequest = $this->api->validateDataMac($dataToMac, $key, $mac);
		$this->assertFalse($invalidRequest);
		
		// Check an invalid request by modifying the mac
		$key = $this->serverKey;
		$dataToMac = $this->staticRequestData['data'];
		$mac = $this->staticRequestData['mac'] . '0';
		$invalidRequest = $this->api->validateDataMac($dataToMac, $key, $mac);
		$this->assertFalse($invalidRequest);
	}
	
	public function testFilterNonLowercaseAlphabeticalChars()
	{
		// Check it leaves only lowercase alphabetical chars
		$user = $this->api->filterNonLowercaseAlphabeticalChars('!"#$%&()*+-,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ ');
		$this->assertEquals('abcdefghijklmnopqrstuvwxyz', $user);
	}
		
	public function testValidateUser()
	{
		// Check valid users
		$valid = $this->api->validateUser('alpha');
		$this->assertTrue($valid);
		
		$valid = $this->api->validateUser('bravo');
		$this->assertTrue($valid);
		
		$valid = $this->api->validateUser('charlie');
		$this->assertTrue($valid);
		
		// Check one that is valid but does not exist in active list
		$valid = $this->api->validateUser('delta');
		$this->assertFalse($valid);
		
		// Check one that is completely invalid
		$valid = $this->api->validateUser('nsa');
		$this->assertFalse($valid);
	}
	
	public function testFilterNonIntegers()
	{
		$numbers = $this->api->filterNonIntegers('!"#$%&()*+-,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ ');
		$this->assertEquals('0123456789', $numbers);
	}
	
	public function testValidateDataTimestamp()
	{
		// Test a timestamp in the right range
		$sentTimestamp = time();
		$valid = $this->api->validateDataTimestamp($sentTimestamp);
		$this->assertTrue($valid);
		
		// Minus 2 seconds
		$sentTimestamp = time() - 2;
		$valid = $this->api->validateDataTimestamp($sentTimestamp);
		$this->assertTrue($valid);
		
		// Plus 2 seconds
		$sentTimestamp = time() + 2;
		$valid = $this->api->validateDataTimestamp($sentTimestamp);
		$this->assertTrue($valid);
		
		// Test a timetamp that is too early
		$sentTimestamp = time() - $this->api->validityWindow - 1;
		$valid = $this->api->validateDataTimestamp($sentTimestamp);
		$this->assertFalse($valid);
		
		// Test a timetamp that is too far in future
		$sentTimestamp = time() + $this->api->validityWindow + 1;
		$valid = $this->api->validateDataTimestamp($sentTimestamp);
		$this->assertFalse($valid);
	}
	
	public function testAddSentNonceToDatabase()
	{
		// Add the static nonce to the database
		$dataJson = $this->staticRequestData['data'];
		$data = json_decode($dataJson, true);
		$nonce = $data['nonce'];
		$timestamp = $data['timestamp'];
		$result = $this->api->addSentNonceToDatabase($nonce, $timestamp);
		$this->assertTrue($result);
	}
	
	public function testGenerateNonce()
	{
		$nonceObj = $this->api->generateNonce();
		$nonce = $nonceObj['nonce'];
		$cryptoStrong = $nonceObj['cryptoStrong'];
				
		// Check it was generated with a CSPRNG 
		$this->assertTrue($cryptoStrong, 'Warning nonce not cryptographically secure.');
		
		// Check it is the correct length
		$this->assertEquals(128, strlen($nonce), 'Failed length test: ' . $nonce);
	}
	
	public function testValidateDataNonce()
	{
		// Check if the static nonce already exists in the database which indicates a replay attack
		$dataJson = $this->staticRequestData['data'];
		$data = json_decode($dataJson, true);
		$nonce = $data['nonce'];
		$valid = $this->api->validateDataNonce($nonce);
		$this->assertFalse($valid);
		
		// Add a random nonce and timestamp
		$nonceObj = $this->api->generateNonce();
		$nonce = $nonceObj['nonce'];
		$timestamp = time();
		$result = $this->api->addSentNonceToDatabase($nonce, $timestamp);
		$this->assertTrue($result);
	}
	
	public function testFilterNonAlphabeticalChars()
	{
		$chars = $this->api->filterNonAlphabeticalChars('!"#$%&()*+-,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ ');
		$this->assertEquals('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', $chars);
	}
	
	public function testValidateApiAction()
	{
		// Test valid actions
		$apiAction = 'sendMessage';
		$valid = $this->api->validateApiAction($apiAction);
		$this->assertTrue($valid);
		
		$apiAction = 'receiveMessages';
		$valid = $this->api->validateApiAction($apiAction);
		$this->assertTrue($valid);
		
		$apiAction = 'autoNuke';
		$valid = $this->api->validateApiAction($apiAction);
		$this->assertTrue($valid);
		
		$apiAction = 'testConnection';
		$valid = $this->api->validateApiAction($apiAction);
		$this->assertTrue($valid);
		
		// Test invalid actions
		$apiAction = '';
		$valid = $this->api->validateApiAction($apiAction);
		$this->assertFalse($valid);
		
		$apiAction = null;
		$valid = $this->api->validateApiAction($apiAction);
		$this->assertFalse($valid);
		
		$apiAction = 'abc';
		$valid = $this->api->validateApiAction($apiAction);
		$this->assertFalse($valid);
	}
		
	public function testCleanupOldNonces()
	{
		// Clear the database table to give a clean slate for the tests
		$this->db->update('DELETE FROM nonces');
		
		// Get the current timestamp
		$currentTimestamp = time();
		
		// Add some test nonces into the database with varying timestamps
		$nonce = $this->api->generateNonce();
		$timestamp = $currentTimestamp;		
		$result = $this->api->addSentNonceToDatabase($nonce['nonce'], $timestamp);
		$validNonceId = $this->db->getLastInsertedId();
		$this->assertTrue($result);
		
		// Timestamp on verge of being cleaned up
		$nonce = $this->api->generateNonce();
		$timestamp = $currentTimestamp - $this->api->nonceExpiryTime;
		$result = $this->api->addSentNonceToDatabase($nonce['nonce'], $timestamp);
		$invalidNonceId = $this->db->getLastInsertedId();
		$this->assertTrue($result);
		
		// Timestamp that should be definitely cleaned up
		$nonce = $this->api->generateNonce();
		$timestamp = $currentTimestamp - $this->api->nonceExpiryTime - 1;
		$result = $this->api->addSentNonceToDatabase($nonce['nonce'], $timestamp);
		$definitelyInvalidNonceId = $this->db->getLastInsertedId();
		$this->assertTrue($result);
		
		// Cleanup the old nonces		
		$result = $this->api->cleanupOldNonces($currentTimestamp);
		$this->assertTrue($result);
		
		// Try retrieve the still valid nonce from the database
		$result = $this->db->select('SELECT * from nonces WHERE nonce_id = ' . $validNonceId);
		$this->assertNotEmpty($result);
		
		// Try retrieve the invalid nonce from the database
		$result = $this->db->select('SELECT * from nonces WHERE nonce_id = ' . $invalidNonceId);
		$this->assertEmpty($result);
		
		// Try retrieve the invalid nonce from the database (it should be deleted)
		$result = $this->db->select('SELECT * from nonces WHERE nonce_id = ' . $definitelyInvalidNonceId);
		$this->assertEmpty($result);
	}
	
	public function testSaveMessageToDatabase()
	{
		// Clear the database from any old test messages
		$result = $this->db->update('DELETE FROM messages');
		
		// Add some test messages to the database
		$result = $this->api->saveMessageToDatabase('alpha', 'abc');
		$this->assertTrue($result['success']);
		
		$result = $this->api->saveMessageToDatabase('bravo', 'def');
		$this->assertTrue($result['success']);
		
		$result = $this->api->saveMessageToDatabase('charlie', 'ghi');
		$this->assertTrue($result['success']);
	}
	
	public function testCleanupReadMessages()
	{
		// Set the message to read by all users, this will be cleaned up
		$result = $this->db->update("UPDATE messages SET read_by_alpha = 1, read_by_bravo = 1, read_by_charlie = 1 WHERE from_user = 'alpha'");
		$this->assertEquals(1, $result);
		
		// Set the message to read by alpha and bravo, this will not be cleaned up as not read by all people
		$result = $this->db->update("UPDATE messages SET read_by_alpha = 1, read_by_bravo = 1 WHERE from_user = 'bravo'");
		$this->assertEquals(1, $result);
					
		// Run cleanup and test query ran successfully
		$result = $this->api->cleanupReadMessages();
		$this->assertTrue($result);
		
		// Check how many messages are remaining in the database now
		$result = $this->db->select('SELECT * from messages');
		$this->assertCount(2, $result);
	}
	
	public function testPerformCleanup()
	{
		// Update last run cleanup time to 31 seconds in the past so cleanup can be run
		$currentTimestamp = time() - $this->api->cleanupSchedule - 1;
		$result = $this->api->updateLastCleanupTime($currentTimestamp);
		$this->assertTrue($result);
		
		// Run the cleanup
		$result = $this->api->performCleanup();
		$this->assertTrue($result);
		
		// Run the cleanup again just after, which should not run
		$result = $this->api->performCleanup();
		$this->assertFalse($result);
	}
	
	public function testCheckIfAutoNukeInitiated()
	{
		// Initiate the nuke
		$result = $this->db->update("UPDATE settings SET auto_nuke_initiated = 1, auto_nuke_initiated_by_user = 'alpha'");
				
		// Check whether initiated
		$autoNukeInitiatedBy = $this->api->checkIfAutoNukeInitiated();
		$this->assertEquals('alpha', $autoNukeInitiatedBy);
		
		// Set it back to not enabled
		$result = $this->db->update("UPDATE settings SET auto_nuke_initiated = 0, auto_nuke_initiated_by_user = NULL");
		
		// Check whether initiated
		$autoNukeInitiatedBy = $this->api->checkIfAutoNukeInitiated();
		$this->assertFalse($autoNukeInitiatedBy);
	}
	
	public function testGetMessagesForUser()
	{
		// Clear the database from any old test messages
		$result = $this->db->update('DELETE FROM messages');
		$this->assertNotEquals(false, $result);
		
		// Add some test messages to the database
		$result = $this->api->saveMessageToDatabase('alpha', 'abc');
		$this->assertTrue($result['success']);
		
		$result = $this->api->saveMessageToDatabase('bravo', 'def');
		$this->assertTrue($result['success']);
		
		$result = $this->api->saveMessageToDatabase('charlie', 'ghi');
		$this->assertTrue($result['success']);
		
		// Get the messages for user alpha, there should be two not from alpha
		$jsonResult = $this->api->getMessagesForUser('alpha');
		$this->assertTrue($jsonResult['success']);
		$this->assertEquals('Messages received successfully.', $jsonResult['statusMessage']);
		$this->assertCount(2, $jsonResult['messages']);
		
		// Try get the messages again and they should have been marked read, so none left to get
		$jsonResult = $this->api->getMessagesForUser('alpha');
		$this->assertFalse($jsonResult['success']);
		$this->assertEquals('No messages in database.', $jsonResult['statusMessage']);
		
		// Get the messages for user bravo, there should be two not from user bravo
		$jsonResult = $this->api->getMessagesForUser('bravo');
		$this->assertTrue($jsonResult['success']);
		$this->assertEquals('Messages received successfully.', $jsonResult['statusMessage']);
		$this->assertCount(2, $jsonResult['messages']);
		
		// Try get the messages again and they should have been marked read, so none left to get
		$jsonResult = $this->api->getMessagesForUser('bravo');
		$this->assertFalse($jsonResult['success']);
		$this->assertEquals('No messages in database.', $jsonResult['statusMessage']);
		
		// Get the messages for user charlie, there should be two not from user charlie
		$jsonResult = $this->api->getMessagesForUser('charlie');
		$this->assertTrue($jsonResult['success']);
		$this->assertEquals('Messages received successfully.', $jsonResult['statusMessage']);
		$this->assertCount(2, $jsonResult['messages']);
		
		// Try get the messages again and they should have been marked read, so none left to get
		$jsonResult = $this->api->getMessagesForUser('charlie');
		$this->assertFalse($jsonResult['success']);
		$this->assertEquals('No messages in database.', $jsonResult['statusMessage']);
	}
	
	public function testInitiateAutoNuke()
	{
		// Start the auto nuke process. This deletes everything from the server and sets a flag 
		// so the next time the other users connect their chat and pads will be wiped
		$jsonResult = $this->api->initiateAutoNuke('alpha');
		$this->assertTrue($jsonResult['success']);
		
		// Check whether initiated
		$autoNukeInitiatedBy = $this->api->checkIfAutoNukeInitiated();
		$this->assertEquals('alpha', $autoNukeInitiatedBy);
		
		// Set it back to not enabled for next test
		$this->db->update("UPDATE settings SET auto_nuke_initiated = 0, auto_nuke_initiated_by_user = NULL");
	}
	
	public function testCreateMac()
	{		
		// Test MAC that is similar to what is used in the response
		$requestMac = $this->staticRequestData['mac'];
		$serverKey = $this->serverKey;
		$jsonResult['success'] = true;
		$jsonResult['statusMessage'] = 'Server and database connection successful.';
		$responseDataJson = json_encode($jsonResult);
		
		// Generate response MAC and test (verify with JavaScript for matching hash)
		$responseMac = $this->api->createMac($serverKey, $responseDataJson, $requestMac);		
		$this->assertEquals('56607c49b1312ee22873a65f27ded9cf6b1ea5478f2d5663874904e6b86652fb5c7601d28b4e5550dc498c75c8c47471f767d47d7f2b5721d5d93d6d48ea67b9', $responseMac);
	}
}