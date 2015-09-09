<?php
/**
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2015  Joshua M. David
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
	private $numberOfUsers = null;
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
		$this->numberOfUsers = 3;
		
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
		$this->api = new Api($this->db, $this->numberOfUsers, $this->serverKey, $this->applicationConfig);
		
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
	
	public function testSetChatGroupUsers()
	{
		// Test valid number of users
		$numberOfUsers = 2;
		$validUsers = $this->api->setChatGroupUsers($numberOfUsers);
		$expectedUsers = array('alpha', 'bravo');
		$this->assertEquals(json_encode($validUsers), json_encode($expectedUsers));
		
		$numberOfUsers = 3;
		$validUsers = $this->api->setChatGroupUsers($numberOfUsers);
		$expectedUsers = array('alpha', 'bravo', 'charlie');
		$this->assertEquals(json_encode($validUsers), json_encode($expectedUsers));
		
		$numberOfUsers = 4;
		$validUsers = $this->api->setChatGroupUsers($numberOfUsers);
		$expectedUsers = array('alpha', 'bravo', 'charlie', 'delta');
		$this->assertEquals(json_encode($validUsers), json_encode($expectedUsers));
		
		$numberOfUsers = 5;
		$validUsers = $this->api->setChatGroupUsers($numberOfUsers);
		$expectedUsers = array('alpha', 'bravo', 'charlie', 'delta', 'echo');
		$this->assertEquals(json_encode($validUsers), json_encode($expectedUsers));
		
		$numberOfUsers = 6;
		$validUsers = $this->api->setChatGroupUsers($numberOfUsers);
		$expectedUsers = array('alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot');
		$this->assertEquals(json_encode($validUsers), json_encode($expectedUsers));
		
		$numberOfUsers = 7;
		$validUsers = $this->api->setChatGroupUsers($numberOfUsers);
		$expectedUsers = array('alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf');
		$this->assertEquals(json_encode($validUsers), json_encode($expectedUsers));
		
		
		// Test invalid number of users
		$numberOfUsers = 8;
		$validUsers = $this->api->setChatGroupUsers($numberOfUsers);
		$expectedUsers = array('alpha', 'bravo');
		$this->assertEquals(json_encode($validUsers), json_encode($expectedUsers));
				
		$numberOfUsers = 1;
		$validUsers = $this->api->setChatGroupUsers($numberOfUsers);
		$expectedUsers = array('alpha', 'bravo');
		$this->assertEquals(json_encode($validUsers), json_encode($expectedUsers));
		
		$numberOfUsers = 'x';
		$validUsers = $this->api->setChatGroupUsers($numberOfUsers);
		$expectedUsers = array('alpha', 'bravo');
		$this->assertEquals(json_encode($validUsers), json_encode($expectedUsers));
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
		
	public function testFilterNonBase64Chars()
	{
		$base64Chars = $this->api->filterNonBase64Chars('!"#$%&()*+-,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ ');
		$this->assertEquals('+/0123456789=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', $base64Chars);
	}
	
	public function testValidateAndDecodeBase64()
	{
		// Test a valid send message request
		$rawDataBase64 = 'eyJ1c2VyIjoiYWxwaGEiLCJhcGlBY3Rpb24iOiJzZW5kTWVzc2FnZSIsIm1zZyI6ImI0M2Y4NDA3YmU0ZjdmODQxZTJhNDgyNDRhZTQyYmZhZDI5YTdlMmQyMmYyZmEzZGUzODZiMzkyNjUyYzNjOTg4YzBiNWQ0M2RhOTIyOTVlMmIzZmYxODFhZWQ3MWM3MWVlODcxODI4ZDQxZjQxOWRlNzVkODcwMzU2NTEyYWNkNmZmOThjMjk3MjBjNzc1YWZlNjc0ZDExZDRiMWIxZTYzZWI4MTQ2YzQ4NmM0M2Q4MGZkM2Q2NzNiNDFiNTIwYjlhOTllOWIyYjgyMDY0M2FhN2EwYTM2ZDdiZTg3OWZlM2U1Y2IwYTQxYzMzYjRlYjYyMTJmYWJlYWU3ODgzNmU2NzE0ZjJiYzAwNDMwMTViMWYzMzQzODgxNThhYTljMGJiYmJjYTkyZjQyNTg0YjcyYzFkYTVlMTJmOTg1MTk5ODIzOGVhMjQzOTI0NDhjMmM3Nzk2MDdmZDFlMWFiNWU2MzZhNDQyNjFlMTA2YTMyNGRmZWE2MjJhMjczZjc0MyIsIm5vbmNlIjoiOTAyNmI0MzAwYWMzNzE1ZGZlOGU0YTc1YTg2MjE0MzliNzI3YzQwOTdmZjNiNDY0MmFmMGQ1MTA1MmRmOTVlOWVhNTk1ZjJiOTJmMDU0MzFhZWE5NGJkMjdmM2YwMjE0ZTI4NWU4ODA2OWQ1NGIyMzVmYzdmYjhiY2M2M2ZhNTIiLCJ0aW1lc3RhbXAiOjE0Mzg1MDgwNDZ9NmU2NTkxNzVjNTM1MzNiNjY3YmJlYzhkNTlmYWI5ZmQ1MTA2MmEyZjczOTc4YjczNzEzNjBiMzRjMTM1ZWQ3Zjk4MDk3ZTMxYzMzNWQ0MWVhYjViNDdkYWM5NjQ3NjE4NDA1MzdhZjg0OWY3YzhkYjk3YmE4ZDQ4ZTBiNzE5ZDI=';
		$valid = $this->api->validateAndDecodeBase64($rawDataBase64);
		$this->assertEquals($valid['dataJson'], '{"user":"alpha","apiAction":"sendMessage","msg":"b43f8407be4f7f841e2a48244ae42bfad29a7e2d22f2fa3de386b392652c3c988c0b5d43da92295e2b3ff181aed71c71ee871828d41f419de75d870356512acd6ff98c29720c775afe674d11d4b1b1e63eb8146c486c43d80fd3d673b41b520b9a99e9b2b820643aa7a0a36d7be879fe3e5cb0a41c33b4eb6212fabeae78836e6714f2bc0043015b1f334388158aa9c0bbbbca92f42584b72c1da5e12f9851998238ea24392448c2c779607fd1e1ab5e636a44261e106a324dfea622a273f743","nonce":"9026b4300ac3715dfe8e4a75a8621439b727c4097ff3b4642af0d51052df95e9ea595f2b92f05431aea94bd27f3f0214e285e88069d54b235fc7fb8bcc63fa52","timestamp":1438508046}');
		$this->assertEquals($valid['mac'], '6e659175c53533b667bbec8d59fab9fd51062a2f73978b7371360b34c135ed7f98097e31c335d41eab5b47dac964761840537af849f7c8db97ba8d48e0b719d2');
		
		// Test a bad request
		$rawDataBase64 = '';
		$valid = $this->api->validateAndDecodeBase64($rawDataBase64);
		$this->assertFalse($valid);
		
		// Test a bad request
		$rawDataBase64 = false;
		$valid = $this->api->validateAndDecodeBase64($rawDataBase64);
		$this->assertFalse($valid);
		
		// Test a bad request
		$rawDataBase64 = '!"#$%&()*+-,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ ';
		$valid = $this->api->validateAndDecodeBase64($rawDataBase64);
		$this->assertFalse($valid);
		
		// Test a bad request (shorted MAC tag length)
		$rawDataBase64 = 'eyJ1c2VyIjoiYWxwaGEiLCJhcGlBY3Rpb24iOiJzZW5kTWVzc2FnZSIsIm1zZyI6ImI0M2Y4NDA3YmU0ZjdmODQxZTJhNDgyNDRhZTQyYmZhZDI5YTdlMmQyMmYyZmEzZGUzODZiMzkyNjUyYzNjOTg4YzBiNWQ0M2RhOTIyOTVlMmIzZmYxODFhZWQ3MWM3MWVlODcxODI4ZDQxZjQxOWRlNzVkODcwMzU2NTEyYWNkNmZmOThjMjk3MjBjNzc1YWZlNjc0ZDExZDRiMWIxZTYzZWI4MTQ2YzQ4NmM0M2Q4MGZkM2Q2NzNiNDFiNTIwYjlhOTllOWIyYjgyMDY0M2FhN2EwYTM2ZDdiZTg3OWZlM2U1Y2IwYTQxYzMzYjRlYjYyMTJmYWJlYWU3ODgzNmU2NzE0ZjJiYzAwNDMwMTViMWYzMzQzODgxNThhYTljMGJiYmJjYTkyZjQyNTg0YjcyYzFkYTVlMTJmOTg1MTk5ODIzOGVhMjQzOTI0NDhjMmM3Nzk2MDdmZDFlMWFiNWU2MzZhNDQyNjFlMTA2YTMyNGRmZWE2MjJhMjczZjc0MyIsIm5vbmNlIjoiOTAyNmI0MzAwYWMzNzE1ZGZlOGU0YTc1YTg2MjE0MzliNzI3YzQwOTdmZjNiNDY0MmFmMGQ1MTA1MmRmOTVlOWVhNTk1ZjJiOTJmMDU0MzFhZWE5NGJkMjdmM2YwMjE0ZTI4NWU4ODA2OWQ1NGIyMzVmYzdmYjhiY2M2M2ZhNTIiLCJ0aW1lc3RhbXAiOjE0Mzg1MDgwNDZ9NmU2NTkxNzVjNTM1MzNiNjY3YmJlYzhkNTlmYWI5ZmQ1MTA2MmEyZjczOTc4YjczNzEzNjBiMzRjMTM1ZWQ3Zjk4MDk3ZTMxYzMzNWQ0MWVhYjViNDdkYWM5NjQ3NjE4NDA1MzdhZjg0OWY3YzhkYjk3YmE4ZDQ4';
		$valid = $this->api->validateAndDecodeBase64($rawDataBase64);
		$mac = $this->api->filterNonHexadecimalChars($valid['mac']);
		$validMac = $this->api->validateDataMac($valid['dataJson'], $this->serverKey, $mac);
		$this->assertFalse($validMac);
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