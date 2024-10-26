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


use Jericho\Database as Database;
use Jericho\Api as Api;
use PHPUnit\Framework\TestCase;


/**
 * All tests for testing the API
 */
class ApiTest extends TestCase
{
	// Import configuration from config-test.php file
	use testConfig;

	// Database and API objects
	private $db;
	private $api;

	// Test data
	private $dbConnectionSuccess = false;
	private $staticRequestData = array();

	// Main setup
	protected function setUp(): void
	{
		// Load common helper functions
		$converter = new Converter();

		// Connect to the database and initalise the API
		$this->db = new Database($this->databaseConfig);
		$this->api = new Api($this->db, $converter);

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
