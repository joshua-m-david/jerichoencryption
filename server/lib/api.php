<?php
/*
	Jericho Chat - Information-theoretically secure communications.
	Copyright (C) 2013  Joshua M. David

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation in version 3 of the License.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see [http://www.gnu.org/licenses/].
*/

/**
 * API library functions across the application
 */
class Api
{
	// Database object
	private $db;
	
	/**
	 * Constructor
	 * @param object $db Database object
	 */
	public function __construct(&$db)
	{
		$this->db = $db;
	}
	
	/**
	 * Check if the API username and password is incorrect
	 */
	public function checkApiCredentials($serverConfig)
	{
		// Make sure the request contains the username and password
		if (isset($_POST['username']) && isset($_POST['password']))
		{
			// Check credentials
			if (($_POST['username'] !== $serverConfig['username']) || ($_POST['password'] !== $serverConfig['password']))
			{
				// Send an error response to the client
				$jsonResult['statusMessage'] = 'Server username or password incorrect.';
				$this->outputJson($jsonResult);
			}
		}
		else {
			// Send error response to the client
			$jsonResult['statusMessage'] = 'Login credentials not received by server.';
			$this->outputJson($jsonResult);
		}
	}
	
	/**
	 * Test the database connection from the client
	 * @return array Response array to be sent to the client with JSON
	 */
	public function testDatabaseConnection()
	{
		// Initialise response
		$jsonResult = array(
			'success' => false,
			'statusMessage' => ''
		);

		// Get the test message from the database
		$result = $this->db->select('SELECT test_connection FROM settings WHERE test_connection = 1');

		// If the database correctly inserted the row return success
		if (($result !== false) && ($this->db->getNumRows() >= 1))
		{
			// Prepare output
			$jsonResult['success'] = true;
			$jsonResult['statusMessage'] = 'Server and database connection successful.';
		}
		else if ($result === false)
		{
			// Query failure
			$jsonResult['statusMessage'] = 'Database query failed. ' . $this->db->getErrorMsg();
		}
		else {
			// No test message in database
			$jsonResult['statusMessage'] = 'Could not find the test record in the database. ' . $this->db->getErrorMsg();
		}

		return $jsonResult;
	}
	
	/**
	 * Check if auto nuke has been initiated by the user. If it has it will send a response to the 
	 * user which will delete their local database of pads and current screen of messages.
	 */
	public function checkIfAutoNukeInitiated()
	{
		// Check if auto nuke was initiated by other user
		$query = 'SELECT auto_nuke_initiated FROM settings';
		$result = $this->db->select($query);

		if (($result !== false) && ($this->db->getNumRows() >= 1))
		{
			// If auto nuke has been initiated by the other user, the server database has already been nuked
			if ($result[0]['auto_nuke_initiated'] == '1')
			{
				// Now reset the auto nuke initiated flag on the database so they can load new pads sometime later
				$query = 'UPDATE settings SET auto_nuke_initiated = 0';
				$result = $this->db->update($query);

				// Set auto nuke parameters in the response to tell the other user to delete their local database of pads.
				// On the client this will immediately delete their local database and screen of messages.
				$jsonResult['success'] = false;
				$jsonResult['statusMessage'] = 'Auto nuke initiated.';

				// Output response
				$this->outputJson($jsonResult);
			}
		}
	}
	
	/**
	 * Sets a flag on the database so that next time the other user connects their client will delete all the pads and messages from their 
	 * machine. Also clears all encrypted messages from the server and resets the table back to original status as if no messages were sent.
	 */
	public function initiateAutoNuke()
	{
		// Update the value so the next user when they check for new messages will receive the command to nuke their local database
		$query = 'UPDATE settings SET auto_nuke_initiated = 1';
		$result = $this->db->update($query);

		// Delete the messages on the server
		$query = 'DELETE FROM messages';
		$result = $this->db->update($query);

		// Reset the auto increment value to remove how many messages have been sent so far
		$query = 'ALTER TABLE messages AUTO_INCREMENT = 1';
		$result = $this->db->update($query);

		// Prepare output
		$jsonResult = array(
			'success' => true,
			'statusMessage' => 'Messages on server successfully deleted.'
		);
		
		return $jsonResult;
	}
	
	/**
	 * Saves the message to the database. The other user can check the database and retrieve the message.
	 * @param string $to Who the message is for
	 * @param string $msg The encrypted message
	 * @param string $mac The encrypted MAC
	 * @return array The response to send to the client
	 */
	public function saveMessageToDatabase($to, $msg, $mac)
	{
		// Insert the message into the database using a prepared statement
		$query = 'INSERT INTO messages (message_to, message, message_authentication_code) VALUES (:message_to, :message, :message_authentication_code)';
		$params = array(
			'message_to' => $to,
			'message' => $msg,
			'message_authentication_code' => $mac
		);

		// Execute the query
		$result = $this->db->preparedUpdate($query, $params);
				
		// If the database correctly inserted the row return success
		if (($result !== false) && ($this->db->getNumRows() == 1))
		{
			// Message saved successfully
			$jsonResult['success'] = true;
			$jsonResult['statusMessage'] = 'Sent';
		}
		else {
			// Insert failed
			$jsonResult['success'] = false;
			$jsonResult['statusMessage'] = 'Database insert failed. ' . $this->db->getErrorMsg();
		}
		
		return $jsonResult;
	}
	
	/**
	 * Get messages from the database for a user
	 * @param string $to Get messages for this user
	 * @return array Returns an array of parameters for the response
	 */
	public function getMessagesForUser($to)
	{
		// Select the message from the database using a prepared statement
		$query = 'SELECT message_id, message, message_authentication_code FROM messages WHERE message_to = :message_to';
		$params = array(
			'message_to' => $to
		);

		// Execute the query
		$result = $this->db->preparedSelect($query, $params);
		
		// Initialise response
		$jsonResult = array(
			'success' => false,
			'statusMessage' => ''
		);
		
		// If the database correctly selected the row/s
		if (($result !== false) && ($this->db->getNumRows() >= 1))
		{
			$messages = array();
			$transactionQueries = array();

			// Format the database results into an array of messages		
			foreach($result as $val)
			{
				// Set params to send back
				$messageData = array(
					'msg' => $val['message'],
					'mac' => $val['message_authentication_code']
				);

				// Add message to array of messages
				array_push($messages, $messageData);

				// Create a new query to delete the messages on the server now that they have been retrieved
				$deleteSql = 'DELETE FROM messages WHERE message_id = :message_id';
				$params = array('message_id' => $val['message_id']);
				$query = new Query($deleteSql, $params);

				// Add to list of queries to run in the transaction
				array_push($transactionQueries, $query);
			}

			// Delete the messages from the database in a transaction
			$this->db->preparedTransaction($transactionQueries);

			// Prepare output
			$jsonResult['success'] = true;
			$jsonResult['statusMessage'] = 'Messages received successfully.';
			$jsonResult['messages'] = $messages;
		}
		else if ($result === false)
		{
			// Query failure
			$jsonResult['statusMessage'] = 'Database query failed. ' . $this->db->getErrorMsg();
		}
		else {
			// No messages for the user
			$jsonResult['statusMessage'] = 'No messages in database.';
		}
		
		return $jsonResult;
	}
	
	/**
	 * Set JSON and CORS headers to allow JavaScript on the client to make XMLHttpRequests to the server
	 * http://en.wikipedia.org/wiki/Cross-origin_resource_sharing
	 */
	public function outputJson($jsonResult)
	{
		header("Access-Control-Allow-Origin: *");
		header("Access-Control-Allow-Methods: POST");
		header('Content-Type: application/json');
		
		echo json_encode($jsonResult);
		exit;
	}
}