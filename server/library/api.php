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


namespace Jericho;

use Jericho\CommonConstants;
use Jericho\Database;
use Jericho\Response;
use Jericho\ValidatedRequest;


/**
 * Main API functionality, accessible once authenticated
 */
class Api
{
	/**
	 * @var Database The Database object which allows database operations
	 */
	private $db;

	/**
	 * Constructor takes the initialised database object and helper objects using dependency injection
	 * @param Database $db The database object (should be connected to DB)
	 */
	public function __construct($db)
	{
		$this->db = $db;
	}

	/**
	 * Performs the requested API action
	 * @param ValidatedRequest $validatedRequest The validated request details
	 * @return Response Returns the response object
	 */
	public function performRequestedApiAction($validatedRequest)
	{
		switch ($validatedRequest->apiAction)
		{
			// Store the sent message/s in the database and mark it as from the user making the request
			case CommonConstants::API_ACTION_SEND:
				return $this->saveMessagesToDatabase($validatedRequest->fromUser, $validatedRequest->messagePackets);

			// User is requesting to download their messages, get the unread messages for this user
			case CommonConstants::API_ACTION_RECEIVE:
				return $this->getMessagesForUser($validatedRequest->fromUser);

			// User is requesting to test the server authentication and connection to the database
			case CommonConstants::API_ACTION_TEST:
				return $this->testDatabaseConnection();

			// Invalid API action
			default:
				return new Response(Response::RESPONSE_ERROR_INVALID_API_ACTION);
		}
	}

	/**
	 * Test the database connection from the client
	 * @return Response Returns a Response object
	 */
	public function testDatabaseConnection()
	{
		// Prepare query
		$query = 'SELECT test_connection '
		       . 'FROM settings '
		       . 'WHERE test_connection = :test_connection';
		$params = array(
			'test_connection' => true
		);

		// Get the test boolean value from the database
		$result = $this->db->preparedSelect($query, $params);

		// If the database query failed
		if ($result === false)
		{
			// Add specific DB error into the error response if the debug mode is turned on
			return new Response(Response::RESPONSE_ERROR_DB_QUERY_FAILED, [], $this->db->getErrorMsg());
		}

		// If there was no record returned
		if ($this->db->getNumRows() === 0)
		{
			// Return response that could not find the test record in the database
			return new Response(Response::RESPONSE_ERROR_DB_NO_TEST_RECORD);
		}

		// Return server and database connection successful
		return new Response(Response::RESPONSE_SUCCESS);
	}

	/**
	 * Saves the message/s to the database. The other user can check the database and retrieve the message.
	 * @param string $fromUser Which user the message/s are from e.g. alpha, bravo etc which is whitelisted
	 * @param array $messagePackets An array of message packets (client side encrypted and MACed messages)
	 * @return Response Returns a Response object
	 */
	public function saveMessagesToDatabase($fromUser, $messagePackets)
	{
		// Count the number of message packets
		$numOfSentMessagePackets = count($messagePackets);

		// If there are no message packets
		if ($numOfSentMessagePackets === 0)
		{
			// Return an error response because there should be at least one message
			return new Response(Response::RESPONSE_ERROR_NO_MESSAGES_SENT);
		}

		// Initialise an array to hold the queries to be run in the transaction
		$transactionQueries = [];

		// Loop through the message packets
		foreach ($messagePackets as $messagePacket)
		{
			// Create a new query to insert the message into the database
			$readByUser = 'read_by_' . $fromUser;
			$insertSql = "INSERT INTO messages (from_user, message, $readByUser) "
				   . "VALUES (:from_user, :message, :$readByUser)";
			$params = array(
				'from_user' => $fromUser,
				'message' => $messagePacket,
				$readByUser => true
			);
			$query = new TransactionQuery($insertSql, $params);

			// Add to list of queries to run in the transaction
			$transactionQueries[] = $query;
		}

		// Add the messages into the database using a transaction
		$transactionInsertResult = $this->db->preparedTransaction($transactionQueries);

		// If the transaction failed
		if ($transactionInsertResult === false)
		{
			// Add specific DB error into the error response if the debug mode is turned on
			return new Response(Response::RESPONSE_ERROR_DB_QUERY_FAILED, [], $this->db->getErrorMsg());
		}

		// If the number of messages inserted in the DB did not match the number of messages that were sent
		if ($transactionInsertResult !== $numOfSentMessagePackets)
		{
			return new Response(Response::RESPONSE_ERROR_MESSAGES_INSERTED_MISMATCH);
		}

		// If it got to here, everything succeeded so return a success response
		return new Response(Response::RESPONSE_SUCCESS);
	}

	/**
	 * Get messages from the database for a user. This also will mark those retrieved messages as read by that user so
	 * they won't be retrieved again in future requests.
	 * @param string $requestFrom Who the request is from that is asking for new messages (e.g. alpha etc from whitelist)
	 * @return Response Returns a Response object
	 */
	public function getMessagesForUser($requestFrom)
	{
		// Select the messages not sent by this user from the database
		$query = 'SELECT message_id, from_user, message '
		       . 'FROM messages '
		       . "WHERE from_user != :from_user AND read_by_$requestFrom IS NULL";
		$params = array(
			'from_user' => $requestFrom
		);

		// Execute the query using a prepared statement
		$result = $this->db->preparedSelect($query, $params);

		// If the query failed
		if ($result === false)
		{
			// Add specific DB error into the error response if the debug mode is turned on
			return new Response(Response::RESPONSE_ERROR_DB_QUERY_FAILED, [], $this->db->getErrorMsg());
		}

		// If there are no messages for the user
		if ($this->db->getNumRows() === 0)
		{
			// Just return an empty array of messages
			return new Response(Response::RESPONSE_SUCCESS_NO_MESSAGES);
		}

		// If it got to here the database found some row/s
		$userMessagePackets = [];
		$transactionQueries = [];

		// Loop through the database results
		foreach ($result as $val)
		{
			// Add message to array of messages
			$userMessagePackets[] = [
				'fromUser' => $val['from_user'],
				'messagePacket' => $val['message']
			];

			// Create a new query to update the messages on the server now that they have been retrieved by that user
			$deleteSql = 'UPDATE messages '
					   . "SET read_by_$requestFrom = :read_successfully "
					   . 'WHERE message_id = :message_id';
			$params = array(
				'read_successfully' => true,
				'message_id' => $val['message_id']
			);
			$query = new TransactionQuery($deleteSql, $params);

			// Add to list of queries to run in the transaction
			$transactionQueries[] = $query;
		}

		// Update the messages in the database using a transaction
		$transactionUpdateResult = $this->db->preparedTransaction($transactionQueries);

		// If the transaction update failed
		if ($transactionUpdateResult === false)
		{
			// Add specific DB error into the error response if the debug mode is turned on
			return new Response(Response::RESPONSE_ERROR_DB_QUERY_FAILED, [], $this->db->getErrorMsg());
		}

		// If it got to here, everything succeeded so return a success response
		return new Response(Response::RESPONSE_SUCCESS, $userMessagePackets);
	}
}
