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

use \PDO;
use \PDOException;


/**
 * Database wrapper class using PHP Data Objects (PDO). Handles connections to
 * the database, prepared insert, update and select queries and transactions.
 *
 * For debugging database results these can be used from the calling code:
 * db->getErrorMsg('lastErrorMsg')
 * db->getErrorMsg('all')
 * db->getException()
 */
class Database
{
	/**
	 * @var object Database connection config
	 */
	private $config;

	/**
	 * @var object Database connection handler
	 */
	private $conn;

	/**
	 * @var object Statement for prepared queries
	 */
	private $statement;

	/**
	 * @var int Number of rows affected/returned
	 */
	private $numRows;

	/**
	 * @var array Errors generated
	 */
	private $errors = [];

	/**
	 * @var object Exception object for full stack trace
	 */
	private $exception;


	/**
	 * Constructor
	 * @param array $config The database configuration array
	 */
	public function __construct($config)
	{
		$this->config = $config;
	}

	/**
	 * Disconnect from the database
	 */
	public function __destruct()
	{
		$this->disconnect();
	}

	/**
	 * Connect to the database with persistent connection
	 * @return boolean Whether the database connected successfully or not
	 */
	public function connect()
	{
		// If already connected, re-use the connection and return success
		if ($this->conn !== null)
		{
			return true;
		}

		// Create connection string
		$connectionString = 'pgsql:'
		                  . 'host=' . $this->config['databaseHostname'] . ';'
		                  . 'port=' . $this->config['databasePort'] . ';'
		                  . 'dbname=' . $this->config['databaseName'];

		try {
			// Connect to the database
			$this->conn = new PDO(
				$connectionString,
				$this->config['databaseUsername'],
				$this->config['databasePassword'],
				[
					PDO::ATTR_PERSISTENT => false
				]
			);
			$this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		}
		catch (PDOException $exception)
		{
			// Store the error message and exception info in the class
			$this->handleDatabaseError('Error connecting to database.', $exception);
			return false;
		}

		// Connection success
		return true;
	}

	/**
	 * Disconnect from the database
	 */
	private function disconnect()
	{
		$this->conn = null;
	}

	/**
	 * Update the database name in the config once it's known. This is needed because we don't connect to the
	 * database until the group is known and each group has its own database and own set of tables (for now).
	 * @param string $databaseName The database name
	 */
	public function updateConfigDatabaseName($databaseName)
	{
		$this->config['databaseName'] = $databaseName;
	}

	/**
	 * Prepares a query and binds parameter values to the statement before executing the query. This is used
	 * especially for cases where user input is being added to the query to protect against SQL injection.
	 * @param string $query A query e.g. 'SELECT test_connection FROM settings WHERE test_connection = :test_connection'
	 * @param array|null $params The optional parameters to be bound to the query e.g. array('test_connection' => true)
	 * @return array|false Returns an associative array if successful, an empty array if no rows were returned and
	 *                     false on error.
	 */
	public function preparedSelect($query, $params = [])
	{
		try {
			// Prepare the query
			$this->statement = $this->conn->prepare($query);
			$this->numRows = 0;

			// If failed to prepare the query, return error
			if ($this->statement === false)
			{
				$this->handleDatabaseError('Error preparing select query.');
				$this->statement = null;
				return false;
			}

			// If there are query parameters to be bound, bind them
			$binding = $this->bindParams($params);

			// If binding failed, return error
			if ($binding === false)
			{
				$this->statement->closeCursor();
				$this->handleDatabaseError('Error binding parameters in select query.');
				$this->statement = null;
				return false;
			}

			// Set to receive associative array and execute query
			$this->statement->setFetchMode(PDO::FETCH_ASSOC);
			$result = $this->statement->execute();

			// If executing the query failed, return error
			if ($result === false)
			{
				$this->statement->closeCursor();
				$this->handleDatabaseError('Error executing query and retrieving results.');
				$this->statement = null;
				return false;
			}

			$rows = array();

			// Add each row into the array
			foreach ($this->statement as $row)
			{
				$rows[] = $row;
				$this->numRows++;
			}

			// Free up the connection so that other SQL statements may be issued
			$this->statement->closeCursor();
			$this->statement = null;

			# Returns results in associative array
			return $rows;
		}
		catch (PDOException $exception)
		{
			$this->handleDatabaseError('PDO Exception error retrieving prepared select results.', $exception);
			$this->statement = null;
			return false;
		}
	}

	/**
	 * Prepares an insert or other update query binding parameter values to the statement before executing the query.
	 * This is used especially for cases where user input is being entered into the DB to protect against SQL injection.
	 * @param string $query A query e.g. 'DELETE FROM nonces' or 'INSERT INTO nonces (nonce) VALUES (:nonce)' etc
	 * @param array|null $params The parameters to be bound to the query e.g. array('nonce' => $nonce)
	 * @return int|false Returns the number of affected rows on success, or false on error
	 */
	public function preparedUpdate($query, $params = [])
	{
		try {
			// Prepare the query
			$this->statement = $this->conn->prepare($query);
			$this->numRows = 0;

			// If failed to prepare the query, return error
			if ($this->statement === false)
			{
				// Set error if prepare or executing fails
				$this->handleDatabaseError('Error while executing prepared update.');
				$this->statement = null;
				return false;
			}

			// If there are query parameters to be bound, bind them
			$binding = $this->bindParams($params);

			// If binding failed, return error
			if ($binding === false)
			{
				$this->statement->closeCursor();
				$this->handleDatabaseError('Error binding parameters in update query.');
				$this->statement = null;
				return false;
			}

			// Execute query
			$result = $this->statement->execute();

			// If executing the query failed, return error
			if ($result === false)
			{
				$this->statement->closeCursor();
				$this->handleDatabaseError('Error while executing prepared update.');
				$this->statement = null;
				return false;
			}

			// Get number of rows affected and close statement
			$this->numRows = $this->statement->rowCount();
			$this->statement->closeCursor();
			$this->statement = null;

			// Return number of rows affected
			return $this->numRows;
		}
		catch (PDOException $exception)
		{
			$this->handleDatabaseError('PDO Exception error while executing prepared update.', $exception);
			$this->statement = null;
			return false;
		}
	}

	/**
	 * Takes in an array of TransactionQuery objects to run them all in a batch transaction.
	 * @param array<TransactionQuery> $transactionQueries An array of TransactionQuery objects to be run in the transaction
	 * @return int|false Returns the number of rows affected or rolls back transaction and returns false on any error
	 */
	public function preparedTransaction($transactionQueries)
	{
		try {
			$success = true;
			$this->numRows = 0;
			$this->conn->beginTransaction();

			// Execute each query
			foreach ($transactionQueries as $transactionQuery)
			{
				// Prepare the query
				$this->statement = $this->conn->prepare($transactionQuery->query);

				// If failed to prepare the query, return error
				if ($this->statement === false)
				{
					$success = false;
					$this->statement = null;
					$this->handleDatabaseError('Error preparing query in transaction. Query: ' .$transactionQuery->query);
					break;
				}

				// If there are query parameters to be bound, bind them
				$binding = $this->bindParams($transactionQuery->params);

				// If binding failed, return error
				if ($binding === false)
				{
					$success = false;
					$this->statement->closeCursor();
					$this->statement = null;
					$this->handleDatabaseError('Error binding parameters in transaction. Query: ' .$transactionQuery->query);
					break;
				}

				// Execute query
				$result = $this->statement->execute();

				// If executing the query failed, return error
				if ($result === false)
				{
					$success = false;
					$this->statement->closeCursor();
					$this->statement = null;
					$this->handleDatabaseError('Error while executing query in transaction. Query: ' .$transactionQuery->query);
					break;
				}

				// Increment number of affected rows and close statement
				$this->numRows += $this->statement->rowCount();
				$this->statement->closeCursor();
				$this->statement = null;

			} # foreach

			// If any query failed
			if ($success === false)
			{
				// Rollback the entire transaction on failure
				$this->conn->rollback();
				$this->handleDatabaseError('Error while executing transaction.');
				return false;
			}

			// Otherwise the queries ran successfully so commit the changes to the DB now
			$this->conn->commit();

			// Return the number of affected rows
			return $this->numRows;
		}
		catch (PDOException $exception)
		{
			// Roll back the transaction on failure
			$this->conn->rollback();
			$this->statement = null;
			$this->handleDatabaseError('PDO Exception error while executing transaction.', $exception);
			return false;
		}
	}

	/**
	 * Binds parameters to a statement. Returns true on success, false on error.
	 * @param array $params An associative array of parameters to be bound to the statement e.g. array('nonce' => $nonce)
	 * @return boolean Returns true if bound successfully, false on error
	 */
	private function bindParams($params)
	{
		try {
			// If there are no parameters to be bound, succeed
			if (!is_array($params) || ($params === null) || (empty($params)))
			{
				return true;
			}

			$bindingSuccess = true;
			$nulledParams = $this->setEmptyValuesToNull($params);

			// Loop through array of params and bind them to the statement
			foreach ($nulledParams as $key => $val)
			{
				$dataType = $this->getConstantType($val);
				$bindResult = $this->statement->bindValue(":$key", $val, $dataType);

				if ($bindResult === false)
				{
					$bindingSuccess = false;
				}
			}

			return ($bindingSuccess === true) ? true : false;
		}
		catch (PDOException $e)
		{
			$this->handleDatabaseError('PDO Exception error while binding parameters to statement.', $e);
			return false;
		}
	}

	/**
	 * Returns the PDO constant data type for use in prepared statement while reading data in
	 * @param string|bool|int|null $var Pass in a variable and it checks the variable's type
	 * @return int PDO param type i.e. PDO::PARAM_BOOL, PDO::PARAM_INT, PDO::PARAM_NULL, PDO::PARAM_STR
	 */
	private function getConstantType($var)
	{
		if (is_bool($var))
		{
			return PDO::PARAM_BOOL;
		}

		if (is_int($var))
		{
			return PDO::PARAM_INT;
		}

		if (is_null($var))
		{
			return PDO::PARAM_NULL;
		}

		return PDO::PARAM_STR;			# Default
	}

	/**
	 * Set any empty string values to null so that getConstantType will work properly
	 * @param array $params
	 * @return array
	 */
	private function setEmptyValuesToNull($params)
	{
		foreach ($params as $key => $val)
		{
			$val = ($val === '') ? null : $val;
			$newParams[$key] = $val;
		}

		return $newParams;
	}

	/**
	 * Returns the primary key ID of the last row inserted into the table
	 * @return int
	 */
	public function getLastInsertedId()
	{
		return $this->conn->lastInsertId();
	}

	/**
	 * Gets the number of rows returned by the last query
	 * @return int
	 */
	public function getNumRows()
	{
		return $this->numRows;
	}

	/**
	 * Gets the PDO exception error info, updates array of DB errors
	 * @param string $customErrorMessage
	 * @param Exception $exception
	 */
	private function handleDatabaseError($customErrorMessage, $exception = null)
	{
		if ($exception !== null)
		{
			// Show exception error message
			$errorMessage = $customErrorMessage . ' ' .$exception->getMessage(). '.';
			$this->errors[] = $errorMessage;
			$this->exception = $exception;
		}
		else {
			// Show PDO error info
			$errorInfo = $this->conn->errorInfo();
			$errorMessage = $customErrorMessage . ' SQL state error code: ' . $errorInfo[0]. '. Driver error code: ' .$errorInfo[1]. '. ' .$errorInfo[2] . '.';
			$this->errors[] = $errorMessage;
			$this->exception = null;
		}
	}

	/**
	 * Gets database error messages
	 * @param string $message What error messages to get e.g. 'lastErrorMsg' (default) or 'all'
	 * @return array|string|false Returns an array of error messages if 'all' passed, or the last error message if
	 *                            'lastErrorMsg' is passed or false if there were no errors in the last DB query
	 */
	public function getErrorMsg($message = 'lastErrorMsg')
	{
		// Returns false if no errors
		if (empty($this->errors))
		{
			return false;
		}

		// Return all error messages in array
		if ($message === 'all')
		{
			return $this->errors;
		}

		// Return last error message
		if ($message === 'lastErrorMsg')
		{
			return end($this->errors);
		}
	}

	/**
	 * Returns the full exception object for stack trace, or false if no errors
	 * @return array|false
	 */
	public function getException()
	{
		return ($this->exception !== null) ? $this->exception : false;
	}
}
