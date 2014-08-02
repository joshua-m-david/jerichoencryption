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
 * Database wrapper class using PHP Data Objects (PDO). Handles connections to the database,
 * insert, update and select queries, transactions, prepared queries/transactions.
 */
class Database
{
	private $config;				# Database connection config
	private $conn;					# Database connection handler
	private $statement;				# Statement for prepared queries
	private $numRows;				# Number of rows affected/returned
	private $errors = array();		# Errors generated
	private $exception;				# Exception object for full stack trace

	/**
	 * Constructor
	 * @param array &$config Pass in the config array from config.php
	 */
	public function __construct(&$config)
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
	 * @param array $config
	 * @return boolean Whether the database connected successfully or not
	 */
	public function connect()
	{
		// If the socket is set, use that, otherwise use the hostname
		$hostOrSocket = ($this->config['unix_socket'] != '') ? 'unix_socket=' . $this->config['unix_socket'] : 'host=' . $this->config['hostname'];		
		$connectionString = 'mysql:' . $hostOrSocket . ';port=' . $this->config['port'] . ';dbname=' . $this->config['database'];
		
		try {
			// Connect to the database
			$this->conn = new PDO($connectionString, $this->config['username'], $this->config['password'], array(PDO::ATTR_PERSISTENT => false));
			$this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		}
		catch (PDOException $e)
		{
			// Store the error message and exception info in the class
			$this->handleDatabaseError('Error connecting to database.', $e);
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
	 * Gets a result set from the database
	 * Warning! Only use this function if there is ZERO chance of SQL injection, i.e. the query is made up of only
	 * SQL hand coded by the developer and there are no user inputs from POST, GET etc. Otherwise use preparedSelect
	 * method.
	 * @param string $query The SQL query
	 * @return array|false Returns an assoc array if successful, false on error. Returns an empty array if no rows returned
	 */
	public function select($query)
	{
		try {
			// Get database results in assoc array format and return new array if successful
			$this->statement = $this->conn->query($query);
			$this->numRows = 0;
			
			if ($this->statement !== false)
			{
				$this->statement->setFetchMode(PDO::FETCH_ASSOC);
				$rows = array();				
				
				// Add each row into the array
				foreach($this->statement as $row)
				{			
					$rows[] = $row;
					$this->numRows++;
				}
				
				$this->statement->closeCursor();	# Frees up the connection to the server so that other SQL statements may be issued
				$this->statement = null;
				return $rows;			# Returns results in array
			}
			
			$this->handleDatabaseError('Error retrieving query results.');
			$this->statement = null;
			return false;
		}
		catch (PDOException $e)
    	{
			$this->handleDatabaseError('PDO Exception retrieving query results.', $e);
			$this->statement = null;
			return false;
		}
	}
	
	/**
	 * Used for inserting, updating and deleting
	 * Warning! Only use this function if there is ZERO chance of SQL injection, i.e. the query is made up of only
	 * SQL hand coded by the developer and there are no user inputs from POST, GET etc. Otherwise use preparedUpdate
	 * method.
	 * @param string $query The SQL query
	 * @return int|false Returns # of affected rows or false on error. Will return (int) 0 if no update made.
	 */
	public function update($query)
	{
		try {
			// Run the query
			$this->numRows = $this->conn->exec($query);
			
			// If there's an error return the error message otherwise return number of rows
			if ($this->numRows !== false)
			{
				return $this->numRows;
			}
			
			$this->handleDatabaseError('Error executing query.');
			return false;
		}
		catch (PDOException $e)
    	{
			$this->handleDatabaseError('PDO Exception executing query.', $e);
			return false;
		}
	}

	/**
	 * Runs a bunch of queries as a transaction
	 * Warning: Only use this function if there is ZERO chance of SQL injection, i.e. the query is made up of only
	 * SQL hand coded by the developer and there are no user inputs from POST, GET etc. Otherwise use preparedTransaction method.
	 * @param array $query An array of query strings to be run in a batch transaction
	 * @return int|false Returns # of affected rows or false on error. Will return (int) 0 if no updates made.
	 */
	public function transaction($queries)
	{
		$success = true;
		$this->numRows = 0;
			
		try {	
			$this->conn->beginTransaction();
			
			// Execute each query
			foreach ($queries as $query)
			{
				$rowsAffected = $this->conn->exec($query);
				
				if ($rowsAffected !== false)
				{
					$this->numRows += $rowsAffected;
				}
				else {
					// There is an error so set flag to false and update error message
					$success = false;
					$this->handleDatabaseError('Error while executing query in transaction. Query: ' .$query. '.');
				}
			}
			
			// If queries ran successfully we can commit the changes to the db now
			// If not, all the rows will be rolled back
			if ($success === true)
			{
				$this->conn->commit();
				return $this->numRows;
			}
			
			// Roll back the transaction on failure
			$this->conn->rollback();
			$this->handleDatabaseError('Error while executing transaction.');
			return false;
		}
		catch (PDOException $e)
		{
			// Roll back the transaction on failure
			$this->conn->rollback();
			$this->handleDatabaseError('PDO Exception error while executing transaction.', $e);
			return false;
		}
	}
	
	/**
	 * Prepares a query and binds param values to statement.
	 * Returns an associative array if successful, false on error and an empty array if no rows returned.
	 * Used in cases where user input is being entered into the db to protect against sql injection.
	 * @param string $query
	 * @param array $params
	 * @return array|false
	 */
	public function preparedSelect($query, $params = array())
	{
		try {
			// Prepare the query
			$this->statement = $this->conn->prepare($query);
			$this->numRows = 0;

			if ($this->statement !== false)
			{			
				// Bind params, set to receive assoc array and execute statement
				$binding = $this->bindParams($params);
				
				if ($binding !== false)
				{
					$this->statement->setFetchMode(PDO::FETCH_ASSOC);			
					$result = $this->statement->execute();
					
					if ($result !== false)
					{
						$rows = array();						
							
						// Add each row into the array
						foreach($this->statement as $row)
						{			
							$rows[] = $row;
							$this->numRows++;
						}

						$this->statement->closeCursor();	# Frees up the connection so that other SQL statements may be issued
						$this->statement = null;
						return $rows;					# Returns results in array
					}
				} # if
			} # if

			// Return error if not succesful
			$this->statement->closeCursor();
			$this->handleDatabaseError('Error retrieving prepared select results.');
			$this->statement = null;
			return false;
		}
		catch (PDOException $e)
		{
			$this->handleDatabaseError('PDO Exception error retrieving prepared select results.', $e);
			$this->statement = null;
			return false;
		}
	}
	
	/**
	 * Prepares a query and binds param values to statement. 
	 * Used in cases where user input is being entered into the db to protect against SQL injection.
	 * @param string $query
	 * @param array $params
	 * @return int|false Returns false on error or number of affected rows on success.
	 */
	public function preparedUpdate($query, $params)
	{
		try {
			// Prepare the query
			$this->statement = $this->conn->prepare($query);
			$this->numRows = 0;
			
			if ($this->statement !== false)
			{
				// Bind params, set to receive assoc array and execute statement
				$binding = $this->bindParams($params);
				
				if ($binding !== false)
				{				
					// Run statement
					$result = $this->statement->execute();
					
					if ($result !== false)
					{
						// Return number of rows and close statement
						$this->numRows = $this->statement->rowCount();
						$this->statement->closeCursor();
						$this->statement = null;
						return $this->numRows;
					}
				}
			}
			
			// Set error if prepare or executing fails
			$this->statement->closeCursor();
			$this->handleDatabaseError('Error while executing prepared update.');
			$this->statement = null;
			return false;
		}
		catch (PDOException $e)
		{
			$this->handleDatabaseError('PDO Exception error while executing prepared update.', $e);
			$this->statement = null;
			return false;
		}
	}
	
	/**
	 * Takes in an array of transaction query objects to run them all in a batch transaction.
	 * Returns num of rows affected or rolls back transaction and returns false if there is an error.
	 * @param array $transactionQueries
	 * @return boolean
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
				
				if ($this->statement !== false)
				{
					// Bind params (not checked for false in case we need to run a query with no params)
					$this->bindParams($transactionQuery->params);
					
					// Run statement
					$result = $this->statement->execute();
					
					if ($result !== false)
					{
						// Return number of rows and close statement
						$this->numRows += $this->statement->rowCount();
						$this->statement->closeCursor();
						$this->statement = null;
					}
					else {
						$success = false;
						$this->handleDatabaseError('Error while executing query in transaction. Query: ' .$transactionQuery->query);
						$this->statement = null;
					}
				}
				else {
					$success = false;
					$this->handleDatabaseError('Error preparing query in transaction. Query: ' .$transactionQuery->query);
					$this->statement = null;
				}
			} # foreach
						
			// If queries ran successfully we can commit the changes to the db now
			if ($success === true)
			{
				$this->conn->commit();
				return $this->numRows;
			}
			
			// Roll back the transaction on failure
			$this->conn->rollback();
			$this->handleDatabaseError('Error while executing transaction.');
			return false;
		}
		catch (PDOException $e)
		{
			// Roll back the transaction on failure
			$this->conn->rollback();
			$this->handleDatabaseError('PDO Exception error while executing transaction.', $e);
			$this->statement = null;
			return false;
		}
	}
		
	/**
	 * Binds parameters to a statement. Returns true on success, false on error.
	 * @param array $params
	 * @return boolean
	 */
	private function bindParams($params)
	{
		try {
			if ((is_array($params)) && ($params !== null) && (!empty($params)))
			{
				$bindingSuccess = true;
				$params = $this->setEmptyValuesToNull($params);
				
				// Loop through array of params and bind them to the statement
				foreach($params as $key => $val)
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
			else {
				$this->handleDatabaseError('No parameters entered.');
				return false;
			}
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
	 * @return string PDO param type
	 */
	private function getConstantType($var)
	{
		if (is_bool($var)) { return PDO::PARAM_BOOL; }
		if (is_int($var)) {	return PDO::PARAM_INT; }
		if (is_null($var)) { return PDO::PARAM_NULL; }

		return PDO::PARAM_STR;			# Default
	}

	/**
	 * Set any empty string values to null so that getConstantType will work properly
	 * @param array $params
	 * @return array
	 */
	private function setEmptyValuesToNull($params)
	{
		foreach($params as $key => $val)
		{
			$val = ($val === '') ? null : $val;
			$newParams[$key] = $val;
		}		
		return $newParams;
	}
	
	/**
	 * Returns the ID of the last row inserted into the table
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
	 * Gets the PDO exception error info, updates array of db errors
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
	 * @param string $message What error messages to get
	 * @return array|string|false
	 */
	public function getErrorMsg($message = 'lastErrorMsg')
	{
		if (empty($this->errors))
		{
			return false;						# Returns false if no errors
		}
		if ($message == 'all')
		{
			return $this->errors;				# Return all error messages in array
		}
		if ($message == 'lastErrorMsg')
		{
			return end($this->errors);			# Return last error message
		}		
	}
	
	/**
	 * Returns the full exception object for stack trace or false if no errors
	 * @return array|false
	 */
	public function getException()
	{
		return ($this->exception !== null) ? $this->exception : false;
	}
}