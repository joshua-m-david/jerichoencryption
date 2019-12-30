<?php
/**
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2019  Joshua M. David
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation in version 3 of the License.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see [http://www.gnu.org/licenses/].
 */


namespace Jericho;


/**
 * Object to store data about a prepared transaction. Includes the query that will be executed
 * and the parameters to be bound.
 */
class Query
{
	public $query;
	public $params;

	/**
	 * Constructor
	 * @param string $query The query to run in a transaction
	 * @param array $params An associative array of named parameters for the query
	 */
	public function __construct($query = '', $params = array())
	{
		$this->query = $query;
		$this->params = $params;
	}
}
