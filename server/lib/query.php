<?php
/*
	Jericho Encrypted Chat
	Copyright (c) 2013 Joshua M. David

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software including without limitation the rights to use, copy, modify, 
	merge, publish, distribute, and to permit persons to whom the Software is 
	furnished to do so, subject to the following conditions:

	1) The above copyright notice and this permission notice shall be included in
	   all copies or portions of the Software.
	2) Other programs derived from the Software must be called by a different name.
	3) The Software must not be used for evil purposes.
	4) The Software may be used for free by commercial users but selling or 
	   sublicensing of the Software or derivations of it is not permitted.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
*/

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
	 * @param array $params An assoc array of named parameters for the query
	 */
	public function __construct($query = '', $params = array())
	{
		$this->query = $query;
		$this->params = $params;
	}
}