/*!
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

// Import scripts to be used
importScripts('tests-randomness.js');

// Get data from the process which started the worker thread
self.addEventListener('message', function(e)
{
	// Run the tests on all the random data (inside web worker)
	var overallResults = randomTests.runTests(e.data.randomData, e.data.testVersion);
	
	// Send the processed data back to the main thread
	self.postMessage({
		overallResults: overallResults,
		testVersion: e.data.testVersion
	});
	
}, false);