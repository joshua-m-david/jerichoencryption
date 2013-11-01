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
 * Statistical random number generator tests from FIPS 140-1, Section 4.11, Self-Tests.
 * In future, add more tests from:  http://www.random.org/analysis/Analysis2005.pdf
 */
var randomTests = {

	/**
	 * Test 1 - The Monobit Test
	 * 1. Count the number of ones in the 20,000 bit stream. Denote this quantity by X.
	 * 2. The test is passed if 9,654 < X < 10,346.
	 * @param {string} randomBits The random bits to test
	 * @param {int} numOfBits The number of random bits
	 * @return {bool} Returns true if the test passed or false if not
	 */
	randomnessMonobitTest: function(randomBits, numOfBits)
	{
		var x = 0;
		
		// Count the bits
		for (var i=0; i < numOfBits; i++)
		{
			var binaryDigit = randomBits.charAt(i);			
			if (binaryDigit == '1')
			{
				x += 1;
			}
		}
		
		// Evaluation
		var testResult = ((9654 < x) && (x < 10346)) ? true : false;
		
		// Log output to screen
		$('#monobitTestResults').html('The test is passed if 9654 < X < 10346. Test passed: ' + testResult + '. X = ' + x);
		
		return testResult;
	},
	
	/**
	 * Test 2 - The Poker Test
	 * 1. Divide the 20,000 bit stream into 5,000 contiguous 4 bit segments. Count and store the number of occurrences 
	 *    of each of the 16 possible 4 bit values. Denote f(i) as the number of each 4 bit value i where 0 <= i <= 15.
	 * 2. Evaluate the following:
	 *    X = (16/5000) * (SUM i=0 -> i=15 [f(i)]^2) - 5000
	 * 3. The test is passed if 1.03 < X < 57.4. 
	 * @param {string} randomBits The random bits to test
	 * @param {int} numOfBits The number of random bits
	 * @return {bool} Returns true if the test passed or false if not
	 */
	randomnessPokerTest: function(randomBits, numOfBits)
	{		
		var possibleFourBits = {};
		possibleFourBits['bits0000'] = { hex: '0', binary: '0000', count: 0 };
		possibleFourBits['bits0001'] = { hex: '1', binary: '0001', count: 0 };
		possibleFourBits['bits0010'] = { hex: '2', binary: '0010', count: 0 };
		possibleFourBits['bits0011'] = { hex: '3', binary: '0011', count: 0 };
		possibleFourBits['bits0100'] = { hex: '4', binary: '0100', count: 0 };
		possibleFourBits['bits0101'] = { hex: '5', binary: '0101', count: 0 };
		possibleFourBits['bits0110'] = { hex: '6', binary: '0110', count: 0 };
		possibleFourBits['bits0111'] = { hex: '7', binary: '0111', count: 0 };
		possibleFourBits['bits1000'] = { hex: '8', binary: '1000', count: 0 };
		possibleFourBits['bits1001'] = { hex: '9', binary: '1001', count: 0 };
		possibleFourBits['bits1010'] = { hex: 'a', binary: '1010', count: 0 };
		possibleFourBits['bits1011'] = { hex: 'b', binary: '1011', count: 0 };
		possibleFourBits['bits1100'] = { hex: 'c', binary: '1100', count: 0 };
		possibleFourBits['bits1101'] = { hex: 'd', binary: '1101', count: 0 };
		possibleFourBits['bits1110'] = { hex: 'e', binary: '1110', count: 0 };
		possibleFourBits['bits1111'] = { hex: 'f', binary: '1111', count: 0 };
		
		// Count number of occurrences for each 4 digits
		for (var i=0; i < numOfBits; i += 4)
		{
			var bits = randomBits.substr(i, 4);			
			possibleFourBits['bits' + bits].count += 1;
		}
		
		// Square the count by 2 and add to total
		var sum = 0;		
		$.each(possibleFourBits, function(index, value)
		{			
			sum += Math.pow(value.count, 2);
		});
		
		// Evaluation
		var x = (16/5000) * sum - 5000;
		var testResult = ((1.03 < x) && (x < 57.4)) ? true : false;
		
		// Log output to screen
		$('#pokerTestResults').html('The test is passed if 1.03 < X < 57.4. Test passed: ' + testResult + '. X = ' + x.toFixed(2));
		
		return testResult;
	},
	
	/**
	 * Test 3 - The Runs Test
	 * A run is defined as a maximal sequence of consecutive bits of either all ones or all
	 * zeros, which is part of the 20,000 bit sample stream. The incidences of runs (for both
	 * consecutive zeros and consecutive ones) of all lengths ( >= 1 ) in the sample stream
	 * should be counted and stored.
	 * 1. The test is passed if the number of runs that occur (of lengths 1 through 6) is each
	 * within the corresponding interval specified below. This must hold for both the zeros
	 * and ones; that is, all 12 counts must lie in the specified interval. For the purpose of this
	 * test, runs of greater than 6 are considered to be of length 6.
	 * Length of Run  Required Interval
	 * 1	2267-2733
	 * 2	1079-1421
	 * 3	502-748
	 * 4	223-402
	 * 5	90-223
	 * 6+	90-223
	 * @param {string} randomBits The random bits to test
	 * @param {int} numOfBits The number of random bits
	 * @return {bool} Returns true if the test passed or false if not
	 */
	randomnessRunsTest: function(randomBits, numOfBits)
	{
		// Initialize object to count the lengths of each run of bits
		var numOfRuns = {
			runlength0: 0,
			runlength1: 0,
			runlength2: 0,
			runlength3: 0,
			runlength4: 0,
			runlength5: 0,
			runlength6: 0
		};
		
		var lastDigit = null;
		var currentRun = 0;
		
		for (var i=0; i < numOfBits; i++)
		{
			var currentDigit = randomBits.charAt(i);
			
			// Increment current run if the bit has not changed
			if (lastDigit == currentDigit)
			{
				currentRun++;
			}
			else {
				// A run of 6 or more bits is counted under the 6+ group
				if (currentRun >= 6)
				{
					numOfRuns['runlength6'] += 1;
				}
				else {
					// Otherwise count it under it's own group
					numOfRuns['runlength' + currentRun] += 1;
				}
				
				// Reset
				currentRun = 0;
			}
			
			lastDigit = currentDigit;
		}
		
		// Tally the counts to see if they are in correct range
		var successCount = 0;		
		if ((2267 < numOfRuns['runlength1']) && (numOfRuns['runlength1'] < 2733))
		{
			successCount += 1;
		}
		if ((1079 < numOfRuns['runlength2']) && (numOfRuns['runlength2'] < 1421))
		{
			successCount += 1;
		}
		if ((502 < numOfRuns['runlength3']) && (numOfRuns['runlength3'] < 748))
		{
			successCount += 1;
		}
		if ((223 < numOfRuns['runlength4']) && (numOfRuns['runlength4'] < 402))
		{
			successCount += 1;
		}
		if ((90 < numOfRuns['runlength5']) && (numOfRuns['runlength5'] < 223))
		{
			successCount += 1;
		}
		if ((90 < numOfRuns['runlength6']) && (numOfRuns['runlength6'] < 223))
		{
			successCount += 1;
		}
				
		// Evaluation
		var testResult = (successCount == 6) ? true : false;
		
		// Log output to screen
		$('#runsTestResults').html(
			'The test is passed if the number of runs that occur (consecutive zeros or ones for lengths 1 through 6) is each within the specified interval.<br>' + 
			'Run length 1: 2267-2733. Test result: ' + numOfRuns['runlength1'] + '<br>' +
			'Run length 2: 1079-1421. Test result: ' + numOfRuns['runlength2'] + '<br>' +
			'Run length 3: 502-748. Test result: ' + numOfRuns['runlength3'] + '<br>' +
			'Run length 4: 223-402. Test result: ' + numOfRuns['runlength4'] + '<br>' +
			'Run length 5: 90-223. Test result: ' + numOfRuns['runlength5'] + '<br>' +
			'Run length 6+: 90-223. Test result: ' + numOfRuns['runlength6'] + '<br>' +
			'Tests passed: ' + testResult + '.'
		);
		
		return testResult;
	},
	
	/**
	 * Test 4 - The Long Run Test
	 * 1. A long run is defined to be a run of length 34 or more (of either zeros or ones).
	 * 2. On the sample of 20,000 bits, the test is passed if there are NO long runs.
	 * @param {string} randomBits The random bits to test
	 * @param {int} numOfBits The number of random bits
	 * @return {bool} Returns true if the test passed or false if not
	 */
	randomnessLongRunsTest: function(randomBits, numOfBits)
	{
		var lastDigit = null;
		var currentRun = 0;
		var longestRun = 0;
		
		for (var i=0; i < numOfBits; i++)
		{
			var currentDigit = randomBits.charAt(i);
			
			// If the bit hasn't changed increment the current run
			if (lastDigit == currentDigit)
			{
				currentRun++;
			}
			else {				
				// Calculate the longest run of 0's or 1's
				if (currentRun > longestRun)
				{
					longestRun = currentRun;
				}
				
				// Reset
				currentRun = 0;
			}
			
			lastDigit = currentDigit;
		}		
		
		// Evaluation
		var testResult = (longestRun >= 34) ? false : true;
		
		// Log output to screen
		$('#longRunsTestResults').html(
			'The test is passed if there are no runs of length 34 or more (of either zeros or ones).<br>' +
			'Length of longest run: ' + longestRun + '. Test passed: ' + testResult + '.'
		);
		
		return testResult;
	}
};