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

/**
 * This program will take a large amount of binary data, fire up a web worker and test 
 * each 20,000 bits of the binary string. Finally it will output the results to the page.
 * Statistical random number generator tests from:
 * FIPS 140-1, Section 4.11, Self-Tests, and 
 * FIPS 140-2, Section 4.9.1, Power-Up Tests.
 */
var randomTests = {
	
	/**
	 * Initialise the randomness tests
	 * @param {string} randomData A binary string to test
	 * @param {string} overallResultOutputId Where the overall result will be rendered after the tests are complete
	 * @param {string} overallResultLogOutputId Where the overall result logs will be rendered after the tests are complete
	 * @param {string} testVersion Which FIPS 140 version and test thresholds to use e.g. 'FIPS-140-1' or 'FIPS-140-2'
	 * @param {function} callbackFunction Function to run when the tests have completed
	 */
	init: function(randomData, overallResultOutputId, overallResultLogOutputId, testVersion, callbackFunction)
	{
		// Convert the base URL so the web worker can import the common.js script
		// Also load the JavaScript code on the HTML page which is what the worker will run
		var baseUrl = window.location.href.replace(/\\/g, '/').replace(/\/[^\/]*$/, '');
        var array = ['var baseUrl = "' + baseUrl + '";' + $('#randomness-tests-worker').html()];
		
		// Create a Blob to hold the JavaScript code and send it to the inline worker
        var blob = new Blob(array, { type: "text/javascript" });
		var blobUrl = window.URL.createObjectURL(blob);
		var worker = new Worker(blobUrl);
				
		// Send data to the worker
		worker.postMessage({
			randomData: randomData,
			testVersion: testVersion
		});
		
		// When the worker is complete
		worker.addEventListener('message', function(e)
		{						
			// Display the results (after web worker complete)
			randomTests.displayTestResults(e.data.overallResults, e.data.testVersion, overallResultOutputId, overallResultLogOutputId);
			
			// Run the callback function
			callbackFunction();
			
		}, false);
		
		// Worker error handler
		worker.addEventListener('error', function(e)
		{
			console.log('ERROR: Line ' + e.lineno + ' in ' + e.filename + ': ' + e.message);
			
		}, false);
	},
	
	/**
	 * Render the test results to the page
	 * @param {object} overallResults
	 * @param {string} testVersion Which FIPS 140 version and test thresholds to use e.g. 'FIPS-140-1' or 'FIPS-140-2'
	 * @param {string} overallResultOutputId
	 * @param {string} overallResultLogOutputId
	 */
	displayTestResults: function(overallResults, testVersion, overallResultOutputId, overallResultLogOutputId)
	{
		// Update the overall results and display the logs on the page
		$('#' + overallResultOutputId).html('<b>All ' + testVersion + ' tests passed: ' + this.colourCode(overallResults.overallResult) + '</b><br><br>');
		$('#' + overallResultLogOutputId).html(overallResults.overallResultLog);
		
		// Determine the CSS class
		var result = (overallResults.overallResult) ? 'passed' : 'failed';
		
		// Show the processed overall result in the header
		if (overallResultOutputId === 'processedOverallResult')
		{
			$('#processedTestsPass .collectionStatusBox').addClass(result).html(result);
		}
		else {
			// Show the extracted overall result in the header
			$('#extractedTestsPass .collectionStatusBox').addClass(result).html(result);
		}
		
		// Update status message on the page
		common.showProcessingMessage('Processing and randomness tests complete.', true);
	},
	
	/**
	 * Starts the tests on every 20,000 bits of random data.
	 * Returns the overall result of all the tests and a log for each test run.
	 * @param {string} randomData All the bits to test
	 * @param {string} testVersion Which FIPS 140 version and test thresholds to use e.g. 'FIPS-140-1' or 'FIPS-140-2'
	 * @returns {object} Returns object with keys: overallResult (boolean) and overallResultLog (string)
	 */
	runTests: function(randomData, testVersion)
	{
		// Get the first 20,000 bits of random data
		var requiredNumOfBits = 20000;
		var numOfBits = randomData.length;

		// If not enough data has been collected
		if (numOfBits < requiredNumOfBits)
		{
			return {
				overallResult: false,
				overallResultLog: 'Not enough entropy for random tests - ' + numOfBits + ' bits out of ' + requiredNumOfBits + ' bits required.'
			};
		}
				
		// Calculate how many sets of 20,000 bits there are
		var numOfSets = Math.floor(numOfBits / requiredNumOfBits);
				
		// Variables to hold accumulated output
		var overallResult = true;
		var overallResultLog = '';
			
		// Test each set of 20,000 bits
		for (var i=0, currentStart=0; i < numOfSets; i++, currentStart += requiredNumOfBits)
		{
			// Run the tests on each 20,000 bits
			var randomBits = randomData.substr(currentStart, requiredNumOfBits);
			var allResults = this.testRandomness(randomBits, requiredNumOfBits, testVersion);
			
			// Get an intermediary result for the current 20,000 bit block
			var currentResult = allResults.monobitTest.testResult && allResults.pokerTest.testResult && 
			                    allResults.runsTest.testResult && allResults.longRunsTest.testResult;
			
			// Get an overall result for all the tests so far
			overallResult = (overallResult && currentResult);
			
			// Build output log for this 
			overallResultLog += '<b>Test results ' + (currentStart + 1) + ' to ' + (currentStart + requiredNumOfBits) + ' bits. '
			                 +  'Tests passed: ' + this.colourCode(currentResult) + '</b><br>'
			                 +  allResults.monobitTest.testResultMsg
			                 +  allResults.pokerTest.testResultMsg
			                 +  allResults.runsTest.testResultMsg
			                 +  allResults.longRunsTest.testResultMsg + '<br>';
		}
		
		// Return results
		return {
			overallResult: overallResult,
			overallResultLog: overallResultLog
		};
	},

	/**
	 * A single bit stream of 20,000 consecutive bits of output from the generator is subjected to each of the following tests. 
	 * If any of the tests fail, then they haven't created good statistical randomness and should try again.	
	 * To do: add more randomness tests e.g. from http://www.random.org/analysis/Analysis2005.pdf
	 * @param {string} randomBits The 20,000 bits to test
	 * @param {integer} numOfBits The number of bits e.g. 20000
	 * @param {string} testVersion Which FIPS 140 version and test thresholds to use e.g. 'FIPS-140-1' or 'FIPS-140-2'
	 * @return {object} Returns an object with all the test results and keys 'monobitTest', 'pokerTest', 'runsTest', 'longRunsTest'
	 */
	testRandomness: function(randomBits, numOfBits, testVersion)
	{		
		// Run the tests
		var monobitTestResults = randomTests.randomnessMonobitTest(randomBits, numOfBits, testVersion);
		var pokerTestResults = randomTests.randomnessPokerTest(randomBits, numOfBits, testVersion);
		var runsTestResults = randomTests.randomnessRunsTest(randomBits, numOfBits, testVersion);
		var longRunsTestResults = randomTests.randomnessLongRunsTest(randomBits, numOfBits, testVersion);

		return {
			monobitTest: monobitTestResults,
			pokerTest: pokerTestResults,
			runsTest: runsTestResults,
			longRunsTest: longRunsTestResults
		};
	},

	/**
	 * Test 1 - The Monobit Test
	 * 1. Count the number of ones in the 20,000 bit stream. Denote this quantity by X.
	 * 2. The test is passed if X is between the threshold.
	 * @param {string} randomBits The random bits to test
	 * @param {int} numOfBits The number of random bits
	 * @param {string} testVersion Which FIPS 140 version and test thresholds to use e.g. 'FIPS-140-1' or 'FIPS-140-2'
	 * @return {bool} Returns true if the test passed or false if not
	 */
	randomnessMonobitTest: function(randomBits, numOfBits, testVersion)
	{
		var x = 0;
		
		// Count the bits
		for (var i=0; i < numOfBits; i++)
		{
			var binaryDigit = randomBits.charAt(i);			
			if (binaryDigit === '1')
			{
				x += 1;
			}
		}
		
		// Check which thresholds to test against
		if (testVersion === 'FIPS-140-1')
		{
			// Evaluation for FIPS-140-1
			var testResult = ((x > 9654) && (x < 10346)) ? true : false;
			var testResultMsg = '<b>The Monobit Test:</b> The test is passed if 9654 < X < 10346. '
			                  + 'Test passed: ' + this.colourCode(testResult) + '. X = ' + x + '<br>';
		}
		else {
			// Evaluation for FIPS-140-2
			var testResult = ((x > 9725) && (x < 10275)) ? true : false;
			var testResultMsg = '<b>The Monobit Test:</b> The test is passed if 9725 < X < 10275. '
			                  + 'Test passed: ' + this.colourCode(testResult) + '. X = ' + x + '<br>';
		}
		
		// Return result and log message to calling function
		return {
			testResult: testResult,
			testResultMsg: testResultMsg
		};
	},
	
	/**
	 * Test 2 - The Poker Test
	 * 1. Divide the 20,000 bit stream into 5,000 contiguous 4 bit segments. Count and store the number of occurrences 
	 *    of each of the 16 possible 4 bit values. Denote f(i) as the number of each 4 bit value i where 0 <= i <= 15.
	 * 2. Evaluate the following:
	 *    X = (16/5000) * (Sum i=0 -> i=15 [f(i)]^2) - 5000
	 * 3. The test is passed if X is between the threshold.
	 * @param {string} randomBits The random bits to test
	 * @param {int} numOfBits The number of random bits
	 * @param {string} testVersion Which FIPS 140 version and test thresholds to use e.g. 'FIPS-140-1' or 'FIPS-140-2'
	 * @return {bool} Returns true if the test passed or false if not
	 */
	randomnessPokerTest: function(randomBits, numOfBits, testVersion)
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
		for (var key in possibleFourBits)
		{		
			sum += Math.pow(possibleFourBits[key].count, 2);
		}
		
		// Result
		var x = (16/5000) * sum - 5000;
		
		// Check which thresholds to test against
		if (testVersion === 'FIPS-140-1')
		{
			// Evaluation for FIPS-140-1
			var testResult = ((x > 1.03) && (x < 57.4)) ? true : false;
			var testResultMsg = '<b>The Poker Test:</b> The test is passed if 1.03 < X < 57.4. '
							  + 'Test passed: ' + this.colourCode(testResult) + '. X = ' + x.toFixed(2) + '<br>';
		}
		else {
			// Evaluation for FIPS-140-2
			var testResult = ((x > 2.16) && (x < 46.17)) ? true : false;
			var testResultMsg = '<b>The Poker Test:</b> The test is passed if 2.16 < X < 46.17. '
							  + 'Test passed: ' + this.colourCode(testResult) + '. X = ' + x.toFixed(2) + '<br>';
		}
		
		
		// Return result and log message to calling function
		return {
			testResult: testResult,
			testResultMsg: testResultMsg
		};
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
	 * @param {string} randomBits The random bits to test
	 * @param {int} numOfBits The number of random bits
	 * @param {string} testVersion Which FIPS 140 version and test thresholds to use e.g. 'FIPS-140-1' or 'FIPS-140-2'
	 * @return {bool} Returns true if the test passed or false if not
	 */
	randomnessRunsTest: function(randomBits, numOfBits, testVersion)
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
		
		// Check which thresholds to test against
		if (testVersion === 'FIPS-140-1')
		{
			// Evaluation for FIPS-140-1
			var successCount = 0;
			if ((numOfRuns['runlength1'] >= 2267) && (numOfRuns['runlength1'] <= 2733))
			{
				successCount += 1;
			}
			if ((numOfRuns['runlength2'] >= 1079) && (numOfRuns['runlength2'] <= 1421))
			{
				successCount += 1;
			}
			if ((numOfRuns['runlength3'] >= 502) && (numOfRuns['runlength3'] <= 748))
			{
				successCount += 1;
			}
			if ((numOfRuns['runlength4'] >= 223) && (numOfRuns['runlength4'] <= 402))
			{
				successCount += 1;
			}
			if ((numOfRuns['runlength5'] >= 90) && (numOfRuns['runlength5'] <= 223))
			{
				successCount += 1;
			}
			if ((numOfRuns['runlength6'] >= 90) && (numOfRuns['runlength6'] <= 223))
			{
				successCount += 1;
			}

			// Tally the counts to see if they are in correct range
			var testResult = (successCount == 6) ? true : false;
			var testResultMsg = '<b>The Runs Test:</b> The test is passed if the number of runs that occur (consecutive zeros or ones for lengths ' +
								'1 through 6) is each within the specified interval.<br>' + 
								'Run length 1: 2267-2733. Test result: ' + numOfRuns['runlength1'] + '<br>' +
								'Run length 2: 1079-1421. Test result: ' + numOfRuns['runlength2'] + '<br>' +
								'Run length 3: 502-748. Test result: ' + numOfRuns['runlength3'] + '<br>' +
								'Run length 4: 223-402. Test result: ' + numOfRuns['runlength4'] + '<br>' +
								'Run length 5: 90-223. Test result: ' + numOfRuns['runlength5'] + '<br>' +
								'Run length 6+: 90-223. Test result: ' + numOfRuns['runlength6'] + '<br>' +
								'Tests passed: ' + this.colourCode(testResult) + '.' + '<br>';
		}
		else {
			// Evaluation for FIPS-140-2 (see Change Notice 1, Page 62)
			var successCount = 0;
			if ((numOfRuns['runlength1'] >= 2315) && (numOfRuns['runlength1'] <= 2685))
			{
				successCount += 1;
			}
			if ((numOfRuns['runlength2'] >= 1114) && (numOfRuns['runlength2'] <= 1386))
			{
				successCount += 1;
			}
			if ((numOfRuns['runlength3'] >= 527) && (numOfRuns['runlength3'] <= 723))
			{
				successCount += 1;
			}
			if ((numOfRuns['runlength4'] >= 240) && (numOfRuns['runlength4'] <= 384))
			{
				successCount += 1;
			}
			if ((numOfRuns['runlength5'] >= 103) && (numOfRuns['runlength5'] <= 209))
			{
				successCount += 1;
			}
			if ((numOfRuns['runlength6'] >= 103) && (numOfRuns['runlength6'] <= 209))
			{
				successCount += 1;
			}

			// Tally the counts to see if they are in correct range
			var testResult = (successCount == 6) ? true : false;
			var testResultMsg = '<b>The Runs Test:</b> The test is passed if the number of runs that occur (consecutive zeros or ones for lengths ' +
								'1 through 6) is each within the specified interval.<br>' + 
								'Run length 1: 2315-2685. Test result: ' + numOfRuns['runlength1'] + '<br>' +
								'Run length 2: 1114-1386. Test result: ' + numOfRuns['runlength2'] + '<br>' +
								'Run length 3: 527-723. Test result: ' + numOfRuns['runlength3'] + '<br>' +
								'Run length 4: 240-384. Test result: ' + numOfRuns['runlength4'] + '<br>' +
								'Run length 5: 103-209. Test result: ' + numOfRuns['runlength5'] + '<br>' +
								'Run length 6+: 103-209. Test result: ' + numOfRuns['runlength6'] + '<br>' +
								'Tests passed: ' + this.colourCode(testResult) + '.' + '<br>';
		}
		
		// Return result and log message to calling function
		return {
			testResult: testResult,
			testResultMsg: testResultMsg
		};
	},
	
	/**
	 * Test 4 - The Long Run Test
	 * 1. A long run is defined to be a run of length x bits or more (of either zeros or ones).
	 * 2. On the sample of 20,000 bits, the test is passed if there are NO long runs.
	 * @param {string} randomBits The random bits to test
	 * @param {int} numOfBits The number of random bits
	 * @param {string} testVersion Which FIPS 140 version and test thresholds to use e.g. 'FIPS-140-1' or 'FIPS-140-2'
	 * @return {bool} Returns true if the test passed or false if not
	 */
	randomnessLongRunsTest: function(randomBits, numOfBits, testVersion)
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
		
		// Check which thresholds to test against
		if (testVersion === 'FIPS-140-1')
		{
			// Evaluation for FIPS-140-1
			var testResult = (longestRun < 34) ? true : false;
			var testResultMsg = '<b>The Long Runs Test:</b> The test is passed if there are no runs of length 34 or more (of either zeros or ones).<br>'
			                  + 'Length of longest run: ' + longestRun + '. Test passed: ' + this.colourCode(testResult) + '.<br>';
		}
		else {
			// Evaluation for FIPS-140-2
			var testResult = (longestRun < 26) ? true : false;
			var testResultMsg = '<b>The Long Runs Test:</b> The test is passed if there are no runs of length 26 or more (of either zeros or ones).<br>'
			                  + 'Length of longest run: ' + longestRun + '. Test passed: ' + this.colourCode(testResult) + '.<br>';
		}
		
		// Return result and log message to calling function
		return {
			testResult: testResult,
			testResultMsg: testResultMsg
		};
	},
	
	/**
	 * Set the colour of the test result depending on success or failure
	 * @param {Boolean} testResult
	 * @returns {String}
	 */
	colourCode: function(testResult)
	{
		// Set the CSS class
		var colourClass = (testResult) ? 'testSuccess' : 'testFailure';
		
		// Return the colour coded text
		return '<span class="' + colourClass + '">' + testResult + '</span>';
	},
	
	/**
	 * Testing function to count the number of ones and zeros in the processed and extracted data
	 */
	countZerosAndOnesInFullImage: function()
	{
		var countZeros = 0;
		var countOnes = 0;		
		
		// Count the number of zeros and ones in the processed bits
		for (var i=0, length = trngImg.fullBinaryDataProcessed.length; i < length; i++)
		{
			if (trngImg.fullBinaryDataProcessed.charAt(i) === '0')
			{
				countZeros++;
			}
			else {
				countOnes++;
			}
		}
		
		console.log('Number of zeros in processed image: ' + countZeros);
		console.log('Number of ones in processed image: ' + countOnes);
		
		var countZeros = 0;
		var countOnes = 0;		
		
		for (var i=0, length = trngImg.fullBinaryDataExtracted.length; i < length; i++)
		{
			if (trngImg.fullBinaryDataExtracted.charAt(i) === '0')
			{
				countZeros++;
			}
			else {
				countOnes++;
			}
		}
		
		console.log('Number of zeros in extracted image: ' + countZeros);
		console.log('Number of ones in extracted image: ' + countOnes);
	}
};