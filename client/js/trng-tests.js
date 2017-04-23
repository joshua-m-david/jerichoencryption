/*!
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2017  Joshua M. David
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation in version 3 of the License.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see [http://www.gnu.org/licenses/].
 */

// Use ECMAScript 5's strict mode
'use strict';

/**
 * This program will take a large amount of binary data, fire up a web worker and test each 
 * 20,000 bits of the binary string. Finally it will output the results to the page. The 
 * statistical random number generator tests are from FIPS 140-2, Section 4.9.1, Power-Up Tests. 
 * This program uses the updated test intervals noted in Change Notice 1.
 */
var trngTests = {
	
	/**
	 * Initialise the randomness tests
	 * @param {String} randomData A binary string to test
	 * @param {Function} callbackFunction Function to run when the tests have completed
	 */
	init: function(randomData, callbackFunction)
	{
		// Setup the worker to run the randomness tests
		var worker = common.startWebWorker('randomness-tests-worker');
		
		// When the worker is complete
		worker.addEventListener('message', function(event)
		{
			// Run the callback function and pass through the test results
			callbackFunction(event.data.overallResults);
			
		}, false);
		
		// Send data to the worker
		worker.postMessage(
		{
			randomData: randomData
		});
	},
		
	/**
	 * Starts the tests on every 20,000 bits of random data.
	 * Returns the overall result of all the tests and a log for each test run.
	 * @param {String} randomData All the bits to test
	 * @returns {Object} Returns object with keys: overallResult (boolean) and overallResultLog (string)
	 */
	runTests: function(randomData)
	{
		// Get the first 20,000 bits of random data
		var requiredNumOfBits = 20000;
		var numOfBits = randomData.length;
		var testVersion = 'FIPS-140-2';

		// If not enough data has been collected
		if (numOfBits < requiredNumOfBits)
		{
			return {
				overallResult: false,
				overallResultLog: '<b>All ' + testVersion + ' tests passed: ' + this.colourCode(false) + '</b><br><br>'
								+ 'Not enough entropy for randomness tests - ' + numOfBits + ' bits out of ' + requiredNumOfBits + ' bits required.'
			};
		}
				
		// Calculate how many sets of 20,000 bits there are
		var numOfSets = Math.floor(numOfBits / requiredNumOfBits);
				
		// Variables to hold accumulated output
		var overallResult = true;
		var overallResultLog = '';
			
		// Test each set of 20,000 bits
		for (var i = 0, currentStart = 0;  i < numOfSets;  i++, currentStart += requiredNumOfBits)
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
		
		// Append header to top of results
		overallResultLog = '<b>All ' + testVersion + ' tests passed: ' + this.colourCode(overallResult) + '</b><br><br>'
		                 +  overallResultLog;
		
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
	 * @param {String} randomBits The 20,000 bits to test
	 * @param {Number} numOfBits The number of bits e.g. 20000
	 * @param {String} testVersion Which FIPS 140 version and test thresholds to use e.g. 'FIPS-140-1' or 'FIPS-140-2'
	 * @return {Object} Returns an object with all the test results and keys 'monobitTest', 'pokerTest', 'runsTest', 'longRunsTest'
	 */
	testRandomness: function(randomBits, numOfBits, testVersion)
	{		
		// Run the tests
		var monobitTestResults = trngTests.randomnessMonobitTest(randomBits, numOfBits, testVersion);
		var pokerTestResults = trngTests.randomnessPokerTest(randomBits, numOfBits, testVersion);
		var runsTestResults = trngTests.randomnessRunsTest(randomBits, numOfBits, testVersion);
		var longRunsTestResults = trngTests.randomnessLongRunsTest(randomBits, numOfBits, testVersion);

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
	 * @param {String} randomBits The random bits to test
	 * @param {Number} numOfBits The number of random bits
	 * @return {Boolean} Returns true if the test passed or false if not
	 */
	randomnessMonobitTest: function(randomBits, numOfBits)
	{
		var x = 0;
		var testResult = false;
		var testResultMsg = '';
		
		// Count the bits
		for (var i = 0; i < numOfBits; i++)
		{
			var binaryDigit = randomBits.charAt(i);			
			if (binaryDigit === '1')
			{
				x += 1;
			}
		}
		
		// Evaluation for FIPS-140-2
		testResult = ((x > 9725) && (x < 10275)) ? true : false;
		testResultMsg = '<b>The Monobit Test:</b> The test is passed if 9725 < X < 10275. '
		              + 'Test passed: ' + this.colourCode(testResult) + '. X = ' + x + '<br>';
		
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
	 * @param {String} randomBits The random bits to test
	 * @param {Number} numOfBits The number of random bits
	 * @return {Boolean} Returns true if the test passed or false if not
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
		for (var i = 0; i < numOfBits; i += 4)
		{
			var bits = randomBits.substr(i, 4);			
			possibleFourBits['bits' + bits].count += 1;
		}
		
		// Square the count and add to total
		var sum = 0;
		for (var key in possibleFourBits)
		{		
			sum += Math.pow(possibleFourBits[key].count, 2);
		}
		
		// Result
		var x = ((16 / 5000) * sum) - 5000;
		var testResult = false;
		var testResultMsg = '';
		
		// Evaluation for FIPS-140-2
		testResult = ((x > 2.16) && (x < 46.17)) ? true : false;
		testResultMsg = '<b>The Poker Test:</b> The test is passed if 2.16 < X < 46.17. '
		              + 'Test passed: ' + this.colourCode(testResult) + '. X = ' + x.toFixed(2) + '<br>';		
		
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
	 * @param {String} randomBits The random bits to test
	 * @param {Number} numOfBits The number of random bits
	 * @return {Boolean} Returns true if the test passed or false if not
	 */
	randomnessRunsTest: function(randomBits, numOfBits)
	{
		// Initialize object to count the lengths of each run of bits and whether that number of runs passed or failed
		var numOfRuns = {
			runLength0: { count: 0, passed: false },
			runLength1: { count: 0, passed: false },
			runLength2: { count: 0, passed: false },
			runLength3: { count: 0, passed: false },
			runLength4: { count: 0, passed: false },
			runLength5: { count: 0, passed: false },
			runLength6: { count: 0, passed: false }
		};
		
		var lastDigit = null;
		var currentRun = 0;
		
		for (var i = 0; i < numOfBits; i++)
		{
			var currentDigit = randomBits.charAt(i);
			
			// Increment current run if the bit has not changed
			if (lastDigit === currentDigit)
			{
				currentRun++;
			}
			else {
				// A run of 6 or more bits is counted under the 6+ group
				if (currentRun >= 6)
				{
					numOfRuns.runLength6.count += 1;
				}
				else {
					// Otherwise count it under it's own group
					numOfRuns['runLength' + currentRun].count += 1;
				}
				
				// Reset
				currentRun = 0;
			}
			
			lastDigit = currentDigit;
		}
						
		// Evaluation for FIPS-140-2 (see Change Notice 1, Page 62)
		var totalSuccessCount = 0;
		if ((numOfRuns.runLength1.count >= 2315) && (numOfRuns.runLength1.count <= 2685))
		{
			// Increment total of successful tests and set flag that this test passed
			totalSuccessCount += 1;
			numOfRuns.runLength1.passed = true;
		}
		if ((numOfRuns.runLength2.count >= 1114) && (numOfRuns.runLength2.count <= 1386))
		{
			totalSuccessCount += 1;
			numOfRuns.runLength2.passed = true;
		}
		if ((numOfRuns.runLength3.count >= 527) && (numOfRuns.runLength3.count <= 723))
		{
			totalSuccessCount += 1;
			numOfRuns.runLength3.passed = true;
		}
		if ((numOfRuns.runLength4.count >= 240) && (numOfRuns.runLength4.count <= 384))
		{
			totalSuccessCount += 1;
			numOfRuns.runLength4.passed = true;
		}
		if ((numOfRuns.runLength5.count >= 103) && (numOfRuns.runLength5.count <= 209))
		{
			totalSuccessCount += 1;
			numOfRuns.runLength5.passed = true;
		}
		if ((numOfRuns.runLength6.count >= 103) && (numOfRuns.runLength6.count <= 209))
		{
			totalSuccessCount += 1;
			numOfRuns.runLength6.passed = true;
		}

		// Tally the counts to see if they are in correct range
		var testResult = (totalSuccessCount === 6) ? true : false;
		var testResultMsg = '<b>The Runs Test:</b> The test is passed if the number of runs that occur (consecutive zeros or ones for lengths '
		                  + '1 through 6) is each within the specified interval.<br>'
		                  + 'Run length 1: 2315 - 2685. Test result: ' + numOfRuns.runLength1.count + '. Test passed: ' + this.colourCode(numOfRuns.runLength1.passed) + '.<br>'
		                  + 'Run length 2: 1114 - 1386. Test result: ' + numOfRuns.runLength2.count + '. Test passed: ' + this.colourCode(numOfRuns.runLength2.passed) + '.<br>'
		                  + 'Run length 3: 527 - 723. Test result: ' + numOfRuns.runLength3.count + '. Test passed: ' + this.colourCode(numOfRuns.runLength3.passed) + '.<br>'
		                  + 'Run length 4: 240 - 384. Test result: ' + numOfRuns.runLength4.count + '. Test passed: ' + this.colourCode(numOfRuns.runLength4.passed) + '.<br>'
		                  + 'Run length 5: 103 - 209. Test result: ' + numOfRuns.runLength5.count + '. Test passed: ' + this.colourCode(numOfRuns.runLength5.passed) + '.<br>'
		                  + 'Run length 6+: 103 - 209. Test result: ' + numOfRuns.runLength6.count + '. Test passed: ' + this.colourCode(numOfRuns.runLength6.passed) + '.<br>'
		                  + 'Tests passed: ' + this.colourCode(testResult) + '.' + '<br>';
		
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
	 * @param {String} randomBits The random bits to test
	 * @param {Number} numOfBits The number of random bits
	 * @return {Boolean} Returns true if the test passed or false if not
	 */
	randomnessLongRunsTest: function(randomBits, numOfBits)
	{
		var lastDigit = null;
		var currentRun = 0;
		var longestRun = 0;
		
		for (var i = 0; i < numOfBits; i++)
		{
			var currentDigit = randomBits.charAt(i);
			
			// If the bit hasn't changed increment the current run
			if (lastDigit === currentDigit)
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
		
		// Evaluation for FIPS-140-2
		var testResult = (longestRun < 26) ? true : false;
		var testResultMsg = '<b>The Long Runs Test:</b> The test is passed if there are no runs of length 26 or more (of either zeros or ones).<br>'
		                  + 'Length of longest run: ' + longestRun + '. Test passed: ' + this.colourCode(testResult) + '.<br>';
				
		// Return result and log message to calling function
		return {
			testResult: testResult,
			testResultMsg: testResultMsg
		};
	},
		
	/**
	 * Set the colour of the test result depending on success or failure
	 * @param {Boolean} testResult
	 * @returns {String} Returns some HTML which is green or red depending on the test result
	 */
	colourCode: function(testResult)
	{
		// Set the CSS class
		var colourClass = (testResult) ? 'testSuccess' : 'testFailure';
		
		// Return the colour coded text
		return '<span class="' + colourClass + '">' + testResult + '</span>';
	},
	
	/**
	 * Fills the HTML5 canvas with random bits, 0 bits are coloured white, 1 bits are coloured black.
	 * @param {String} canvasId The id to render the binary data into
	 * @param {String} randomBits Random binary data
	 */
	fillCanvasWithBlackWhite: function(canvasId, randomBits)
	{
		// Dynamically work out the size of the square image (x & y axis)
		var numRandomBits = randomBits.length;
		var squareRoot = Math.sqrt(numRandomBits);
		var axisLength = Math.floor(squareRoot);

		// Set new canvas dimensions
		$('#' + canvasId).prop(
		{
			width: axisLength,
			height: axisLength
		});

		// Create the canvas
		var context = document.getElementById(canvasId).getContext('2d');

		// Fill everything with white first
		context.fillStyle = "#FFF";
		context.fillRect(0, 0, axisLength, axisLength);
		context.fillStyle = "#000";

		// Loop through each binary char
		for (var x = 0; x < axisLength; x++)
		{
			for (var y = 0; y < axisLength; y++)
			{
				// If the character is a binary 1
				if (randomBits[x * axisLength + y] === '1')
				{
					// Fill that pixel with black
					context.fillRect(x, y, 1, 1);
				}
			}
		}
	},
	
	/**
	 * This fills the HTML5 canvas with random colours. It works by converting the random bits to a byte array. Then it 
	 * takes successive groups of 3 bytes, rendering them as red, green and blue colours for each pixel in the image.
	 * @param {String} canvasId The id to render the binary data into
	 * @param {String} randomBits Random binary data
	 */
	fillCanvasWithColour: function(canvasId, randomBits)
	{
		var byteArray = [];
		
		// Convert the bits to an array of byte integers
		for (var i = 0, length = randomBits.length;  i < length;  i += 8)
		{
			// Get 8 bits and convert to an integer (0 - 255)
			var byteBinary = randomBits.substr(i, 8);
			var byteInteger = common.convertBinaryToInteger(byteBinary);
			
			// Add to array
			byteArray.push(byteInteger);
		}
		
		// Dynamically work out the size of the square image (x & y axis)
		var numRandomBytes = byteArray.length;
		var numOfPixels = (numRandomBytes / 3);
		var squareRoot = Math.sqrt(numOfPixels);
		var axisLength = Math.floor(squareRoot);
		var height = axisLength;
		var width = axisLength;

		// Set new canvas dimensions
		$('#' + canvasId).prop(
		{
			height: height,
			width: width
		});
		
		// Create the canvas
		var context = document.getElementById(canvasId).getContext('2d');
		var currentIndex = 0;

		// Fill each pixel in the canvas with random colours
		for (var x = 0; x < width; x++)
		{
			for (var y = 0; y < height; y++)
			{
				// Get the RGB values
				var red = byteArray[currentIndex];
				var green = byteArray[currentIndex + 1];
				var blue = byteArray[currentIndex + 2];

				// Update index for next loop
				currentIndex += 3;

				// Convert each colour to a 2 character hex code
				var redHex = common.convertSingleByteIntegerToHex(red);
				var greenHex = common.convertSingleByteIntegerToHex(green);
				var blueHex = common.convertSingleByteIntegerToHex(blue);

				// Fill the canvas pixel with colour
				context.fillStyle = '#' + redHex + greenHex + blueHex;		// e.g. #2d89fc
				context.fillRect(x, y, 1, 1);
			}
		}
	}
};