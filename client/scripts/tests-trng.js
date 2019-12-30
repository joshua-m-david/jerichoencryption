/*!
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
	 * @returns {Object} Returns object with keys: allTestsPassed {Boolean} and allGroupTestResults (Object)
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
				allTestsPassed: false,
				allGroupTestResults: 'All ' + testVersion + ' tests did not pass. Not enough entropy for randomness tests - '
				                   + numOfBits + ' bits out of ' + requiredNumOfBits + ' bits required.'
			};
		}

		// Calculate how many sets of 20,000 bits there are
		var numOfSets = Math.floor(numOfBits / requiredNumOfBits);

		// Variables to hold accumulated output
		var allTestsPassed = true;
		var allGroupTestResults = [];

		// Test each set of 20,000 bits
		for (var i = 0, currentStart = 0;  i < numOfSets;  i++, currentStart += requiredNumOfBits)
		{
			// Run the tests on each 20,000 bits
			var randomBits = randomData.substr(currentStart, requiredNumOfBits);
			var allResults = this.testRandomness(randomBits, requiredNumOfBits);

			// Get an intermediary result for the current 20,000 bit block
			var currentResult = (allResults.monobitTest.testPassed && allResults.pokerTest.testPassed &&
			                    allResults.runsTest.testPassed && allResults.longRunsTest.testPassed);

			// Update the overall result for all the tests done so far
			allTestsPassed = (allTestsPassed && currentResult);

			// Store the results for this test group in an object
			var groupTestResults = {
				groupTestsPassed: currentResult,
				groupStartNum: (currentStart + 1),					// Count starting from 1 not 0
				groupEndNum: (currentStart + requiredNumOfBits),
				monobitTest: allResults.monobitTest,
				pokerTest: allResults.pokerTest,
				runsTest: allResults.runsTest,
				longRunsTest: allResults.longRunsTest
			};

			// Add the object to the overall array to be rendered later
			allGroupTestResults.push(groupTestResults);
		}

		// Return results
		return {
			allTestsPassed: allTestsPassed,
			allGroupTestResults: allGroupTestResults
		};
	},

	/**
	 * A single bit stream of 20,000 consecutive bits of output from the generator is subjected to each of the following tests.
	 * If any of the tests fail, then they haven't created good statistical randomness and should try again.
	 * To do: add more randomness tests e.g. from http://www.random.org/analysis/Analysis2005.pdf
	 * @param {String} randomBits The 20,000 bits to test
	 * @param {Number} numOfBits The number of bits e.g. 20000
	 * @returns {Object} Returns an object with all the test results and keys 'monobitTest', 'pokerTest', 'runsTest', 'longRunsTest'
	 */
	testRandomness: function(randomBits, numOfBits)
	{
		// Run the tests
		var monobitTestResults = trngTests.randomnessMonobitTest(randomBits, numOfBits);
		var pokerTestResults = trngTests.randomnessPokerTest(randomBits, numOfBits);
		var runsTestResults = trngTests.randomnessRunsTest.init(randomBits, numOfBits);
		var longRunsTestResults = trngTests.randomnessLongRunsTest(randomBits, numOfBits);

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
	 * @returns {Object} Returns object with keys:
	 *                  'testResult' which contains the result of X, and
	 *                  'testPassed' which contains true/false
	 */
	randomnessMonobitTest: function(randomBits, numOfBits)
	{
		var x = 0;
		var testPassed = false;

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
		testPassed = ((x > 9725) && (x < 10275)) ? true : false;

		// Return result and log message to calling function
		return {
			testResult: x,
			testPassed: testPassed
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
	 * @returns {Object} Returns object with keys:
	 *                  'testResult' which contains the result of X, and
	 *                  'testPassed' which contains true/false
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
		var testPassed = false;

		// Evaluation for FIPS-140-2
		testPassed = ((x > 2.16) && (x < 46.17)) ? true : false;

		// Return result and log message to calling function
		return {
			testResult: x,
			testPassed: testPassed
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
	 */
	randomnessRunsTest: {

		/**
		 * Initialise the test
		 * @param {String} randomBits The random bits to test
		 * @param {Number} numOfBits The number of random bits
		 * @returns {Object} Returns object with keys:
		 *          'runCounts' which contains an array of objects for all the run counts for 0 and 1 bits
		 *          'runCountsScored' which contains an object with the run lengths from 1 - 6 and whether the test passed
		 *          'testPassed' which contains true/false of whether all the tests passes for bits 0 and 1
		 */
		init: function(randomBits, numOfBits)
		{
			// Count runs of zeros and ones
			var runCounts = this.countRuns(randomBits, numOfBits);

			// Calculate whether the tests passed or not
			var testResult = this.scoreRuns(runCounts);

			// Return result and log message to calling function
			return {
				runCounts: runCounts,
				testResult: testResult.runCountsScored,
				testPassed: testResult.testPassed
			};
		},

		/**
		 * Count the number of runs in the 0 bits and in the 1 bits
		 * @param {String} randomBits The random bits to test
		 * @param {Number} numOfBits The number of random bits
		 * @returns {Array} Returns an array with two keys (0 and 1).
		 *                  The values are an object containing the run counts from 1 - 6
		 */
		countRuns: function(randomBits, numOfBits)
		{
			var lastBit = null;
			var currentRun = 0;
			var runCounts = [
			{
				// Run counts for '0' bits
				runLength1: { count: 0 },
				runLength2: { count: 0 },
				runLength3: { count: 0 },
				runLength4: { count: 0 },
				runLength5: { count: 0 },
				runLength6: { count: 0 }
			},
			{
				// Run counts for '1' bits
				runLength1: { count: 0 },
				runLength2: { count: 0 },
				runLength3: { count: 0 },
				runLength4: { count: 0 },
				runLength5: { count: 0 },
				runLength6: { count: 0 }
			}];

			// A function to store the final count for a finished run
			var runFinishedCountRun = function(bitType) {

				// A run of 6 or more bits is counted under the 6+ group
				if (currentRun >= 6)
				{
					runCounts[bitType].runLength6.count += 1;
				}
				else if (currentRun > 0)
				{
					// Otherwise count it under it's own group
					runCounts[bitType]['runLength' + currentRun].count += 1;
				}
			};

			// Loop through the bits
			for (var i = 0; i < numOfBits; i++)
			{
				// Get the current bit
				var currentBit = randomBits.charAt(i);

				// For the first digit we can't do anything
				if (lastBit === null)
				{
					// Set the previous bit so it can be compared against in the next loop then start the next loop
					lastBit = currentBit;
					continue;
				}

				// If this is the last bit
				else if (i === numOfBits - 1)
				{
					// Store the final run count and exit the loop
					runFinishedCountRun(lastBit);
					break;
				}

				// If the bits are the same, increment the count
				else if (lastBit === currentBit)
				{
					currentRun++;
				}

				// Otherwise if the bit is different
				else if (lastBit !== currentBit)
				{
					// Count a run for the previous bit type (0 or 1)
					runFinishedCountRun(lastBit);

					// Reset run count
					currentRun = 0;
				}

				// Set the previous bit so it can be compared against in the next loop
				lastBit = currentBit;
			}

			// Return result and log message to calling function
			return runCounts;
		},

		/**
		 * Calculate whether the run counts were within the acceptable levels
		 * @param {Array} runCounts The run counts as an array of 2 objects (each object has run counts from 1 - 6+)
		 * @returns {Object} Returns an object with two keys:
		 *          'runCountsScored' which contains an object of the run counts and whether the test passed or not
		 *          'testPassed' which contains a boolean for whether all the tests passed or not
		 */
		scoreRuns: function(runCounts)
		{
			// Initialise object to store the results
			var runCountsScored = {
				runLength1: { count: 0, passed: false },
				runLength2: { count: 0, passed: false },
				runLength3: { count: 0, passed: false },
				runLength4: { count: 0, passed: false },
				runLength5: { count: 0, passed: false },
				runLength6: { count: 0, passed: false }
			};

			// Combine the run counts for 0 bits and 1 bits
			for (var i = 1; i <= 6; i++)
			{
				runCountsScored['runLength' + i].count = runCounts[0]['runLength' + i].count + runCounts[1]['runLength' + i].count;
			}

			// Evaluation for FIPS-140-2 (see Change Notice 1, Page 62)
			var totalSuccessCount = 0;
			if ((runCountsScored.runLength1.count >= 2315) && (runCountsScored.runLength1.count <= 2685))
			{
				// Increment total of successful tests and set flag that this test passed
				totalSuccessCount += 1;
				runCountsScored.runLength1.passed = true;
			}
			if ((runCountsScored.runLength2.count >= 1114) && (runCountsScored.runLength2.count <= 1386))
			{
				totalSuccessCount += 1;
				runCountsScored.runLength2.passed = true;
			}
			if ((runCountsScored.runLength3.count >= 527) && (runCountsScored.runLength3.count <= 723))
			{
				totalSuccessCount += 1;
				runCountsScored.runLength3.passed = true;
			}
			if ((runCountsScored.runLength4.count >= 240) && (runCountsScored.runLength4.count <= 384))
			{
				totalSuccessCount += 1;
				runCountsScored.runLength4.passed = true;
			}
			if ((runCountsScored.runLength5.count >= 103) && (runCountsScored.runLength5.count <= 209))
			{
				totalSuccessCount += 1;
				runCountsScored.runLength5.passed = true;
			}
			if ((runCountsScored.runLength6.count >= 103) && (runCountsScored.runLength6.count <= 209))
			{
				totalSuccessCount += 1;
				runCountsScored.runLength6.passed = true;
			}

			// Tally the counts to see if they are in correct range
			var testPassed = (totalSuccessCount === 6) ? true : false;

			// Return object
			return {
				runCountsScored: runCountsScored,
				testPassed: testPassed
			};
		}
	},

	/**
	 * Test 4 - The Long Run Test
	 * 1. A long run is defined to be a run of length x bits or more (of either zeros or ones).
	 * 2. On the sample of 20,000 bits, the test is passed if there are NO long runs.
	 * @param {String} randomBits The random bits to test
	 * @param {Number} numOfBits The number of random bits
	 * @returns {Boolean} Returns true if the test passed or false if not
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
		var testPassed = (longestRun < 26) ? true : false;

		// Return result and log message to calling function
		return {
			testResult: longestRun,
			testPassed: testPassed
		};
	},

	/**
	 * Fills the HTML5 canvas with random bits, 0 bits are coloured white, 1 bits are coloured black.
	 * @param {String} canvasClassName The class name of the element to render the binary data into
	 * @param {String} randomBits Random binary data
	 */
	fillCanvasWithBlackWhite: function(canvasClassName, randomBits)
	{
		// Dynamically work out the size of the square image (x & y axis)
		var numRandomBits = randomBits.length;
		var squareRoot = Math.sqrt(numRandomBits);
		var axisLength = Math.floor(squareRoot);

		// Set new canvas dimensions
		query.getCached('.' + canvasClassName).prop(
		{
			width: axisLength,
			height: axisLength
		});

		// Create the canvas
		var context = query.getCached('.' + canvasClassName).get(0).getContext('2d');

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
	 * Fills the HTML5 canvas with random bits, 0 bits are coloured white, 1 bits are coloured black. It will draw the
	 * canvas to the width and height specified which is useful for comparison againt the original image.
	 * @param {String} canvasClassName The class name of the element to render the binary data into
	 * @param {String} randomBits Random binary data
	 * @param {String} canvasWidth The width of the original canvas and the width of the canvas to be filled
	 * @param {String} canvasHeight The height of the original canvas and the height of the canvas to be filled
	 */
	fillCanvasWithBlackWhiteUsingOriginalDimensions: function(canvasClassName, randomBits, canvasWidth, canvasHeight)
	{
		// Set new canvas dimensions
		query.getCached('.' + canvasClassName).prop(
		{
			width: canvasWidth,
			height: canvasHeight
		});

		// Get the canvas context
		var context = query.getCached('.' + canvasClassName)
		                  .get(0)
		                  .getContext('2d');

		// Fill everything with white first
		context.fillStyle = "#FFF";
		context.fillRect(0, 0, canvasWidth, canvasHeight);

		// Set to fill with black pixels
		context.fillStyle = "#000";

		var xCoordinate = 0;
		var yCoordinate = 0;
		var numOfRandomBits = randomBits.length;

		// Loop through each binary digit in the random data
		for (var i = 0; i < numOfRandomBits; i++)
		{
			// If end of row reached
			if (xCoordinate % canvasWidth === 0)
			{
				// Start on next horizontal canvas row
				yCoordinate++;

				// Start at the start of the horizontal canvas row again
				xCoordinate = 0;
			}

			// If the character is a binary one
			if (randomBits[i] === '1')
			{
				// Fill that pixel with black
				context.fillRect(xCoordinate, yCoordinate, 1, 1);
			}

			// Increment to fill the next pixel to the right of the current one in the next loop
			xCoordinate++;
		}
	},

	/**
	 * This fills the HTML5 canvas with random colours. It works by converting the random bits to a byte array. Then it
	 * takes successive groups of 3 bytes, rendering them as red, green and blue colours for each pixel in the image.
	 * @param {String} canvasClassName The class name of the element to render the binary data into
	 * @param {String} randomBits Random binary data
	 */
	fillCanvasWithColour: function(canvasClassName, randomBits)
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
		query.getCached('.' + canvasClassName).prop(
		{
			height: height,
			width: width
		});

		// Create the canvas
		var context = document.querySelector('.' + canvasClassName).getContext('2d');
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
				context.fillStyle = '#' + redHex + greenHex + blueHex;	// e.g. #2d89fc
				context.fillRect(x, y, 1, 1);
			}
		}
	},

	/**
	 * Creates the HTML to be displayed for all the tests
	 * @param {Object} allResults Contains 'overallResult' pass/fail boolean, and the 'overallResultLog' which is the HTML test results
	 * @returns {String} Returns the HTML
	 */
	generateTestLogOutputHtml: function(allResults)
	{
		// Variable to hold the cumulative HTML output per test group
		var outputHtml = '';

		// Check if the test failed due to not enough bits
		if ((allResults.allTestsPassed === false) && (typeof allResults.allGroupTestResults === 'string'))
		{
			// Show the overall error message instead of the individual test results
			return allResults.allGroupTestResults;
		}

		// Loop through all the test results for all groupss
		for (var i = 0; i < allResults.allGroupTestResults.length; i++)
		{
			// Clone the template for the test results and remove the template class
			var $allResultsTemplate = query.getCachedGlobal('.isRandomnessTestResultsTemplate')
			                                    .clone()
		                                        .removeClass('isRandomnessTestResultsTemplate');

			// Shorten reference for the current group
			var currentGroup = allResults.allGroupTestResults[i];

			// Fill template for start bits - end bits and the overall test result
			$allResultsTemplate.find('.jsTestGroupStartNum').text(currentGroup.groupStartNum);
			$allResultsTemplate.find('.jsTestGroupEndNum').text(currentGroup.groupEndNum);
			$allResultsTemplate.find('.jsTestGroupPassed').text(currentGroup.groupTestsPassed)
					                                      .addClass(currentGroup.groupTestsPassed ? 'isTestSuccess' : 'isTestFailure');

			// Fill template for the Monobit Test
			$allResultsTemplate.find('.jsMonobitTestResult').text(currentGroup.monobitTest.testResult);
			$allResultsTemplate.find('.jsMonobitTestPassed').text(currentGroup.monobitTest.testPassed ? 'passed' : 'failed')
			                                                .addClass(currentGroup.monobitTest.testPassed ? 'isTestSuccess' : 'isTestFailure');

			// Fill template for the Poker Test
			$allResultsTemplate.find('.jsPokerTestResult').text(currentGroup.pokerTest.testResult.toFixed(2));
			$allResultsTemplate.find('.jsPokerTestPassed').text(currentGroup.pokerTest.testPassed ? 'passed' : 'failed')
			                                              .addClass(currentGroup.pokerTest.testPassed ? 'isTestSuccess' : 'isTestFailure');

			// Fill template for the Runs Test intermediate results (run lengths 1 - 6+)
			for (var j = 1; j <= 6; j++)
			{
				// Set number of zero bit runs
				$allResultsTemplate.find('.jsRunsTestResultRunLength' + j + ' .js0BitRuns').text(
					currentGroup.runsTest.runCounts[0]['runLength' + j].count);

				// Set number of one bit runs
				$allResultsTemplate.find('.jsRunsTestResultRunLength' + j + ' .js1BitRuns').text(
					currentGroup.runsTest.runCounts[1]['runLength' + j].count);

				// Set total number of runs (zero and one bits)
				$allResultsTemplate.find('.jsRunsTestResultRunLength' + j + ' .jsTotalRuns').text(
					currentGroup.runsTest.testResult['runLength' + j].count);

				// Set passed or failed text
				$allResultsTemplate.find('.jsRunsTestPassedRunLength' + j).text(
					currentGroup.runsTest.testResult['runLength' + j].passed ? 'passed' : 'failed');

				// Set colour class for passed or failed
				$allResultsTemplate.find('.jsRunsTestPassedRunLength' + j).addClass(
					currentGroup.runsTest.testResult['runLength' + j].passed ? 'isTestSuccess' : 'isTestFailure');
			}

			// Fill template for the Long Runs Test
			$allResultsTemplate.find('.jsLongRunsTestResult').text(currentGroup.longRunsTest.testResult);
			$allResultsTemplate.find('.jsLongRunsTestPassed').text(currentGroup.longRunsTest.testPassed ? 'passed' : 'failed')
			                                                 .addClass(currentGroup.longRunsTest.testPassed ? 'isTestSuccess' : 'isTestFailure');

			// Add to the HTML output
			outputHtml += $allResultsTemplate.prop('outerHTML');
		}

		return outputHtml;
	}
};
