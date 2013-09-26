/*
	Jericho Encrypted Chat
	Copyright (c) 2013 Joshua M. David

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software, design and associated documentation files (the "Software"), 
	to deal in the Software including without limitation the rights to use, copy, 
	modify, merge, publish, distribute, and to permit persons to whom the Software 
	is furnished to do so, subject to the following conditions:

	1) The above copyright notice and this permission notice shall be included in
	   all copies of the Software and any other software that utilises part or all
	   of the Software (the "Derived Software").
	2) Neither the Software nor any Derived Software may be sold, published, 
	   distributed or otherwise dealt with for financial gain without the express
	   consent of the copyright holder.
	3) Derived Software must not use the same name as the Software.
	4) The Software and Derived Software must not be used for evil purposes.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
*/

/**
 * On DOM load
 */
$(document).ready(function()
{
	// Start the database
	db.initialiseLocalDatabase();

	// If user does a normal F5 refresh it doesn't disable the buttons if they were 
	// enabled previously (in Firefox), so disable them on page load.
	$('#btnStartCollectingEntropy').attr('disabled', true);
	$('#btnStopCollectingEntropy').attr('disabled', true);
	$('#btnProcessAllEntropy').attr('disabled', true);
	$('#btnTestRandomData').attr('disabled', true);
	$('#btnShowRandomData').attr('disabled', true);
	$('#btnViewBitmap').attr('disabled', true);
	$('#btnOpenExportPadsSettings').attr('disabled', true);

	/* --------------------------------------- */
	/*	Entropy Collection Settings Dialog
	/* --------------------------------------- */

	// Toggle collecting Web Crypto API entropy
	$('#enableWebCryptoApiEntropyCollection').change(function()
	{
		rng.includeWebCryptoApiEntropy = !rng.includeWebCryptoApiEntropy;

		if (rng.includeWebCryptoApiEntropy)
		{
			$('#webCryptoApiEntropyLengthLabel').show();
			$('#webCryptoApiEntropyLength').show();
		}
		else {
			$('#webCryptoApiEntropyLengthLabel').hide();
			$('#webCryptoApiEntropyLength').hide();
		}
	});

	// Configure button to open the Entropy Collection Settings dialog
	$('#btnOpenEntropyCollectionSettings').click(function()
	{
		$('#entropyCollectionSettings').dialog('open');

		// Enable the start collection button
		$('#btnStartCollectingEntropy').attr('disabled', false);
	});

	// Configure button to close the Entropy Collection Settings dialog
	$('#btnCloseEntropyCollectionSettings').click(function()
	{
		$('#entropyCollectionSettings').dialog('close');
	});

	// Configure entropy collection settings dialog
	$('#entropyCollectionSettings').dialog(
	{
		autoOpen: false,
		width: '730px'
	});

	// Initialise Web Crypto API interval slider
	$("#webCryptoApiIntervalSliderAmount").html(rng.webCryptoApiEntropyCollectionInterval + ' ms');
	$('#webCryptoApiIntervalSlider').slider(
	{
		min: 50,
		max: 3000,
		value: rng.webCryptoApiEntropyCollectionInterval,
		slide: function(event, ui)
		{
			rng.webCryptoApiEntropyCollectionInterval = ui.value;
			$("#webCryptoApiIntervalSliderAmount").html(ui.value + ' ms');
		}
	});

	// Initialise mouse movement interval slider
	$("#mouseMovementIntervalSliderAmount").html(rng.mouseMovementEntropyCollectionInterval + ' mouse movements');
	$('#mouseMovementIntervalSlider').slider(
	{
		min: 1,
		max: 10,
		value: rng.mouseMovementEntropyCollectionInterval,
		slide: function(event, ui)
		{
			rng.mouseMovementEntropyCollectionInterval = ui.value;
			$("#mouseMovementIntervalSliderAmount").html(ui.value + ' mouse movements');
		}
	});

	// Initialise mouse scroll interval slider
	$("#mouseScrollIntervalSliderAmount").html(rng.mouseScrollEntropyCollectionInterval + ' ms');
	$('#mouseScrollIntervalSlider').slider(
	{
		min: 700,
		max: 3000,
		value: rng.mouseScrollEntropyCollectionInterval,
		slide: function(event, ui)
		{
			rng.mouseScrollEntropyCollectionInterval = ui.value;
			$("#mouseScrollIntervalSliderAmount").html(ui.value + ' ms');
		}
	});

	// Initialise keypress interval slider
	$("#keypressIntervalSliderAmount").html(rng.keypressEntropyCollectionInterval + ' keypresses');
	$('#keypressIntervalSlider').slider(
	{
		min: 1,
		max: 10,
		value: rng.keypressEntropyCollectionInterval,
		slide: function(event, ui)
		{
			rng.keypressEntropyCollectionInterval = ui.value;
			$("#keypressIntervalSliderAmount").html(ui.value + ' keypresses');
		}
	});

	// Initialise number of times to shuffle the entropy pool slider
	$("#numTimesToShuffleEntropyPoolAmount").html(rng.numTimesToShufflePool + ' time');
	$('#numTimesToShuffleEntropyPool').slider(
	{
		min: 1,
		max: 3,
		step: 1,
		value: rng.numTimesToShufflePool,
		slide: function(event, ui)
		{
			// Set values
			rng.numTimesToShufflePool = ui.value;
			var wording = (rng.numTimesToShufflePool == 1) ? ' time' : ' times';			

			// Update the text next to the slider with value
			$("#numTimesToShuffleEntropyPoolAmount").html(rng.numTimesToShufflePool + wording);
		}
	});
	
	// Initialise bytes to feed into hash slider
	$("#bytesToFeedIntoHashSliderAmount").html(rng.numBytesToFeedIntoHash + ' Bytes (' + (rng.numBytesToFeedIntoHash * 8) + ' bits)');
	$('#bytesToFeedIntoHashSlider').slider(
	{
		min: 128,								// Min 128 Bytes
		max: 256,								// Max 256 Bytes
		step: 8,								// Increment in 32 Byte (256 bit) increments
		value: rng.numBytesToFeedIntoHash,
		slide: function(event, ui)
		{
			// Set values
			rng.numBytesToFeedIntoHash = ui.value;
			var numBytesSelected = ui.value;
			var numBitsSelected = numBytesSelected * 8;

			// Update the text next to the slider with value
			$("#bytesToFeedIntoHashSliderAmount").html(numBytesSelected + ' Bytes (' + numBitsSelected + ' bits)');
		}
	});

	/* --------------------------------------- */
	/*	Start and stop entropy collection
	/* --------------------------------------- */

	// Button to start entropy collection
	$('#btnStartCollectingEntropy').click(function()
	{
		// Disable the buttons to prevent accidental double clicks and runaway interval timers
		$(this).attr('disabled', true);
		$('#btnOpenEntropyCollectionSettings').attr('disabled', true);

		// Show instructions and start collecting
		common.showStatus('success', 'Entropy collection started, start by clicking in random places, moving the mouse randomly around the window, use scroll wheel and randomly type on the keyboard.');
		rng.startCollectingEntropy();

		// Enable the stop collection button
		$('#btnStopCollectingEntropy').attr('disabled', false);
	});

	// Stop collecting
	$('#btnStopCollectingEntropy').click(function()
	{
		rng.stopCollectingEntropy();

		// Re-enable the Collection settings, Start collecting and Process entropy buttons
		$('#btnOpenEntropyCollectionSettings').attr('disabled', false);
		$('#btnStartCollectingEntropy').attr('disabled', false);
		$('#btnProcessAllEntropy').attr('disabled', false);
	});

	/* --------------------------------------- */
	/*	Process entropy functions
	/* --------------------------------------- */

	// Button to process the entropy
	$('#btnProcessAllEntropy').click(function()
	{
		// Show in progress message
		common.showStatus('success', 'Processing entropy...');

		// This method kicks off a process to combine entropy, shuffle it, hash it, 
		// shuffle it again, then split the data into separate one-time pads
		rng.combineAllEntropyPools();

		// Enable the export button
		$('#btnOpenExportPadsSettings').attr('disabled', false);
	});

	/* --------------------------------------- */
	/*	Testing functions
	/* --------------------------------------- */

	// Run statistical tests on the random data
	$('#btnTestRandomData').click(function()
	{
		rng.testRandomness();
	});

	// Show all raw random data, combined data and the generated pads
	$('#btnShowRandomData').click(function()
	{
		// Combine array data into a string
		var webCryptoEntropy = rng.webCryptoApiEntropy.join(' ');
		var mouseMoveEntropy = rng.mouseMovementEntropy.join(' ');
		var mouseClickEntropy = rng.mouseClickEntropy.join(' ');
		var mouseClickTimeEntropy = rng.mouseClickTimeEntropy.join(' ');
		var mouseScrollEntropy = rng.mouseScrollEntropy.join(' ');
		var keypressEntropy = rng.keypressEntropy.join(' ');
		var keypressTimeEntropy = rng.keypressTimeEntropy.join(' ');
		var combinedAndShuffledEntropy = rng.combinedEntropyPool.join(' ');
		var hashedAndShuffledEntropy = rng.hashedAndShuffledEntropyString;

		// Display on the page
		$('#webCryptoEntropy').html(webCryptoEntropy);
		$('#mouseMoveEntropy').html(mouseMoveEntropy);
		$('#mouseClickEntropy').html(mouseClickEntropy);
		$('#mouseClickTimeEntropy').html(mouseClickTimeEntropy);
		$('#mouseScrollEntropy').html(mouseScrollEntropy);
		$('#keypressEntropy').html(keypressEntropy);
		$('#keypressTimeEntropy').html(keypressTimeEntropy);
		$('#combinedAndShuffledEntropy').html(combinedAndShuffledEntropy);
		$('#hashedAndShuffledEntropy').html(hashedAndShuffledEntropy);

		// Output pads to screen to view
		var padHtml = '';
		var totalPads = db.padData.pads.length;
		for (var i=0; i < totalPads; i++)
		{
			padHtml += '<div class="pad">' + db.padData.pads[i].pad + '</div>';
		}
		padHtml += 'Total: ' + totalPads;
		$('#allPads').html(padHtml);

		// Show the data
		$('.collectedEntropyDisplay').show();
	});

	// Create bitmap from random data collected
	$('#btnViewBitmap').click(function()
	{
		rng.viewRandomDataAsBitmap();
	});

	/* --------------------------------------- */
	/*	Export Pads Settings Dialog
	/* --------------------------------------- */

	// Configure button to open entropy collection settings dialog
	$('#btnOpenExportPadsSettings').click(function()
	{
		$('#exportPadsSettings').dialog('open');
	});

	// Configure entropy collection settings dialog
	$('#exportPadsSettings').dialog({
		autoOpen: false,
		width: 'auto'
	});

	// Export the pads
	$('#btnExportPads').click(function()
	{
		// Get values from page
		var exportMethod = $('.exportMethod:checked').val();
		var user = $('.exportForUser:checked').val();					
		var serverAddressAndPort = $('#serverAddressAndPort').val();
		var serverUsername = $('#serverUsername').val();
		var serverPassword = $('#serverPassword').val();

		// Export to text, file or database
		common.preparePadsForExport(exportMethod, user, serverAddressAndPort, serverUsername, serverPassword);
	});

	// Test server connection
	$('#testServerConnection').click(function()
	{
		var serverAddressAndPort = $('#serverAddressAndPort').val();
		var serverUsername = $('#serverUsername').val();
		var serverPassword = $('#serverPassword').val();

		common.testServerConnection(serverAddressAndPort, serverUsername, serverPassword);
	});
});

/**
 * Entropy collection and random number generator functions
 */
var rng = {
	
	// Stores what time the program started in milliseconds
	entropyCollectionStartTime: null,
		
	// Flag to use random numbers from the Web Crypto API in the combined entropy pool.
	// By default it will be set to off, users can enable if they are on linux and using a hardware RNG.
	// The Web Crypto API will still be used to shuffle the combined entropy pool and hashed entropy.
	includeWebCryptoApiEntropy: false,
	
	// Interval ID, used to stop collecting the Web Crypto API entropy
	collectionIntervalId: null,
	
	// Collection sampling intervals (sampling the random data from sources). Higher numbers 
	// will allow for slower (and likely more random) collection. These are the defaults and
	// the user will set the variables using sliders before starting collection of entropy.
	webCryptoApiEntropyCollectionInterval: 300,			// Collect every x milliseconds (range 50 - 3000)
	mouseMovementEntropyCollectionInterval: 2,			// Collect every x number of mouse movements (range 1 - 10)
	mouseScrollEntropyCollectionInterval: 1000,			// Collect every x milliseconds (range 700 - 3000)
	keypressEntropyCollectionInterval: 2,				// Collect every x number of key presses (range 1 - 10)
	
	// The number of bytes of raw entropy to feed into the hashing algorithm at a time as it is looping through all the entropy and processing it. 
	// This basically functions as an entropy extractor. NIST Special Publication 800-90B Section 6.4.2 recommends several extractors, including the SHA 
	// hash family and states that if the amount of entropy input is twice (or more) the number of bits output from them, that output can be considered 
	// to have full entropy. The hash algorithms used are 512 bit, so at a minimum we would want to gather 128 bytes (1024 bits) of entropy at 
	// a time and feed it into the hash, then the hash output would give us 512 bits we can use for a one-time pad. The amount of entropy to feed in 
	// can be decided by the user and they can increase it using the slider if they really want to.
	numBytesToFeedIntoHash: 128,
	
	// This sets the number of times the entropy pool will be shuffled. This is configurable by slider.
	numTimesToShufflePool: 1,	
	
	// Collection variables for mouse movement collection
	prevMouseMoveCoordinates: { x: null, y: null },
	mouseMovementCount: 0,
	
	// Collection variables for mouse click collection
	prevMouseClickCoordinates: { x: null, y: null },
	prevMouseClickTime: null,
	
	// Collection variables for mouse scrolling
	currentScrollAmount: 0,
	prevMouseScrollAmount: 0,
	prevMouseScrollTime: null,
	
	// Collection variables for keypress collection
	keypressCount: 0,
	prevKeypressCharCode: null,
	prevKeypressTime: null,
	prevKeypressTimeDifference: null,
			
	// Stores all random number entropy
	webCryptoApiEntropy: [],				// HTML5 Web Crypto API getRandomValues
	mouseMovementEntropy: [],				// Random mouse movements
	mouseClickEntropy: [],					// Area or distance between mouse clicks
	mouseClickTimeEntropy: [],				// Time between mouse clicks
	mouseScrollEntropy: [],					// Difference between scroll movements
	keypressEntropy: [],					// ASCII character codes from keypresses
	keypressTimeEntropy: [],				// Time between keypresses
	combinedEntropyPool: [],				// Combination of all entropy which is shuffled
	
	// Combination of all combined, hashed and shuffled entropy
	hashedAndShuffledEntropyString: null,
	
	// Stores the length of the the entropy for quick display on the page
	webCryptoApiEntropyLength: 0,
	mouseMovementEntropyLength: 0,
	mouseClickEntropyLength: 0,
	mouseClickTimeEntropyLength: 0,
	mouseScrollEntropyLength: 0,
	keypressEntropyLength: 0,
	keypressTimeEntropyLength: 0,
	totalEntropyLength: 0,
	
		
	/**
	 * Start collecting entropy from all sources 
	 */
	startCollectingEntropy: function()
	{
		// Initialisations
		rng.setEntropyCollectionStartTime();
		rng.collectWebCryptoApiEntropy();
		
		// Add event handlers for mouse move, mouse click, mouse scroll and keypress
		$(document).on(
		{
			// While collecting they can push any button on keyboard
			'mousemove': rng.collectMouseMovementEntropy,
			'click': rng.collectMouseClickEntropy,
			'mousewheel DOMMouseScroll': rng.collectMouseScrollEntropy,
			'keydown': rng.collectKeypressEntropy
		});
	},
	
	/**
	 * Stop collecting entropy from all sources
	 */
	stopCollectingEntropy: function()
	{
		// Stop collecting Web Crypto API entropy
		window.clearInterval(rng.collectionIntervalId);
		
		// Stop collecting mouse movement, mouse clicks, keypress and mouse scroll entropy
		$(document).off('mousemove');
		$(document).off('click');
		$(document).off('DOMMouseScroll mousewheel');	
		$(document).off('keydown');			
	},	
	
	/**
	 * Sets the current start time of the program in milliseconds so it can be used later
	 */
	setEntropyCollectionStartTime: function()
	{
		var date = new Date();
		var timeInMilliseconds = date.getTime();		
		this.entropyCollectionStartTime = timeInMilliseconds;	
	},
	
	/**
	 * Store the entropy in the correct pool and update the display at the same time
	 * @param {string} entropyPoolName The name of the entropy pool
	 * @param {string|number} value The value to add to the pool
	 */
	storeInPool: function(entropyPoolName, value)
	{
		// Convert to string for consistency and to determine the length
		value = value.toString();
		
		// Calculate the new number of bytes in the entropy pool
		var sizeOfEntropyInPool = rng[entropyPoolName + 'Length'] + value.length;
		var totalEntropyLength = rng['totalEntropyLength'] + value.length;
		
		// Calculate how many messages could roughly be sent/received with this much entropy. If there isn't 
		// enough entropy left to feed into the last hash at the end, the remainder raw entropy won't be used.
		var hashAlgorithmOutputBytes = 64;															// SHA2, SHA3 & Whirlpool all output 512 bits
		var extractedBytesPercentage = hashAlgorithmOutputBytes / this.numBytesToFeedIntoHash;
		var totalNumOfMessages = ((totalEntropyLength * extractedBytesPercentage) / common.totalPadSize);
		totalNumOfMessages = Math.floor(totalNumOfMessages);
				
		// Update the size of the pool and amount of entropy overall
		rng[entropyPoolName + 'Length'] = sizeOfEntropyInPool;
		rng['totalEntropyLength'] = totalEntropyLength;
		
		// Add the entropy to the relevant pool
		rng[entropyPoolName].push(value);
		
		// Update display boxes on page
		$('#' + entropyPoolName + 'Length div').html(sizeOfEntropyInPool);
		$('#totalEntropyLength div').html(totalEntropyLength);
		$('#totalNumOfMessages div').html(totalNumOfMessages);
	},
	
	/**
	 * Gets secure random numbers from the HTML5 Web Crypto API. This uses the operating system's entropy source e.g. /dev/urandom.
	 * We can't trust this source to be "true random" data so collect only so much of it and blend it in with other pools.
	 */
	collectWebCryptoApiEntropy: function()
	{
		// Only include Web Crypto API entropy if specifically enabled by user
		if (this.includeWebCryptoApiEntropy)
		{
			// Set an interval timer to collect a random number from the Web Crypto API every x milliseconds
			rng.collectionIntervalId = window.setInterval(function()
			{
				try {					
					// Collect a random number
					var byteArray = new Uint32Array(1);
					window.crypto.getRandomValues(byteArray);
					var randomNum = byteArray[0];

					// Append array of random values into the pool
					rng.storeInPool('webCryptoApiEntropy', randomNum);
				}
				catch (e)
				{
					// Catch QuotaExceededError but don't do anything, the next interval collection should continue to get random numbers
				}
				
				return true;

			}, this.webCryptoApiEntropyCollectionInterval);
		}
	},
		
	/**
	 * Collects x and y coordinates when mouse is moved and stores in entropy pool
	 * @param {event} e The event object
	 */
	collectMouseMovementEntropy: function(e)
	{		
		// Get the current mouse coordinates
		var x = e.pageX;
		var y = e.pageY;

		// Make sure the previous co-ordinates are not the same and only collect every x number of movements (set by user)
		if ((rng.prevMouseMoveCoordinates.x !== x) && (rng.prevMouseMoveCoordinates.y !== y) && (rng.mouseMovementCount % rng.mouseMovementEntropyCollectionInterval == 0))
		{
			// Concatenate the mouse coordinates to make a unique random number
			var newRandomNum = x.toString() + y.toString();

			// Store the new number in the entropy pool
			rng.storeInPool('mouseMovementEntropy', newRandomNum);

			// Set the current coordinates to the previous coordinates variable, now that they've been processed
			rng.prevMouseMoveCoordinates.x = x;
			rng.prevMouseMoveCoordinates.y = y;
		}

		rng.mouseMovementCount++;
	},
		
	/**
	 * Collects all mouse click entropy and stores into various pools:
	 * 1) On each click it collects the distance in pixels between the previous and current mouse click.
	 * 2) On each click it also collects the time between the mouse clicks.
	 * @param {event} e The event object
	 */
	collectMouseClickEntropy: function(e)
	{		
		var currentX = e.pageX;
		var currentY = e.pageY;

		// Make sure the previous co-ordinates have been set with at least the first click, and that they are not the same as the previous click
		if ((rng.prevMouseClickCoordinates.x !== null) && (rng.prevMouseClickCoordinates.x !== currentX) && (rng.prevMouseClickCoordinates.y !== currentY))
		{
			// Collect the mouse distance
			rng.collectMouseClickDistanceEntropy(rng.prevMouseClickCoordinates.x, rng.prevMouseClickCoordinates.y, currentX, currentY);
		}

		// Set the current coordinates to the previous coordinates variable, now that they've been processed
		rng.prevMouseClickCoordinates.x = currentX;
		rng.prevMouseClickCoordinates.y = currentY;

		// Collect the time between mouse clicks
		rng.collectMouseClickTimeEntropy();
	},
		
	/**
	 * If a user clicks once, then clicks again we can work out the distance in pixels based on those two sets 
	 * of coordinates. This number is stored in a separate entropy pool and mixed in with the other entropy pools later
	 * @param {number} previousX
	 * @param {number} previousY
	 * @param {number} currentX
	 * @param {number} currentY
	 */
	collectMouseClickDistanceEntropy: function(previousX, previousY, currentX, currentY)
	{
		// Calculate the length on each axis between each axis, giving us two sides of a triangle e.g. _| or |_ etc
		var lengthX = Math.abs(previousX - currentX);
		var lengthY = Math.abs(previousY - currentY);
		
		// Calculate the distance between mouse clicks in pixels using Pythagoras' theorem (a^2 + b^2 = c^2)
		var distanceSquared = Math.pow(lengthX, 2) + Math.pow(lengthY, 2);
		var distance = Math.sqrt(distanceSquared);
		distance = Math.round(distance);
		
		// Store the distance in the entropy pool
		rng.storeInPool('mouseClickEntropy', distance);
	},
	
	/**
	 * Collects the time in milliseconds between the user's mouse clicks
	 */
	collectMouseClickTimeEntropy: function()
	{
		// If the previous click time hasn't been set, then initialise it to the program's start time
		// Then when the first click occurs it will be the number of milliseconds since program start
		if (rng.prevMouseClickTime === null)
		{
			rng.prevMouseClickTime = rng.entropyCollectionStartTime;
		}

		// Get the current time in milliseconds and calculate time between the last click and the current one
		var date = new Date();
		var timeInMilliseconds = date.getTime();
		var timeDifference = timeInMilliseconds - rng.prevMouseClickTime;

		// Make sure it has at least a value and is not the first click which starts the collection
		if (timeDifference > 1)
		{
			// Store the time difference between clicks in the entropy pool
			rng.storeInPool('mouseClickTimeEntropy', timeDifference);
		}

		// Set the current time to the previous, now that it has been processed
		rng.prevMouseClickTime = timeInMilliseconds;
	},
		
	/**
	 * Collects the current mouse scroll position
	 * @param {event} e The event object
	 */
	collectMouseScrollEntropy: function(e)
	{
		// If the previous scroll time hasn't been set, then initialise it to the program's start time
		// Then when the first scroll occurs it will be the number of milliseconds s0ince program start		
		if (rng.prevMouseScrollTime === null)
		{
			rng.prevMouseScrollTime = rng.entropyCollectionStartTime;
		}
		
		// Get the current scroll amount whether forwards or backwards and add that to the total
		var currentDelta = rng.extractMouseWheelDelta(e);
		rng.currentScrollAmount += Math.abs(currentDelta);

		// Get the time difference between now and the previous scroll time
		var date = new Date();
		var timeInMilliseconds = date.getTime();
		var timeDifference = timeInMilliseconds - rng.prevMouseScrollTime;

		// Capture every x milliseconds which is set by the user
		if (timeDifference >= rng.mouseScrollEntropyCollectionInterval)
		{
			// If the previous scroll amount collected is different to the current amount being collected then keep it, otherwise throw it away
			if ((rng.prevMouseScrollAmount != rng.currentScrollAmount) && (rng.currentScrollAmount != 0))
			{
				// Add to entropy
				rng.storeInPool('mouseScrollEntropy', rng.currentScrollAmount);
				rng.prevMouseScrollAmount = rng.currentScrollAmount;
			}

			// Update the last scroll time so we can sample the numbers
			rng.prevMouseScrollTime = timeInMilliseconds;	

			// Reset current amount to 0 because we want the difference in scroll position
			rng.currentScrollAmount = 0;
		}
	},
	
	/**
	 * Different browsers have different ways to get the mouse wheel delta out even using jQuery. This will 
	 * get the current movement from the scroll wheel. This may produce different values across browsers.
	 * @param {object} e The event object
	 * @return {number} The mouse scroll wheel delta
	 */
	extractMouseWheelDelta: function(e)
	{		
		if (e.wheelDelta)
		{
			return e.wheelDelta;
		}
		if (e.originalEvent.detail)
		{
			return e.originalEvent.detail;
		}
		if (e.originalEvent && e.originalEvent.wheelDelta)
		{
			return e.originalEvent.wheelDelta;
		}
		
		return 0;
	},
		
	/**
	 * Collects the character code of each keypress and calls the function to collect the time between keypresses
	 * @param {event} e The event object
	 */
	collectKeypressEntropy: function(e)
	{			
		// Get the numeric integer of the currently pressed key
		var currentCharCode = e.which;

		// Make sure the char code is not 0 and eliminate repeated keypresses.
		// Also sample the collection to every x keystrokes defined by the user.
		if ((currentCharCode > 0) && (rng.prevKeypressCharCode != currentCharCode) && (rng.keypressCount % rng.keypressEntropyCollectionInterval == 0))
		{
			// Store the random number in the entropy pool and set the current coordinates to the 
			// previous coordinates variable, now that they've been processed
			rng.storeInPool('keypressEntropy', currentCharCode);
			rng.prevKeypressCharCode = currentCharCode;		
		}

		// Increment counter so we only collect once for each interval
		rng.keypressCount++;

		// Collect the time between the last keypress as well
		rng.collectTimeBetweenKeypressEntropy();
				
		// Stop default action. If this isn't used, user might push F5 which would refresh the page or backspace which would go 
		// to the previous page. Either of which they will lose their currently generated entropy which is frustrating.
		e.preventDefault();
	},
	
	/**
	 * Collects the time between each keypress and stores in an entropy pool
	 */
	collectTimeBetweenKeypressEntropy: function()
	{
		// If the previous keypress time hasn't been set, then initialise it to the program's start time
		// Then when the first keypress occurs it will be the number of milliseconds since program start
		if (rng.prevKeypressTime === null)
		{
			rng.prevKeypressTime = rng.entropyCollectionStartTime;
		}
		
		// Get the current time in milliseconds and calculate time between the last keypress and the current one
		var date = new Date();
		var timeInMilliseconds = date.getTime();
		var timeDifference = timeInMilliseconds - rng.prevKeypressTime;
				
		// Make sure there's no duplicate's recorded and that there is at least 3 milliseconds difference 
		// between collection to stop key mashing and getting consecutive 1s & 2s in the entropy
		if ((rng.prevKeypressTimeDifference != timeDifference) && (timeDifference > 3))
		{
			// Store the time difference between clicks in the entropy pool
			rng.storeInPool('keypressTimeEntropy', timeDifference);

			// Set the current time to the previous, now that it has been processed
			rng.prevKeypressTime = timeInMilliseconds;
			rng.prevKeypressTimeDifference = timeDifference;
		}
	},
	
	/**
	 * Combines all the entropy from the various pools and then shuffles it.
	 * Then starts a web worker process to hash all the entropy asynchronously.
	 */
	combineAllEntropyPools: function()
	{
		// Clear existing padData otherwise new data generated will be appended to existing data
		db.resetInMemoryPadData();
		
		// Combine all pools into one array
		this.combinedEntropyPool = this.mouseMovementEntropy.concat(
			this.mouseClickEntropy, this.mouseClickTimeEntropy, this.mouseScrollEntropy, 
			this.keypressEntropy, this.keypressTimeEntropy,	this.webCryptoApiEntropy
		);
			
		// If there's not at least 64 bytes of entropy show an error. If this check is removed, the browser will crash if there is no entropy
		if (this.totalEntropyLength < rng.numBytesToFeedIntoHash)
		{
			common.showStatus('error', 'Not enough entropy generated, generate some more.');
			return false;
		}
				
		// Shuffle all the values in the pool the number of times the user specifies
		for (var i=0; i < this.numTimesToShufflePool; i++)
		{
			this.combinedEntropyPool = common.shuffleArray(this.combinedEntropyPool);
		}
		
		// Combine the array into one string
		var combinedEntropyPoolString = this.combinedEntropyPool.join('');
				
		// For the possible hashing algorithms, mix up the order that they are applied
		hashAlgorithms = common.shuffleAlgorithms(common.hashAlgorithms);
		
		// Run HTML5 web worker thread to hash the entropy because it is CPU intensive and we don't want to block the UI
		var worker = new Worker('js/hashing-worker.js');
		var data = {
			'combinedEntropyPoolString': combinedEntropyPoolString,
			'hashAlgorithms': hashAlgorithms,
			'numBytesToFeedIntoHash': rng.numBytesToFeedIntoHash
		};
		
		// Send data to the worker
		worker.postMessage(data);
		
		// When the worker is complete, get the hashed entropy back and continue processing
		worker.addEventListener('message', function(e)
		{
			rng.processHashedEntropy(e.data);

		}, false);
	},
	
	/**
	 * Once the entropy has been combined, shuffled and hashed this method will shuffle the hashed entropy 
	 * leaving a single random string. Then this data will be split into separate one-time pads.
	 * @param {string} hashedEntropyPoolString Array of random entropy numbers
	 */
	processHashedEntropy: function(hashedEntropyPoolString)
	{				
		// Convert back to array of single hexadecimal symbols
		var hashedEntropyPoolArray = hashedEntropyPoolString.split('');
				
		// Final shuffle of the entropy to mix up the outputs of the hashes to disguise any possible bias
		var hashedAndShuffledEntropyArray = common.shuffleArray(hashedEntropyPoolArray);
		
		// Combine entropy back into string, store so we can use to test randomness later
		this.hashedAndShuffledEntropyString = hashedAndShuffledEntropyArray.join('');
		
		// Create the one-time pads
		common.createPads(this.hashedAndShuffledEntropyString);
	},
			
	/**
	 * View the random data as a bitmap image which lets a user do a simple visual analysis of the numbers produced.
	 * Humans are really good at spotting patterns. Visualisation of the random data allows them to use their eyes 
	 * and brain for this purpose. For example, compare these two images:
	 * http://www.random.org/analysis/randbitmap-rdo.png  (Random.org)
	 * http://www.random.org/analysis/randbitmap-wamp.png  (PHP rand() on Windows)
	 * The random output generated from this program should look something like the first image.
	 */
	viewRandomDataAsBitmap: function()
	{
		// If there is no random data then exit
		if (this.hashedAndShuffledEntropyString == null)
		{
			common.showStatus('error', 'No entropy generated, generate some first.');
			return false;
		}
		
		// First convert our random data to binary and dynamically work out the size of the square image (x & y axis)
		var randomBits = common.convertHexadecimalToBinary(this.hashedAndShuffledEntropyString);		
		var numRandomBits = randomBits.length;
		var squareRoot = Math.sqrt(numRandomBits);
		var axisLength = Math.floor(squareRoot);
		
		// Set new canvas dimensions
		$('#canvasRandomData').prop(
		{
			width: axisLength,
			height: axisLength
		});
		
		// Create the canvas
		var ctx = document.getElementById('canvasRandomData').getContext('2d');
		
		// Fill everything with white first
		ctx.fillStyle = "#FFF";
		ctx.fillRect(0, 0, axisLength, axisLength);
		ctx.fillStyle = "#000";
		
		// Loop through each binary char
		for (var i=0; i < axisLength; i++)
		{
			for (var j=0; j < axisLength; j++)
			{
				// If the character is a binary 1
				if (randomBits[i * axisLength + j] == '1')
				{
					// Fill that pixel with black
					ctx.fillRect(i, j, 1, 1);
				}
			}
		}
		
		// Show it on the page
		$('.randomDataBitmapContainer').show();
	},
	
	/**
	 * Statistical random number generator tests from FIPS 140-1, Section 4.11, Self-Tests. 
	 * A single bit stream of 20,000 consecutive bits of output from the generator is subjected to each of the following tests. 
	 * If any of the tests fail, then they haven't created good statistical randomness and should try again.	
	 * In future, add more randomness tests e.g. from http://www.random.org/analysis/Analysis2005.pdf
	 */
	testRandomness: function()
	{
		// Make sure there is actually entropy
		if (this.hashedAndShuffledEntropyString == null)
		{
			common.showStatus('error', 'No entropy to test.');
			return false;
		}
		
		// Get the first 20,000 bits of random data to run the tests
		var requiredNumOfBits = 20000;
		var randomBits = common.convertHexadecimalToBinary(this.hashedAndShuffledEntropyString);
		randomBits = randomBits.substr(0, requiredNumOfBits);
		var numOfBits = randomBits.length;
		
		// If they haven't collected enough, show an error
		if (numOfBits < requiredNumOfBits)
		{
			common.showStatus('error', 'Not enough entropy generated for random tests: ' + numOfBits + ' bits out of ' + requiredNumOfBits + ' bits required.');
			return false;
		}
		
		// Run the tests
		var monobitTest = randomTests.randomnessMonobitTest(randomBits, numOfBits);
		var pokerTest = randomTests.randomnessPokerTest(randomBits, numOfBits);
		var runsTest = randomTests.randomnessRunsTest(randomBits, numOfBits);
		var longRunsTest = randomTests.randomnessLongRunsTest(randomBits, numOfBits);
		
		// If all tests pass, show success message
		if (monobitTest && pokerTest && runsTest && longRunsTest)
		{
			common.showStatus('success', 'Randomness tests passed.');
			return true;
		}
		else {
			// Show error
			common.showStatus('error', 'Randomness tests failed.');
			return false;
		}
	}
};