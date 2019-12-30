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
 * A program to load custom random data from the user then create the one-time pads for use with the program
 */
var trngCustomPage = {

	/**
	 * Initialise the program
	 */
	init: function()
	{
		// Initialise the functionality
		trngCustomPage.initUploadSettingsDialog();
		trngCustomPage.initHandlerToLoadFile();
		trngCustomPage.initRestartButton();
		trngCustomPage.catchOutOfMemoryError();
		exportPads.initExportPadsDialog();
	},

	/**
	 * Configure the TRNG Extraction Settings dialog to open
	 */
	initUploadSettingsDialog: function()
	{
		// When the file upload type changes in the settings
		query.getCachedGlobal('.jsUploadSettingsDialog .jsFileUploadType').on('change', function()
		{
			// Get the text of the selected option in the dropdown
			var dropdownText = query.getGlobal('.jsUploadSettingsDialog .jsFileUploadType option:selected').text();
			var textToDisplay = 'Load ' + dropdownText.toLowerCase();

			// Update the text on the page to say what file type is being loaded
			query.getCached('.jsFileUploadInstructions').text(textToDisplay);
		});

		// Configure button to open the settings dialog
		query.getCached('.jsOpenUploadSettingsButton').on('click', function()
		{
			query.getCachedGlobal('.jsUploadSettingsDialog').dialog('open');
		});

		// Configure the jQueryUI settings dialog
		query.getCachedGlobal('.jsUploadSettingsDialog').dialog(
		{
			autoOpen: false,
			create: function (event)
			{
				// Set the dialog position as fixed before opening the dialog. See: http://stackoverflow.com/a/6500385
				$(event.target).parent().css('position', 'fixed');
			},
			modal: true,
			resizable: false,
			width: 'auto'
		});

		// On page load, get the text of the first option in the dropdown
		var dropdownText = query.getCachedGlobal('.jsUploadSettingsDialog .jsFileUploadType option:first-child').text();
		var textToDisplay = 'Load ' + dropdownText.toLowerCase();

		// Update the text on the page to say what file type is being loaded
		query.getCached('.jsFileUploadInstructions').text(textToDisplay);
	},

	/**
	 * Initialise the functionality for the file uploader
	 */
	initHandlerToLoadFile: function()
	{
		// When the file is chosen
		query.getCached('.jsFileLoaderButton').on('change', function(event)
		{
			// Make the label appear disabled and disable the actual button (the Restart button must be used to clear everything first)
			query.getCached('.jsFileLoaderLabel').addClass('disabled');
			query.getCached('.jsFileLoaderButton').prop('disabled', true);

			// Load the data from the file
			trngCustomPage.loadDataFromFile(event);
		});
	},

	/**
	 * Load the one-time pads from a text file
	 * @param {event} event The event object
	 */
	loadDataFromFile: function(event)
	{
		// Start timer
		app.startTime = new Date();
		app.showProcessingMessage('Loading file, please wait...', false);

		// Enable the Restart button
		query.getCached('.jsStartOverButton').prop('disabled', false);

		// FileList object
		var files = event.target.files;
		var file = files[0];

		// List some properties
		query.getCached('.jsFileInfo').text(file.name + ', ' + file.type + ', ' + file.size + ' bytes');

		// Set up to read from file
		var reader = new FileReader();
		var fileType = query.getCachedGlobal('.jsUploadSettingsDialog .jsFileUploadType').val();

		// Determine how to read the data depending on the uploaded file type
		if (fileType === 'binary')
		{
			reader.readAsArrayBuffer(file);
		}
		else {
			reader.readAsText(file);
		}

		// Closure to read the file information
		reader.onload = (function()
		{
			return function(onLoadEvent)
			{
				// Convert from binary file
				if (fileType === 'binary')
				{
					// Create a typed array of 0 - 255 integers to view the ArrayBuffer
					var arrayView = new Uint8Array(onLoadEvent.target.result);

					// Create the binary and hexadecimal
					for (var i = 0, length = arrayView.length; i < length; i++)
					{
						exportPads.randomBitsExtractedHex += common.leftPadding(arrayView[i].toString(16), '0', 2);
						exportPads.randomBitsExtractedBinary += common.leftPadding(arrayView[i].toString(2), '0', 8);
					}
				}

				// Normalise the hexadecimal symbols to lowercase and convert to binary as well
				else if (fileType === 'hexadecimal')
				{
					exportPads.randomBitsExtractedHex = onLoadEvent.target.result.toLowerCase();
					exportPads.randomBitsExtractedBinary  = common.convertHexadecimalToBinary(exportPads.randomBitsExtractedHex);
				}

				// Convert from base64 to hexadecimal and binary
				else if (fileType === 'base64')
				{
					// Convert the Base64 to words
					var words = CryptoJS.enc.Base64.parse(onLoadEvent.target.result);

					// Convert to hex and binary
					exportPads.randomBitsExtractedHex = CryptoJS.enc.Hex.stringify(words);
					exportPads.randomBitsExtractedBinary  = common.convertHexadecimalToBinary(exportPads.randomBitsExtractedHex);
				}

				// Calculate the number of random bits loaded
				var numberOfRandomBits = exportPads.randomBitsExtractedBinary.length;
				var numberOfRandomBitsFormatted = common.formatNumberWithCommas(numberOfRandomBits);

				// Update the number of random bits uploaded
				query.getCached('.jsTotalRandomBits').text(numberOfRandomBitsFormatted);

				// Show current status
				app.showProcessingMessage('Random data loaded successfully. Starting randomness tests...', true);

				// Start the randomness tests and render the random data as a bitmap image
				trngCustomPage.startRandomnessTests();
			};
		})(file);
	},

	/**
	 * Reloads the page so the user can start a new upload
	 */
	initRestartButton: function()
	{
		// On clicking the Restart button
		query.getCached('.jsStartOverButton').on('click', function()
		{
			// Hard refresh the browser page (ignores browser cache)
			location.reload(true);
		});
	},

	/**
	 * Catch out of memory errors and display them to the user. Sometimes this can
	 * happen when processing a large image and the machine runs out of memory or the
	 * browser can't free old memory fast enough.
	 */
	catchOutOfMemoryError: function()
	{
		// Catch out of memory error if it occurs and display to the user
		window.onerror = function(error, url, line)
		{
			app.showStatus('error', 'Error occurred: ' + error + ' URL: ' + url + ' line: ' + line, true);
		};
	},

	/**
	 * Start the randomness tests in a background worker
	 */
	startRandomnessTests: function()
	{
		// Run the randomness tests in FIPS 140-2 on the extracted data
		trngTests.init(exportPads.randomBitsExtractedBinary, function(overallResults)
		{
			// On completion of the tests, display the test results
			trngCustomPage.displayTestResults(overallResults, 'jsOverallResult');
		});
	},

	/**
	 * Show the number of bits and number of messages
	 * @param {Object} allResults Contains 'overallResult' pass/fail boolean, and the 'overallResultLog' which is the HTML test results
	 * @param {String} overallResultOutputClass Where the overall result will be rendered after the tests are complete
	 */
	displayTestResults: function(allResults, overallResultOutputClass)
	{
		// Generate the HTML to be rendered
		var outputHtml = trngTests.generateTestLogOutputHtml(allResults);

		// Display in the page
		query.getCached('.jsAllTestResults').append(outputHtml);

		// Determine the CSS class
		var resultText = (allResults.allTestsPassed) ? 'success' : 'failed';
		var resultClass = 'is' + common.capitaliseFirstLetter(resultText);

		// Update the overall result in the result logs on the page
		query.getCached('.' + overallResultOutputClass).addClass(resultClass).text(resultText);

		// Calculate totals of the loaded data
		var totalRandomBits = exportPads.randomBitsExtractedBinary.length;
		var totalNumOfMessages = Math.floor(totalRandomBits / common.totalPadSizeBinary);

		// Format the values with the thousands separator
		totalRandomBits = common.formatNumberWithCommas(totalRandomBits);
		totalNumOfMessages = common.formatNumberWithCommas(totalNumOfMessages);

		// Show the updated totals
		query.getCached('.jsTotalRandomBits').text(totalRandomBits);
		query.getCached('.jsTotalNumOfMessages').text(totalNumOfMessages);
		query.getCached('.jsOverallTestsPass').addClass(resultClass).text(resultText);

		// Show the other headings and activate the other buttons
		query.getCached('.jsOutputAndResults').show();
		query.getCached('.jsOpenExportPadsSettingsButton').prop('disabled', false);
		query.getCached('.jsTestingButtons').addClass('active');

		// Show current status
		app.showProcessingMessage('Completed randomness extraction and tests. Now rendering bitmap image...', true);

		// Make sure the status has updated, then render the image which can take a while if it is large
		setTimeout(function()
		{
			// Render the extracted data to a new HTML5 canvases in colour and black and white
			trngTests.fillCanvasWithBlackWhite('jsRandomBitsBlackWhite', exportPads.randomBitsExtractedBinary);
			trngTests.fillCanvasWithColour('jsRandomBitsColour', exportPads.randomBitsExtractedBinary);

			// Final status
			app.showStatus('success', 'Data import and testing complete.', true);

		}, 300);
	},

	/**
	 * The cleanup function to be run when moving to another page.
	 * This will reset the page to its initial state and clear any sensitive data.
	 */
	cleanup: function()
	{
		// Get the Black & White and Colour canvases
		var blackWhiteCanvas = query.getCached('.jsRandomBitsBlackWhite').get(0);
		var colourCanvas = query.getCached('.jsRandomBitsColour').get(0);

		// Clear the canvases
		blackWhiteCanvas.getContext('2d').clearRect(0, 0, blackWhiteCanvas.width, blackWhiteCanvas.height);
		colourCanvas.getContext('2d').clearRect(0, 0, colourCanvas.width, colourCanvas.height);

		// Clear test results and hide the test results & images container
		query.getCached('.jsAllTestResults').empty();
		query.getCached('.jsOverallResult').removeClass('isSuccess').text('');
		query.getCached('.jsOutputAndResults').hide();

		// Clear the totals section
		query.getCached('.jsTotalRandomBits').text('0');
		query.getCached('.jsTotalNumOfMessages').text('0');
		query.getCached('.jsOverallTestsPass').removeClass('isSuccess isFailed').text('N/A');

		// Deactivate the other buttons
		query.getCached('.jsOpenExportPadsSettingsButton').prop('disabled', true);
		query.getCached('.jsTestingButtons').removeClass('active');
		query.getCached('.jsStartOverButton').prop('disabled', true);

		// Reset the dropdown to select the first option in case another option was chosen previously and returning to the page
		query.getCachedGlobal('.jsUploadSettingsDialog .jsFileUploadType option:first-child').prop('selected', true);

		// Clear file information and reset file upload button
		query.getCached('.jsFileInfo').text('N/A');
		query.getCached('.jsFileLoaderLabel').removeClass('disabled');
		query.getCached('.jsFileLoaderButton').prop('disabled', false).val('');

		// Cleanup export pads dialog and cached random bits
		exportPads.cleanup();
	}
};