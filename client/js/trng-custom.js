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
 * True Random Number Generator (TRNG) to extract random data from photographs
 */
var trngCustom = {
	
	// Image canvas settings
	uploadedImgCanvas: null,
	uploadedImgContext: null,
	imgDataArr: null,
		
	// Output settings
	outputCanvasId: null,
	canvasWidth: null,
	canvasHeight: null,
	
	/**
	 * Initialise the program
	 */
	init: function()
	{
		trngCustom.initHandlerToLoadFile();
		trngCustom.initResetButton();
		trngCustom.catchOutOfMemoryError();
		trngCustom.initUploadSettingsDialog();
		common.initExportPadsDialog();
	},
	
	/**
	 * Initialise the functionality for the file uploader
	 */
	initHandlerToLoadFile: function()
	{
		// On page load update the text on the page to say what file type is being loaded
		var textToDisplay = 'Load ' + $('#fileUploadType option:first-child').text();
		$('#fileUploadInstructions').text(textToDisplay);
		
		// When the file upload type changes, update the text on the page
		$('#fileUploadType').change(function()
		{
			var textToDisplay = 'Load ' + $('#fileUploadType option:selected').text();
			$('#fileUploadInstructions').text(textToDisplay);
		});
		
		// Upload the pads from text file into the database
		$('#fileLoader').change(function(event)
		{
			trngCustom.loadDataFromTextFile(event);
		});
	},
	
	/**
	 * Load the one-time pads from a text file
	 * @param {event} evt The event object
	 */
	loadDataFromTextFile: function(evt)
	{
		// Start timer
	   common.startTime = new Date();
	   common.showProcessingMessage('Loading file, please wait...', false);
	   $('#btnStartOver').removeAttr('disabled');
		
		// FileList object
		var files = evt.target.files;
		var file = files[0];
		
		// List some properties
		var fileInfo = 'Data loaded: ' + file.name + ', ' + file.type + ', ' + file.size + ' bytes.';
		
		// Set up to read from text file
		var reader = new FileReader();
		var fileType = $('#fileUploadType').val();
		
		// Determine how to read the data depending on the uploaded file type
		if (fileType === 'binary')
		{
			reader.readAsArrayBuffer(file);
		}
		else {
			reader.readAsText(file);
		}		

		// Closure to read the file information
		reader.onload = (function(file)
		{
			return function(e)
			{
				// Convert from binary file
				if (fileType === 'binary')
				{
					// Create a typed array of 0 - 255 integers to view the ArrayBuffer
					var arrayView = new Uint8Array(e.target.result);
					
					// Create the binary and hexadecimal
					for (var i=0, length = arrayView.length; i < length; i++)
					{
						common.randomDataHexadecimal += common.leftPadding(arrayView[i].toString(16), '0', 2);
						common.randomDataBinary  += common.leftPadding(arrayView[i].toString(2), '0', 8);						
					}					
				}
				
				// Normalise the hexadecimal symbols to lowercase and convert to binary as well
				else if (fileType === 'hexadecimal')
				{					
					common.randomDataHexadecimal = e.target.result.toLowerCase();
					common.randomDataBinary  = common.convertHexadecimalToBinary(common.randomDataHexadecimal);
				}
				
				// Convert from base64 to hexadecimal and binary
				else if (fileType === 'base64')
				{					
					var words  = CryptoJS.enc.Base64.parse(e.target.result);
					common.randomDataHexadecimal = CryptoJS.enc.Hex.stringify(words);
					common.randomDataBinary  = common.convertHexadecimalToBinary(common.randomDataHexadecimal);
				}
								
				// Update the number of random bits uploaded
				var numberOfRandomBits = common.randomDataBinary .length;
				    numberOfRandomBits = common.formatNumberWithCommas(numberOfRandomBits);
				$('#totalRandomBits .collectionStatusBox').html(numberOfRandomBits);
				
				// Show current status
				common.showProcessingMessage('Random data loaded successfully. ' + fileInfo + ' Starting randomness tests...', true);
						
				// Start the randomness tests and render the random data as a bitmap image
				trngCustom.startRandomnessTests(fileInfo);
			};
		})(file);
	},
		
	/**
	 * Reloads the page so the user can start a new upload
	 */
	initResetButton: function()
	{		
		$('#btnStartOver').click(function()
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
		window.onerror = function(error, url, line) {
			common.showStatus('error', 'Error occurred: ' + error + ' URL: ' + url);
		};
	},
	
	/**
	 * Configure the TRNG Extraction Settings dialog to open
	 */
	initUploadSettingsDialog: function()
	{		
		// Configure button to open entropy collection settings dialog
		$('#btnOpenUploadSettings').click(function()
		{					
			$('#uploadSettings').dialog('open');
		});

		// Configure entropy collection settings dialog
		$('#uploadSettings').dialog(
		{
			autoOpen: false,
			create: function (event)
			{
				// Set the dialog position as fixed before opening the dialog. See: http://stackoverflow.com/a/6500385
				$(event.target).parent().css('position', 'fixed');
			},
			resizable: false,
			width: 'auto'
		});
	},
		
	/**
	 * Start the randomness tests in a background worker
	 */
	startRandomnessTests: function()
	{
		// Run the randomness tests in FIPS 140-2 on the extracted data
		randomTests.init(common.randomDataBinary , 'testsOverallResult', 'testsOverallResultLog', 'FIPS-140-2', function()
		{			
			// On completion of the tests, display the test results
			trngCustom.displayProccessingStats();
		});
	},
		
	/**
	 * Show the number of extracted bits and number of messages
	 */
	displayProccessingStats: function()
	{
		// Show current status
		common.showProcessingMessage('Completed randomness tests.', true);
		
		// Calculate the collected data
		var totalRandomBits = common.randomDataBinary .length;
		var totalNumOfMessages = Math.floor(totalRandomBits / common.totalPadSizeBinary);
		
		// Format the values with the thousands separator
		totalRandomBits = common.formatNumberWithCommas(totalRandomBits);
		totalNumOfMessages = common.formatNumberWithCommas(totalNumOfMessages);
		
		// Show the other headings and update the totals
		$('#totalRandomBits .collectionStatusBox').html(totalRandomBits);
		$('#totalNumOfMessages .collectionStatusBox').html(totalNumOfMessages);
				
		// Show current status
		common.showProcessingMessage('Completed randomness extraction and tests. Now rendering bitmap image...', true);
				
		// Show the other headings and activate the other buttons
		$('h3.originalHeading').show();
		$('h3.processedHeading').show();
		$('#btnOpenExportPadsSettings').removeAttr('disabled');
		$('.testingButtons').addClass('active');
		
		// Make sure the status has updated, then render the image which can take a while if it is large
		setTimeout(function()
		{
			// Render the extracted data to a new HTML5 canvas
			trngCustom.fillCanvasWithData('imageCanvas', common.randomDataBinary );

			// Final status
			common.showProcessingMessage('Data import and testing complete.', true);
			
		}, 500);
	},			

	/**
	 * Fills the HTML5 canvas with random bits, 0 bits are coloured white, 1 bits are coloured black.
	 * @param {string} canvasId The id to render the binary data into
	 * @param {string} randomBits Random binary data
	 */
	fillCanvasWithData: function(canvasId, randomBits)
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
		var ctx = document.getElementById(canvasId).getContext('2d');

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
				if (randomBits[i * axisLength + j] === '1')
				{
					// Fill that pixel with black
					ctx.fillRect(i, j, 1, 1);
				}
			}
		}
	}
};