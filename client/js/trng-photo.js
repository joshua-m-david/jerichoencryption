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
var trngImg = {
	
	// How many datasets to split the data into and how many concurrent web workers
	numOfDatasets: 10,
	maxConcurrentThreads: 2,
	
	// Array to hold temporary datasets in correct order
	tempProcessedBinaryData: [],
	
	// Full binary data
	fullBinaryDataProcessed: '',
	fullBinaryDataExtracted: '',
	
	// Image canvas settings
	uploadedImgCanvas: null,
	uploadedImgContext: null,
	imgDataArr: null,
	
	// Output settings
	rawOutputCanvasId: null,
	extractedOutputCanvasId: null,
	canvasWidth: null,
	canvasHeight: null,
	
	/**
	 * Initialise the program
	 */
	init: function()
	{
		trngImg.initHandlerToLoadImage();
		trngImg.initProcessImageButton();
		trngImg.initResetButton();
		trngImg.catchOutOfMemoryError();
		trngImg.initExportPadsDialog();
		trngImg.dynamicallySetNicknameTextEntry();
		trngImg.hideOptionsDependingOnExportMethod();
		trngImg.initCreateServerKeyButton();
		trngImg.initExportPadsButton();
		trngImg.preloadServerConnectionDetails();
		trngImg.initTestServerConnectionButton();
	},
	
	/**
	 * When an image is uploaded, load it into HTML5 canvas
	 */
	initHandlerToLoadImage: function()
	{
		// Get the file upload element
		var imageLoader = document.getElementById('imageLoader');
		
		// Load the image into HTML5 canvas on file upload
		imageLoader.addEventListener('change', function(eventObj)
		{
			trngImg.loadImageIntoCanvas(eventObj);
			
		}, false);

		// Initialise the image canvas and context
		trngImg.uploadedImgCanvas = document.getElementById('imageCanvas');
		trngImg.uploadedImgContext = trngImg.uploadedImgCanvas.getContext('2d');
	},
	
	/**
	 * Initialise the button to process the image, extract the entropy and run the tests
	 */
	initProcessImageButton: function()
	{		
		$('#processImage').click(function()
		{
			// Start timer
			common.startTime = new Date();
			common.showProcessingMessage('Processing of image started, please wait...', false);

			// Disable the button, as the canvas gets cleared after loading
			$('#processImage').attr('disabled', true);

			// Process the image
			trngImg.rawOutputCanvasId = 'processedImage';
			trngImg.extractedOutputCanvasId = 'extractedImage';
			trngImg.processImage();
		});
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
	 * Configure the Export Pads dialog to open
	 */
	initExportPadsDialog: function()
	{
		// Configure button to open entropy collection settings dialog
		$('#btnOpenExportPadsSettings').click(function()
		{					
			$('#exportPadsSettings').dialog('open');
		});

		// Configure entropy collection settings dialog
		$('#exportPadsSettings').dialog(
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
	 * When the number of users changes, enable/disable options in the Export for user 
	 * select box and dynamically alter the number of user nicknames they can enter
	 */
	dynamicallySetNicknameTextEntry: function()
	{		
		$('#numOfUsers').change(function()
		{
			// Get the number of users
			var numOfUsers = parseInt($(this).val());
			var options = '';
			var nicknames = '';

			// Build the dropdown options dynamically
			for (var i=0; i < numOfUsers; i++)
			{
				options += '<option value="' + common.userList[i] + '">' + common.userList[i] + '</option>';
			}

			// Build list of users so the user can edit the user nicknames
			for (var i=0; i < numOfUsers; i++)
			{
				// Build the HTML to be rendered inside the dialog
				var nicknameCapitalised = common.capitaliseFirstLetter(common.userList[i]);
				nicknames += '<label>' + nicknameCapitalised + '</label> '
						  +  '<input id="nickname-' + common.userList[i] + '" type="text" maxlength="12" value="' + nicknameCapitalised + '"><br>';
			}

			// Display the options
			$('#exportForUser').html(options);
			$('.nicknames').html(nicknames);
		});
	},
	
	/**
	 * Hide or show the last option in the dialog if the export method is changed
	 */
	hideOptionsDependingOnExportMethod: function()
	{		
		$('#exportMethod').change(function()
		{
			var exportMethod = $(this).val();

			// If the pads will be exported for actual use show the Export for User option
			if ((exportMethod === 'textFile') || (exportMethod === 'clipboard') || (exportMethod === 'localDatabase'))
			{
				$('.exportForUserRow').show();
			}
			else {
				// Otherwise export for testing so hide the Export for User option
				$('.exportForUserRow').hide();
			}					
		});
	},
	
	/**
	 * Creates a 512 bit server key from the random, extracted 
	 * data and puts it in the export dialog's text field
	 */
	initCreateServerKeyButton: function()
	{
		$('#btnCreateServerKey').click(function()
		{
			// Check there is enough data to create a key
			if (trngImg.fullBinaryDataExtracted.length < 512) {
				common.showStatus('error', 'Not enough bits remaining to create a full 512 bit key.');
			}
			else {
				// Take the first 512 bits of the extracted data and convert it to hexadecimal
				var serverKey = trngImg.fullBinaryDataExtracted.slice(0, 512);
				var serverKeyHex = common.convertBinaryToHexadecimal(serverKey);

				// After removing the first 512 bits, use the remainder of the bits for the one-time pads
				trngImg.fullBinaryDataExtracted = trngImg.fullBinaryDataExtracted.slice(512);

				// Put it in the text field
				$('#serverKey').val(serverKeyHex);
			}
		});
	},
	
	/**
	 * Initialise the button to export the one-time pads or random data for external testing
	 */
	initExportPadsButton: function()
	{
		// Export the pads
		$('#btnExportPads').click(function()
		{
			// Get the selected export method
			var exportMethod = $('#exportMethod').val();

			// Export to text, file or database depending on user selection
			if ((exportMethod === 'textFile') || (exportMethod === 'clipboard') || (exportMethod === 'localDatabase'))
			{
				var numOfUsers = parseInt($('#numOfUsers').val());
				var exportForUser = $('#exportForUser').val();
				var serverAddressAndPort = $('#serverAddressAndPort').val();
				var serverKey = $('#serverKey').val();						
				var userNicknames = {};

				// Loop through the number of users
				for (var i=0; i < numOfUsers; i++)
				{
					// Get the user, nickname, then filter the nickname field so only A-z and 0-9 characters allowed
					var user = common.userList[i];
					var nickname = $('#nickname-' + common.userList[i]).val();
						nickname = nickname.replace(/[^A-Za-z0-9]/g, '');

					// If the nickname field has nothing, then use the default user name e.g. Alpha, Bravo
					if (nickname === '')
					{
						// Capitalise the default user
						nickname = common.userList[i];
						nickname = common.capitaliseFirstLetter(nickname);
					}

					// Store the nickname as a key next to the user
					userNicknames[user] = nickname;
				}

				// Export the pads
				common.preparePadsForExport(numOfUsers, userNicknames, exportForUser, exportMethod, serverAddressAndPort, serverKey, trngImg.fullBinaryDataExtracted);
			}
			else {
				// Otherwise export the random data for testing using external methods
				common.prepareRandomDataForExternalTesting(exportMethod, trngImg.fullBinaryDataProcessed, trngImg.fullBinaryDataExtracted);
			}
		});
	},
	
	/**
	 * Preload values into the text boxes if they already have connection settings in local storage
	 */
	preloadServerConnectionDetails: function()
	{
		// If they already have connection settings in local storage
		if (db.padData.info.serverAddressAndPort !== null)
		{
			// Load from local storage into the text fields
			$('#serverAddressAndPort').val(db.padData.info.serverAddressAndPort);
			$('#serverUsername').val(db.padData.info.serverUsername);
			$('#serverKey').val(db.padData.info.serverKey);
		}
	},
	
	/**
	 * Test the server connection when the button is clicked
	 */
	initTestServerConnectionButton: function()
	{						
		$('#testServerConnection').click(function()
		{
			// Get values from text inputs
			var serverAddressAndPort = $('#serverAddressAndPort').val();
			var serverKey = $('#serverKey').val();

			// Check connection and show success or failure message on screen
			common.testServerConnection(serverAddressAndPort, serverKey);
		});
	},
	
	/**
	 * Load the image into a canvas object on the page
	 * @param {object} eventObj The event object
	 */
	loadImageIntoCanvas: function(eventObj)
	{
	   // Start timer
	   common.startTime = new Date();
	   common.showProcessingMessage('Loading image into canvas, please wait...', false);

	   // User HTML5 FileReader API
	   var reader = new FileReader();

	   // Callback when file is loaded
	   reader.onload = function(event)
	   {
		   var img = new Image();

		   // Fill the image into the uploadedImgCanvas
		   img.onload = function()
		   {
			   // Set params for output of processed image
			   trngImg.canvasWidth = img.width;
			   trngImg.canvasHeight = img.height;

			   // Set the canvas image data
			   trngImg.uploadedImgCanvas.width = trngImg.canvasWidth;
			   trngImg.uploadedImgCanvas.height = trngImg.canvasHeight;
			   trngImg.uploadedImgContext.drawImage(img, 0, 0);

			   // Show the heading and hide/show buttons
			   $('h3.originalHeading').show();
			   $('#processImage').removeAttr('disabled');
			   $('#btnStartOver').removeAttr('disabled');
			   $('#imageLoader').attr('disabled', true);

			   // Show a status message
			   common.showProcessingMessage('Completed loading of image into canvas, you can now process the image.', true);
		   };

		   // Display the image
		   img.src = event.target.result;
	   };

	   // Upload from the page
	   reader.readAsDataURL(eventObj.target.files[0]);     
	},
	
	/**
	 * Convert the uploaded image to random data
	 */
	processImage: function()
	{
		// Get the data from the image
		trngImg.imgDataArr = this.uploadedImgContext.getImageData(0, 0, this.uploadedImgCanvas.width, this.uploadedImgCanvas.height).data;
		
		// Start the process
		trngImg.splitArrayIntoParts();
	},
			
	/**
	 * Split the image data into parts so each part can be worked on separately by a web worker
	 */
	splitArrayIntoParts: function()
	{
		// Create the dataset arrays
		for (var i=0; i < this.numOfDatasets; i++) {
			trngImg['dataset' + i] = [];
		}
		
		// Calculate how many RGB values per dataset
		var length = this.imgDataArr.length;													// Contains red, green, blue, alpha values in sequential array
		var lengthAlphaChannelValues = (length / 4);											// Get length of alpha channel values
		var lengthWithoutAlphaValues = length - lengthAlphaChannelValues;						// Get length of other values without alpha channel values
		var maxValuesPerDataset = Math.floor(lengthWithoutAlphaValues / this.numOfDatasets);	// Get maximum number of RGB values per dataset
		
		// Loop counters
		var valuesCurrentDataset = 0;
		var currentDataset = 0;
		
		// Enumerate all RGBA values
		for (var i=0; i < length; i += 4)
		{
			// Strip out the unnecessary alpha channel data and convert from 
			// Uint8ClampedArray to basic array so we can perform array manipulations
			trngImg['dataset' + currentDataset].push(this.imgDataArr[i]);		// Add red
			trngImg['dataset' + currentDataset].push(this.imgDataArr[i + 1]);	// Add green
			trngImg['dataset' + currentDataset].push(this.imgDataArr[i + 2]);	// Add blue
			
			// Keep tally of how many pixels have been added to the current dataset
			valuesCurrentDataset += 3;
			
			// If the current number of pixels matches or exceeds the maximum, then start putting into a new dataset
			if (valuesCurrentDataset >= maxValuesPerDataset)
			{
				currentDataset++;
				valuesCurrentDataset = 0;
			}
		}
		
		// Clear the uploaded image canvas to free up memory for processing
		trngImg.uploadedImgContext.clearRect(0, 0, trngImg.canvasWidth, trngImg.canvasHeight);
		trngImg.uploadedImgCanvas.width = 0;
		trngImg.uploadedImgCanvas.height = 0;
		
		// Hide the original photo heading as it will be replaced by the processed image
		$('.originalHeading').hide();
		
		// Free up memory
		delete trngImg.uploadedImgCanvas;
		delete trngImg.uploadedImgContext;
		delete trngImg.imgDataArr;
						
		// Pre-create arrays to hold the dataset id for each thread
		for (var i=0; i < this.maxConcurrentThreads; i++)
		{
			trngImg['datasetQueueThread' + i] = [];
		}
		
		// Counter
		var currentThread = 0;
		
		// Add the datasets to the thread queues equally
		for (var i=0; i < this.numOfDatasets; i++)
		{
			// Add the dataset index to be processed by this thread
			trngImg['datasetQueueThread' + currentThread].push(i);
		
			// Change queue for next thread
			currentThread++;
			
			// Start adding at the first thread if max reached
			if (currentThread === this.maxConcurrentThreads)
			{
				currentThread = 0;
			}
		}
		
		// Preallocate values to the processed array
		for (var i=0; i < this.numOfDatasets; i++)
		{
			trngImg.tempProcessedBinaryData[i] = null;
		}
		
		// Show status message
		common.showProcessingMessage('Image split into ' + this.numOfDatasets + ' datasets. Now starting ' + this.maxConcurrentThreads + ' concurrent threads...', true);
				
		// Start the image processing by splitting the processing work into different web workers
		for (var i=0; i < this.maxConcurrentThreads; i++)
		{
			this.startProcessingWebWorker(i);
		}
	},
	
	/**
	 * Process the entropy in this dataset
	 * @param {integer} threadId The thread ID is kept to process datasets assigned to this thread
	 */
	startProcessingWebWorker: function(threadId)
	{
		// If there are less datasets than there are threads on starting then there might be an empty thread queue so stop processing this thread
		if (trngImg['datasetQueueThread' + threadId].length === 0)
		{
			return false;
		}
		
		// Get the next dataset to work on
		var datasetId = trngImg['datasetQueueThread' + threadId].shift();
		
		// Run HTML5 web worker thread to process the entropy because it is CPU intensive and we don't want to block the UI
		var worker = new Worker('js/trng-photo-worker.js');
		var data = {
			'threadId': threadId,
			'datasetId': datasetId,
			'dataset': trngImg['dataset' + datasetId]
		};
				
		// Send data to the worker
		worker.postMessage(data);
		
		// Free up memory
		delete trngImg['dataset' + datasetId];
		data = undefined;
		
		// When the worker is complete
		worker.addEventListener('message', function(e)
		{						
			// Render the processed data onto the page
			trngImg.finishProcessingWebWorker(e.data.threadId, e.data.datasetId, e.data.datasetBinaryData);
			
		}, false);
		
		// Worker error handler
		worker.addEventListener('error', function(e)
		{
			console.log('ERROR: Line ' + e.lineno + ' in ' + e.filename + ': ' + e.message);
			
		}, false);
	},
		
	/**
	 * When the web worker finishes it will hit this function. Because there are x workers running simultaneously 
	 * then they can finish in different orders. This will store the results of each worker as it finishes, then
	 * when the last one has completed it will go through to the next stage.
	 * @param {integer} threadId The thread ID that processed this data
	 * @param {integer} datasetId The dataset ID that the processed data is from
	 * @param {string} datasetBinaryData The processed binary data
	 */
	finishProcessingWebWorker: function(threadId, datasetId, datasetBinaryData) {
				
		// Add processed dataset to the array
		trngImg.tempProcessedBinaryData[datasetId] = datasetBinaryData;
		
		// If this thread hasn't finished processing the datasets in its queue
		if (trngImg['datasetQueueThread' + threadId].length !== 0)
		{
			// Show current status
			common.showProcessingMessage('Finished processing dataset ' + datasetId + ' in thread ' + threadId + '. Starting next worker...', true);
			
			// Start processing the next dataset in this thread queue
			trngImg.startProcessingWebWorker(threadId);
			return false;
		}
		
		// If all the datasets have been processed (some finish out of order), then join all the data together
		if (trngImg.finishedProcessingAllDatasets())
		{	
			// Show current status
			common.showProcessingMessage('Finished processing all datasets. Starting extraction processing...', true);
			
			// Gather the processed data back into its original order
			for (var i=0; i < trngImg.numOfDatasets; i++)
			{
				// Concatenate processed data together
				trngImg.fullBinaryDataProcessed += trngImg.tempProcessedBinaryData[i];
			}
			
			// Clear memory
			trngImg.tempProcessedBinaryData = [];
			
			// Show total of collected bits formatted with thousands separator
			var totalEntropyLength = trngImg.fullBinaryDataProcessed.length;
			    totalEntropyLength = common.formatNumberWithCommas(totalEntropyLength);
			$('#totalEntropyLength .collectionStatusBox').html(totalEntropyLength);
			
			// Extract the random data
			trngImg.startExtractionProcess();
		}
		else {
			// Show current status
			common.showProcessingMessage('Finished processing dataset ' + datasetId + ' in thread ' + threadId + '. Other threads still running...', true);
		}
	},
	
	/**
	 * Run the Von Nuemann randomness extractor
	 */
	startExtractionProcess: function()
	{
		// Run HTML5 web worker thread to extract the entropy because it is CPU intensive and we don't want to block the UI
		var worker = new Worker('js/trng-extraction-worker.js');
		var data = {
			'fullBinaryDataProcessed': trngImg.fullBinaryDataProcessed
		};
				
		// Send data to the worker
		worker.postMessage(data);
				
		// When the worker is complete
		worker.addEventListener('message', function(e)
		{
			// Get the extracted data back from the worker
			trngImg.fullBinaryDataExtracted = e.data.fullBinaryDataExtracted;
			
			// Start the randomness tests and render the processed and extracted images
			trngImg.startRandomnessTests();
			trngImg.displayRenderedImages();
			trngImg.displayProccessingStats();
			
		}, false);
		
		// Worker error handler
		worker.addEventListener('error', function(e)
		{
			console.log('ERROR: Line ' + e.lineno + ' in ' + e.filename + ': ' + e.message);
			
		}, false);
	},
		
	/**
	 * Checks to see if all the datasets have finished processing
	 * @return {boolean} Whether all the processing has finished or not
	 */
	finishedProcessingAllDatasets: function()
	{		
		// Search through the datasets
		for (var i=0; i < trngImg.numOfDatasets; i++)
		{
			// If the array value is null then processing isn't finished yet
			if (trngImg.tempProcessedBinaryData[i] === null)
			{
				return false;
			}
		}
		
		// Processing is complete
		return true;
	},
	
	/**
	 * Start the randomness tests in a background worker
	 */
	startRandomnessTests: function()
	{
		// Show current status
		common.showProcessingMessage('Completed processing. Starting randomness tests...', true);
		
		// Run the FIPS 140-1 tests on the raw processed data then the tighter thresholds in FIPS 140-2 on the extracted data
		randomTests.init(trngImg.fullBinaryDataProcessed, 'processedOverallResult', 'processedOverallResultLog', 'FIPS-140-1');
		randomTests.init(trngImg.fullBinaryDataExtracted, 'extractedOverallResult', 'extractedOverallResultLog', 'FIPS-140-2');
	},
	
	/**
	 * Render the results to a new HTML5 canvas
	 * @param {string} binaryData The raw processed binary data
	 * @param {string} extractedBinaryData The whitened binary data
	 */
	displayRenderedImages: function()
	{
		// Show current status
		common.showProcessingMessage('Completed processing. Rendering processed and extracted images...', true);
		
		// Show the other headings and activate the other buttons
		$('h3.processedHeading').show();
		$('#btnOpenExportPadsSettings').removeAttr('disabled');
		$('.testingButtons').addClass('active');
		
		// Set width and height to that of original image, also show image after von nuemann extraction
		this.fillCanvasUsingOriginalDimensions(trngImg.rawOutputCanvasId, trngImg.fullBinaryDataProcessed, trngImg.canvasWidth, trngImg.canvasHeight);
		this.fillCanvasWithData(trngImg.extractedOutputCanvasId, trngImg.fullBinaryDataExtracted);
	},
	
	/**
	 * Show the number of extracted bits and number of messages
	 */
	displayProccessingStats: function()
	{
		// Calculate the collected data
		var totalExtractedBits = trngImg.fullBinaryDataExtracted.length;
		var totalNumOfMessages = Math.floor(totalExtractedBits / common.totalPadSizeBinary);
		
		// Format the values with the thousands separator
		totalExtractedBits = common.formatNumberWithCommas(totalExtractedBits);
		totalNumOfMessages = common.formatNumberWithCommas(totalNumOfMessages);
		
		// Show the other headings and update the totals
		$('#totalExtractedBits .collectionStatusBox').html(totalExtractedBits);
		$('#totalNumOfMessages .collectionStatusBox').html(totalNumOfMessages);
	},
	
	/**
	 * Gets the image data from the canvas and processes it into one bit per pixel
	 * @param {array} dataset The dataset to process
	 * @returns {String}
	 */
	convertFromImageData: function(dataset)
	{
		var binaryData = '';
		
		// Enumerate all pixels				
		for (var i=0, length = dataset.length; i < length; i += 3)
		{
			// Each pixel's red, green, blue & alpha datum are stored in separate sequential array elements
			var red = dataset[i];
			var green = dataset[i + 1];
			var blue = dataset[i + 2];
			
			// Convert RGB values for the pixel to binary
			var rgbInBinary = this.convertRgbToBinary(red, green, blue);
			
			// Convert to single bit and append to current data
			binaryData += this.compressBinaryIntoOneBit(rgbInBinary);
		}
		
		return binaryData;
	},
		
	/**
	 * Converts Red, Green and Blue values to binary representation
	 * @param {integer} red
	 * @param {integer} green
	 * @param {integer} blue
	 * @returns {string} Returns 24 bit binary representation of the RGB values
	 */
	convertRgbToBinary: function(red, green, blue)
	{
		// Convert each integer to the binary representation
		var binaryRed = red.toString(2);
		var binaryGreen = green.toString(2);
		var binaryBlue = blue.toString(2);
		
		// Left pad with 0's if necessary so each number is one octet
		binaryRed = common.leftPadding(binaryRed, '0', 8);
		binaryGreen = common.leftPadding(binaryGreen, '0', 8);
		binaryBlue = common.leftPadding(binaryBlue, '0', 8);
		
		// Returns 3 octets
		return binaryRed + binaryGreen + binaryBlue;		
	},

	/**
	 * Compresses 3 binary octets (representing a single pixel's RGB values) into a single bit by XORing each bit with the next
	 * @param {string} binaryString
	 * @returns {string} Returns a single bit
	 */
	compressBinaryIntoOneBit: function(binaryString)
	{
		// Get the first bit
		var currentResultBit = binaryString.charAt(0);

		// Loop through the other bits in the string
		for (var i=1, length = binaryString.length; i < length; i++)
		{	
			// XOR the current bit with the next bit	
			currentResultBit = currentResultBit ^ binaryString.charAt(i);
		}

		// Return a single bit
		return currentResultBit;
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
				if (randomBits[i * axisLength + j] == '1')
				{
					// Fill that pixel with black
					ctx.fillRect(i, j, 1, 1);
				}
			}
		}
	},

	/**
	 * Fills the HTML5 canvas with random bits, 0 bits are coloured white, 1 bits are coloured black.
	 * Fills the canvas according to the original dimensions (width & height) of the image.
	 * @param {string} canvasId The id to render the binary data into
	 * @param {string} randomBits Random binary data
	 */
	fillCanvasUsingOriginalDimensions: function(canvasId, randomBits, originalWidth, originalHeight)
	{
		// Set width and height to that of original image
		var originalWidth = originalWidth;
		var originalHeight = originalHeight;

		// Set new canvas dimensions
		$('#' + canvasId).prop(
		{
			width: originalWidth,
			height: originalHeight
		});

		// Create the canvas
		var ctx = document.getElementById(canvasId).getContext('2d');

		// Fill everything with white first
		ctx.fillStyle = "#FFF";
		ctx.fillRect(0, 0, originalWidth, originalHeight);
		ctx.fillStyle = "#000";

		// Initialisations for loop
		var currentBitPos = 0;
		var numRandomBits = randomBits.length;
		var x = 0;
		var y = 0;				

		// Loop through all bits
		while (currentBitPos < numRandomBits)
		{
			//Get a bit
			var currentBit = randomBits.charAt(currentBitPos);

			// If the character is a binary 1
			if (currentBit == '1')
			{
				// Fill that pixel with black
				ctx.fillRect(x, y, 1, 1);
			}

			// If reached end of row, move to next row
			if (x == originalWidth - 1)
			{
				x = 0;
				y += 1;
			}
			else {
				// Increment horizontal canvas position
				x += 1;
			}

			// Get the next bit
			currentBitPos++;
		}
	}
};