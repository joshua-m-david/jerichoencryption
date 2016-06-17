/*!
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2016  Joshua M. David
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
 * True Random Number Generator (TRNG) to extract random data from photographs.
 * For full documentation see https://joshua-m-david.github.io/jerichoencryption/information.html#trng.
 */
var trng = {
	
	/** A jQuery selector for the TRNG image page container */
	$page: null,
		
	/** The first uploaded image */
	imageA: {
		canvas: null,			// The HTML5 canvas
		context: null,			// The 2D context of the image canvas
		canvasWidth: null,		// The canvas width
		canvasHeight: null,		// The canvas height
		loadComplete: false		// Whether the file has completed loading or not
	},
	
	/** The second uploaded image */
	imageB: {
		canvas: null,
		context: null,
		canvasWidth: null,
		canvasHeight: null,
		loadComplete: false
	},	
	
	/** The bits from the LSBs in both images XORed together */
	xoredEntropyBits: '',
	
	/** The bits after Von Neumann extraction of the XORed bits */
	extractedEntropyBits: '',
			
	/**
	 * Keep track of which tests are finished for which dataset
	 */
	finishedTests: {
		entropyA: false,			// Least significant bits in Image A
		entropyB: false,			// Least significant bits in Image B
		entropyXored: false,		// Least significant bits in Image A and Image B XORed together
		entropyExtracted: false		// Von Nuemann extractor run on the XORed bits
	},
	
	/**
	 * Initialise the page code
	 */
	init: function()
	{
		// Cache page selector for faster DOM lookups
		trng.$page = $('.trngImagePage');
		
		// Initialise the functionality
		trng.initBrowseFilesButton();
		trng.initResetButton();
		trng.initErrorHandler();
		trng.initProcessButton();
		exportPads.initExportPadsDialog();
	},
	
	/**
	 * When an image is uploaded, load it into HTML5 canvas
	 */
	initBrowseFilesButton: function()
	{
		// When the browse files button is clicked and files selected
		trng.$page.find('#imageLoader').change(function()
		{
			// Get the files
			var files = $(this)[0].files;
			
			// If the number of files is not exactly two
			if (files.length !== 2)
			{
				// Clear fields
				trng.$page.find('.fileNameA, .fileSizeA, .fileTypeA').text('');
				trng.$page.find('.fileNameB, .fileSizeB, .fileTypeB').text('');

				// Show an error
				common.showStatus('error', 'Please select exactly two images to load');

				// Exit early so the user fixes the issue
				return false;
			}
			
			// Remove previous warnings and errors
			trng.$page.find('.fileTypeA, .fileTypeB').removeClass('warning');
			common.hideStatus();
			
			// Start timer
			common.startTime = new Date();
			common.showProcessingMessage('Loading images, please wait...', false);
			
			// Load the two files
			trng.loadFileInformation(files[0], 'A');
			trng.loadFileInformation(files[1], 'B');			
		});
	},
	
	/**
	 * Loads the image file information and the image into HTML5 canvas on the page
	 * @param {Object} file An image file
	 * @param {String} id An identifier i.e. 'A' for imageA, 'B' for imageB
	 */
	loadFileInformation: function(file, id)
	{
		// Get the file name, size and type
		var fileName = file.name;
		var fileSize = common.formatNumberWithCommas(file.size);
		var fileType = file.type;		
		
		// Display the first file details
		trng.$page.find('.fileName' + id).text(fileName);
		trng.$page.find('.fileSize' + id).text(fileSize + ' bytes');
		trng.$page.find('.fileType' + id).text(fileType);				
		
		// If JPEG file type then show a warning with hover text
		if (fileType === 'image/jpeg')
		{
			trng.$page.find('.fileType' + id).addClass('warning');
			trng.$page.find('.fileType' + id).attr('title', 'For best results do not use JPEG files, '
			                                                 + 'use RAW files converted to PNG or BMP.');
		}
		
		// Initialise the image canvas and context
		trng['image' + id].canvas = document.getElementById('imageCanvas' + id);
		trng['image' + id].context = trng['image' + id].canvas.getContext('2d');
		
		// Load the images into the canvas
		trng.loadImageIntoCanvas(file, id);
	},
	
	/**
	 * Load the image into a canvas object on the page
	 * @param {Object} file The file object from the files array
	 * @param {String} id An identifier i.e. 'A' for imageA, 'B' for imageB
	 */
	loadImageIntoCanvas: function(file, id)
	{
		// Use HTML5 FileReader API
		var reader = new FileReader();

		// Callback when file is loaded
		reader.onload = function(event)
		{
			var image = new Image();

			// Once the image is loaded
			image.onload = function()
			{
				// Draw the image onto the canvas
				trng['image' + id].canvas.width = image.width;
				trng['image' + id].canvas.height = image.height;
				trng['image' + id].context.drawImage(image, 0, 0);

				// Calculate the number of pixels in image
				var totalPhotoPixels = image.width * image.height;
				var formattedTotalPhotoPixels = common.formatNumberWithCommas(totalPhotoPixels);

				// Show the heading, number of pixels in the image and the number of input entropy bits (same as the number of pixels)
				trng.$page.find('.collectionAmounts.image' + id + ' .totalPhotoPixels .statusBox').text(formattedTotalPhotoPixels);
				trng.$page.find('.collectionAmounts.image' + id + ' .totalEntropyInputBits .statusBox').text(formattedTotalPhotoPixels);

				// Notify that file loading is complete
				trng.showFileLoadingComplete(id);
			};

			// Display the image
			image.src = event.target.result;
		};

		// Upload from the page
		reader.readAsDataURL(file);
	},
	
	/**
	 * When loading of both files is complete, show a status message and enable other functionality. If files are of 
	 * different sizes, then they may finish loading out of normal order. This function makes sure both are loaded 
	 * before allowing the user to continue.
	 * @param {String} id A file identifier i.e. 'A' for image A, 'B' for image B
	 */
	showFileLoadingComplete: function(id)
	{
		// Set the loaded state of this image
		trng['image' + id].loadComplete = true;
		
		// If both images have finished loading
		if (trng['imageA'].loadComplete && trng['imageB'].loadComplete)
		{
			// Enable the Process and Restart buttons, disable the image selection button
			trng.$page.find('#processImage').removeAttr('disabled');
			trng.$page.find('#btnStartOver').removeAttr('disabled');
			trng.$page.find('#imageLoader').attr('disabled', true);
			trng.$page.find('.imageLoaderLabel').addClass('disabled');
			
			// Show the View image buttons
			trng.$page.find('.collectionAmounts.fileInfo').show();
			trng.showAndInitViewButton('btnViewOriginalImageA', 'originalImageHeaderA');
			trng.showAndInitViewButton('btnViewOriginalImageB', 'originalImageHeaderB');

			// Show a status message
			common.showStatus('success', 'Completed loading of images. Now you can visually ' +
			                             'inspect the images and process them when ready.', true);
		}
	},
	
	/**
	 * Shows a button e.g. View image, which when clicked will take you to view that image or the test results
	 * @param {String} buttonId The name of the button's id
	 * @param {String} contentId The name of the ID where the image or test results are
	 */
	showAndInitViewButton: function(buttonId, contentId)
	{
		// Show the button then add click handler
		trng.$page.find('#' + buttonId).click(function()
		{
			// Hide other results
			trng.$page.find('.outputAndResults > div').hide();
			
			// Show just the image or results they want to see
			trng.$page.find('#' + contentId).show();
		});
	},
		
	/**
	 * Reloads the page so the user can start a new upload
	 */
	initResetButton: function()
	{
		// On Reset button click
		trng.$page.find('#btnStartOver').click(function()
		{
			// Hard refresh the page (ignores browser cache)
			location.reload(true);
		});
	},
	
	/**
	 * Catch out of memory errors and display them to the user. Sometimes this can 
	 * happen when processing a large image and the machine runs out of memory or the 
	 * browser can't free old memory fast enough.
	 */
	initErrorHandler: function()
	{
		// Catch out of memory error if it occurs and display to the user
		window.onerror = function(error, url, line)
		{
			common.showStatus('error', 'Error occurred: ' + error + ' URL: ' + url + ' line: ' + line, true);
		};
	},
	
	/**
	 * Initialise the button to process the image, extract the entropy and run the tests
	 */
	initProcessButton: function()
	{
		// On the Process button click
		trng.$page.find('#processImage').click(function()
		{
			trng.processImages();
		});
	},
	
	/**
	 * Process the two images
	 */
	processImages: function()
	{
		// Start timer
		common.startTime = new Date();
		common.showProcessingMessage('Processing of images started, this may take a few minutes...', false);

		// Disable the button, as the canvas gets cleared after loading
		trng.$page.find('#processImage').attr('disabled', true);

		// Get RGBA image data array for both images
		var dataImageA = trng.getImageData('A');
		var dataImageB = trng.getImageData('B');
		
		// Start processing in the background using a web worker
		trng.startProcessingWebWorker(dataImageA, dataImageB);
	},
	
	/**
	 * Get the Red Green Blue Alpha (RGBA) pixel data from an image
	 * @param {String} id id A file identifier i.e. 'A' for image A and 'B' for image B
	 * @returns {Uint8ClampedArray} Returns a sequential array of bytes. Each pixel in the image is decoded to its 
	 *                              RGBA values e.g. [14, 233, 121, 0, ..., 8, 17, 255, 0]
	 */
	getImageData: function(id)
	{
		// Get the canvas width and height
		var canvasWidth = trng['image' + id].canvas.width;
		var canvasHeight = trng['image' + id].canvas.height;
		
		// Get the image data from the canvas as an array of sequential RGBA values		
		var imgDataArr = trng['image' + id].context.getImageData(0, 0, canvasWidth, canvasHeight).data;
						
		return imgDataArr;
	},
	
	/**
	 * Run a HTML5 web worker thread to run the extraction process because it is CPU intensive
	 * @param {Uint8ClampedArray} dataImageA The RGBA values for each pixel in the first image
	 * @param {Uint8ClampedArray} dataImageB The RGBA values for each pixel in the second image
	 */
	startProcessingWebWorker: function(dataImageA, dataImageB)
	{	
		// Setup the extraction worker
		var worker = common.startWebWorker('trng-extraction-worker');
				
		// When the worker is complete
		worker.addEventListener('message', function(event)
		{
			// Save the results from the worker and start the randomness tests
			trng.saveProcessingResults(event.data);
			trng.startRandomnessTests();
			
		}, false);
		
		// Send data to the worker
		worker.postMessage(
		{
			dataImageA: dataImageA,
			dataImageB: dataImageB
		});
	},
		
	/**
	 * Saves the worker processing results for later use to be exported, output to images and tests
	 * @@param {Object} workerData The processed results from the extraction web worker
	 */
	saveProcessingResults: function(workerData)
	{
		// Store the binary random bits
		exportPads.randomBitsFirstImageBinary = workerData.randomBitsFirstImageBinary;
		exportPads.randomBitsSecondImageBinary = workerData.randomBitsSecondImageBinary;
		exportPads.randomBitsXoredBinary = workerData.randomBitsXoredBinary;
		exportPads.randomBitsExtractedBinary = workerData.randomBitsExtractedBinary;
		
		// Store the hexadecimal version as well
		exportPads.randomBitsFirstImageHex = workerData.randomBitsFirstImageHex;		
		exportPads.randomBitsSecondImageHex = workerData.randomBitsSecondImageHex;
		exportPads.randomBitsXoredHex = workerData.randomBitsXoredHex;
		exportPads.randomBitsExtractedHex = workerData.randomBitsExtractedHex;
	},
				
	/**
	 * Wrapper function to start the randomness tests across all random data in a background worker
	 */
	startRandomnessTests: function()
	{		
		// Show current status
		common.showProcessingMessage('Completed randomness extraction. Starting randomness tests...', true);
				
		// Run the randomness tests on the least significant bits of the first image
		trngTests.init(exportPads.randomBitsFirstImageBinary, function(overallResults)
		{
			// On completion of the tests, notify that this set finished
			trng.displayTestResults('entropyA', overallResults, 'inputEntropyTestsPassImageA', 'leastSigBitsOverallResultLogImageA');
		});
		
		// Run the randomness tests on the least significant bits of the second image
		trngTests.init(exportPads.randomBitsSecondImageBinary, function(overallResults)
		{
			trng.displayTestResults('entropyB', overallResults, 'inputEntropyTestsPassImageB', 'leastSigBitsOverallResultLogImageB');
		});
		
		// Run the randomness tests on the least significant bits from both images XORed together
		trngTests.init(exportPads.randomBitsXoredBinary, function(overallResults)
		{
			trng.displayTestResults('entropyXored', overallResults, 'xoredEntropyTestsPass', 'leastSigBitsXoredOverallResultLog');
		});
		
		// Run the randomness tests on the random bits after Von Neumann extraction
		trngTests.init(exportPads.randomBitsExtractedBinary, function(overallResults)
		{
			trng.displayTestResults('entropyExtracted', overallResults, 'extractedTestsPass', 'extractedBitsOverallResultLog');
		});
	},
	
	/**
	 * Show the number of extracted bits and number of messages
	 * @param {String} nameOfCompletedTest The name of the completed test to keep track of which ones are finished
	 * @param {Object} overallResults Contains 'overallResult' pass/fail boolean, and the 'overallResultLog' which is the HTML test results
	 * @param {String} overallResultOutputId Where the overall result will be rendered after the tests are complete
	 * @param {String} overallResultLogOutputId Where the overall result logs will be rendered after the tests are complete
	 */
	displayTestResults: function(nameOfCompletedTest, overallResults, overallResultOutputId, overallResultLogOutputId)
	{
		// Set the test as completed
		trng.finishedTests[nameOfCompletedTest] = true;
		
		// Determine the CSS class
		var result = (overallResults.overallResult) ? 'passed' : 'failed';
		
		// Update the overall result in the header and display the test result logs on the page
		trng.$page.find('#' + overallResultOutputId).addClass(result).text(result);
		trng.$page.find('#' + overallResultLogOutputId).html(overallResults.overallResultLog);
		
		// If all the tests aren't finished yet, exit early
		if (!trng.finishedTests.entropyA || !trng.finishedTests.entropyB || !trng.finishedTests.entropyXored || !trng.finishedTests.entropyExtracted)
		{
			return false;
		}
		
		// If all the tests have now passed, calculate the number of bits collected then how many OTP messages can be sent
		var totalXoredBits = exportPads.randomBitsXoredBinary.length;
		var totalExtractedBits = exportPads.randomBitsExtractedBinary.length;
		var availableBitsForMessages = totalExtractedBits - exportPads.bitLengthOfKeysRequiredForExport;					
		var totalNumOfMessages = Math.floor(availableBitsForMessages / common.totalPadSizeBinary);
		
		// If the total number of messages is less than 0, show 0
		totalNumOfMessages = (totalNumOfMessages > 0) ? totalNumOfMessages : 0;

		// Format the values with the thousands separator
		totalXoredBits = common.formatNumberWithCommas(totalXoredBits);
		totalExtractedBits = common.formatNumberWithCommas(totalExtractedBits);
		totalNumOfMessages = common.formatNumberWithCommas(totalNumOfMessages);

		// Update the totals, activate the Export button
		trng.$page.find('.xoredEntropyBits .statusBox').text(totalXoredBits);
		trng.$page.find('.totalExtractedBits .statusBox').text(totalExtractedBits);
		trng.$page.find('.totalNumOfMessages .statusBox').text(totalNumOfMessages);
		trng.$page.find('#btnOpenExportPadsSettings').removeAttr('disabled');
		
		// If the total number of messages created is less than 2 then they didn't use large enough photos
		if (totalNumOfMessages < 2)
		{
			trng.$page.find('.totalNumOfMessages .statusBox').addClass('failed');
		}

		// Show current status
		common.showProcessingMessage('Completed randomness tests. Rendering bitmaps, this may ' +
									 'take a minute and the screen may go darker momentarily...', false);

		// Set a short timeout so the intermediate processing message above has time to display
		setTimeout(function()
		{				
			// Render the processed data as bitmaps and initialise the buttons for viewing the results
			trng.fillCanvasesWithRandomBits();
			trng.initViewResultsButtons();

			// Show all other totals and buttons in the header
			trng.$page.find('.collectionAmounts').show();

			// Show final complete status
			common.showStatus('success', 'Completed processing, randomness tests and bitmap rendering. '
									   + 'Click the view buttons above to see the results.', true);
		}, 300);
	},
		
	/**
	 * Wrapper function to fill all the canvases with random bits from 
	 * various stages of the process so they can be viewed for testing
	 */
	fillCanvasesWithRandomBits: function()
	{
		// Render random bits as images
		trngTests.fillCanvasWithBlackWhite('leastSigBitsBlackWhiteImageA', exportPads.randomBitsFirstImageBinary);
		trngTests.fillCanvasWithColour('leastSigBitsColourImageA', exportPads.randomBitsFirstImageBinary);
		
		trngTests.fillCanvasWithBlackWhite('leastSigBitsBlackWhiteImageB', exportPads.randomBitsSecondImageBinary);
		trngTests.fillCanvasWithColour('leastSigBitsColourImageB', exportPads.randomBitsSecondImageBinary);
				
		trngTests.fillCanvasWithBlackWhite('leastSigBitsXoredBlackWhite', exportPads.randomBitsXoredBinary);
		trngTests.fillCanvasWithColour('leastSigBitsXoredColour', exportPads.randomBitsXoredBinary);
		
		trngTests.fillCanvasWithBlackWhite('extractedBitsBlackWhite', exportPads.randomBitsExtractedBinary);
		trngTests.fillCanvasWithColour('extractedBitsColour', exportPads.randomBitsExtractedBinary);
	},		
		
	/**
	 * Wrapper function to initialise the buttons required for viewing the results. Each set of buttons will 
	 * do three things: show a colour bitmap of the random data, show a black and white bitmap of the random data 
	 * and show the results of the randomness tests run against that data.
	 */
	initViewResultsButtons: function()
	{
		// Initialise buttons for results of the least significant bits of image A
		trng.showAndInitViewButton('btnViewLeastSigBitsColourBitmapImageA', 'leastSigBitsColourBitmapImageA');
		trng.showAndInitViewButton('btnViewLeastSigBitsBitmapImageA', 'leastSigBitsBitmapImageA');
		trng.showAndInitViewButton('btnViewLeastSigBitsTestResultsImageA', 'leastSigBitsTestResultsImageA');

		// Initialise buttons for results of the least significant bits of image B
		trng.showAndInitViewButton('btnViewLeastSigBitsColourBitmapImageB', 'leastSigBitsColourBitmapImageB');
		trng.showAndInitViewButton('btnViewLeastSigBitsBitmapImageB', 'leastSigBitsBitmapImageB');
		trng.showAndInitViewButton('btnViewLeastSigBitsTestResultsImageB', 'leastSigBitsTestResultsImageB');

		// Initialise buttons for results of the XORed least significant bits from both images
		trng.showAndInitViewButton('btnViewLeastSigBitsXoredColourBitmap', 'leastSigBitsXoredColourBitmap');
		trng.showAndInitViewButton('btnViewLeastSigBitsXoredBitmap', 'leastSigBitsXoredBitmap');
		trng.showAndInitViewButton('btnViewLeastSigBitsXoredTestResults', 'leastSigBitsXoredTestResults');

		// Initialise buttons for results of the extracted bits
		trng.showAndInitViewButton('btnViewExtractedBitsColourBitmap', 'extractedBitsColourBitmap');
		trng.showAndInitViewButton('btnViewExtractedBitsBitmap', 'extractedBitsBitmap');
		trng.showAndInitViewButton('btnViewExtractedBitsTestResults', 'extractedBitsTestResults');
	}
};