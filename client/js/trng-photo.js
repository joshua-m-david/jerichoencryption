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
	
	// Image canvas settings
	uploadedImgCanvas: null,
	uploadedImgContext: null,
	imgDataArr: null,
	
	// Filtered RGB image data before processing
	dataset: [],
	
	// Extracted random data after processing
	extractedRandomDataBinary: '',
	extractedRandomDataHexadecimal: '',
	
	// Default user settings, configurable in TRNG
	hashAlgorithm: 'skein-512',			// The hash algorithm to use for randomness extraction
	entropyInputEstimatePerPixel: 1,	// Estimate of input entropy per pixel to a very conservative 1 bit per pixel
	
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
		trngImg.initExtractionSettingsDialog();
		common.initExportPadsDialog();
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
	 * Configure the TRNG Extraction Settings dialog to open
	 */
	initExtractionSettingsDialog: function()
	{	
		// Pluralise word if necessary and display
		var units = (trngImg.entropyInputEstimatePerPixel > 1) ? 'bits' : 'bit';			
		$("#inputEntropyBitsPerPixelAmount").html(trngImg.entropyInputEstimatePerPixel + ' ' + units + ' per RGB pixel');
				
		// Initialise slider for input entropy
		$('#inputEntropyBitsPerPixelSlider').slider(
		{
			min: 1,
			max: 3,
			value: trngImg.entropyInputEstimatePerPixel,
			slide: function(event, ui)
			{
				// Set it back in the object which is referenced later
				trngImg.entropyInputEstimatePerPixel = ui.value;
				
				// Pluralise word if necessary and display
				units = (trngImg.entropyInputEstimatePerPixel > 1) ? 'bits' : 'bit';
				$("#inputEntropyBitsPerPixelAmount").html(trngImg.entropyInputEstimatePerPixel + ' ' + units + ' per RGB pixel');
			}
		});
		
		// Build up the dropdown options to select which hash algorithm to use
		for (var i=0, length = common.macAlgorithms.length; i < length; i++)
		{
			var algorithm = common.macAlgorithms[i];
			$('<option>').val(algorithm).text(algorithm.replace(/-/g, ' ')).appendTo('#hashAlgorithmSelect');
		}
		
		// On change of dropdown option, set it back in the main object which is referenced later
		$('#hashAlgorithmSelect').change(function()
		{
			trngImg.hashAlgorithm = $(this).val();
		});
		
		// Configure button to open entropy collection settings dialog
		$('#btnOpenExtractionSettings').click(function()
		{					
			$('#extractionSettings').dialog('open');
		});

		// Configure entropy collection settings dialog
		$('#extractionSettings').dialog(
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
	 * Load the image into a canvas object on the page
	 * @param {object} eventObj The event object
	 */
	loadImageIntoCanvas: function(eventObj)
	{
	   // Start timer
	   common.startTime = new Date();
	   common.showProcessingMessage('Loading image, please wait...', false);

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
			   
			   // Show number of pixels in image
			   var totalPhotoPixels = common.formatNumberWithCommas(trngImg.canvasWidth * trngImg.canvasHeight);
			   $('#totalPhotoPixels .collectionStatusBox').html(totalPhotoPixels);

			   // Show a status message
			   common.showProcessingMessage('Completed loading of image. Now you can visually inspect the image and process it when ready.', false);
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
		trngImg.imgDataArr = trngImg.uploadedImgContext.getImageData(0, 0, trngImg.uploadedImgCanvas.width, trngImg.uploadedImgCanvas.height).data;
				
		// Initialisations
		var previousRed = null;
		var previousGreen = null;
		var previousBlue = null;
		var red = null;
		var green = null;
		var blue = null;
				
		// Current count of input entropy in the whole image
		var entropyInputTotal = 0;
		
		// Enumerate all RGBA values for each pixel which are stored in a sequential array 
		for (var i=0, length = trngImg.imgDataArr.length; i < length; i += 4)
		{
			// Get the separate red, green and blue pixels per colour
			red = this.imgDataArr[i];
			green = this.imgDataArr[i + 1];
			blue = this.imgDataArr[i + 2];
									
			// Filter out consecutive repeating underexposed pixels, overexposed pixels and any other 
			// repeating pixel colours (which is rare unless there is a failure in the camera hardware)
			if ((red === previousRed) && (green === previousGreen) && (blue === previousBlue)) {
				continue;
			}
			
			// Filter out the unnecessary alpha channel data and convert from 
			// Uint8ClampedArray to basic array so we can perform array manipulations
			trngImg['dataset'].push(red);		// Add red
			trngImg['dataset'].push(green);		// Add green
			trngImg['dataset'].push(blue);		// Add blue
			
			// Keep tally of how many pixels have been added to the current dataset
			entropyInputTotal += trngImg.entropyInputEstimatePerPixel;
			
			// Set the previous pixel colours to the current ones
			previousRed = red;
			previousGreen = green;
			previousBlue = blue;
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
				
		// Show status message
		$('#totalEntropyInputBits .collectionStatusBox').html(common.formatNumberWithCommas(entropyInputTotal));
		common.showProcessingMessage('Filtered underexposed, overexposed and consecutive repeating pixel colours. Now starting background extraction thread...', true);
				
		// Set a small timeout so the status message has time to display before intensive processing begins
		setTimeout(function()
		{			
			// Start the image processing by doing the processing work in a web worker
			trngImg.startProcessingWebWorker();
			
		}, 300);		
	},
	
	/**
	 * Run a HTML5 web worker thread to run the hash based randomness extractor because it is CPU intensive and will 
	 * block the UI otherwise. It will do the processing work in an inlined web worker which gets around the same origin 
	 * policy problem when loading a web worker from a different file path in Chromium:
	 * http://stackoverflow.com/a/18490502
	 * http://www.html5rocks.com/en/tutorials/workers/basics/#toc-inlineworkers
	 */
	startProcessingWebWorker: function()
	{
		// Convert the base URL so the web worker can import the common.js script
		// Also load the JavaScript code on the HTML page which is what the worker will run
		var baseUrl = window.location.href.replace(/\\/g, '/').replace(/\/[^\/]*$/, '');
        var array = ['var baseUrl = "' + baseUrl + '";' + $('#trng-extraction-worker').html()];
		
		// Create a Blob to hold the JavaScript code and send it to the inline worker
        var blob = new Blob(array, { type: "text/javascript" });
		var blobUrl = window.URL.createObjectURL(blob);
		var worker = new Worker(blobUrl);
				
		// When the worker is complete
		worker.addEventListener('message', function(event)
		{
			// Store the data once to save memory, then render the processed data onto the page
			common.randomDataBinary = event.data.extractedRandomDataBinary;
			common.randomDataHexadecimal = event.data.extractedRandomDataHexadecimal;
			
			// Start the randomness tests and render the processed and extracted images
			trngImg.startRandomnessTests();
			
		}, false);
		
		// Worker error handler
		worker.addEventListener('error', function(e)
		{
			console.log('ERROR: Line ' + e.lineno + ' in ' + e.filename + ': ' + e.message);
			
		}, false);
		
		// Send data to the worker
		worker.postMessage({
			hashAlgorithm: trngImg.hashAlgorithm,
			entropyInputEstimatePerPixel: trngImg.entropyInputEstimatePerPixel,
			dataset: trngImg.dataset
		});
								
		// Free up memory
		delete trngImg.dataset;
		window.URL.revokeObjectURL(blobUrl);
	},
	
	/**
	 * Start the randomness tests in a background worker
	 */
	startRandomnessTests: function()
	{
		// Show current status
		common.showProcessingMessage('Completed randomness extraction. Starting randomness tests...', true);
		
		// Run the randomness tests in FIPS 140-2 on the extracted data
		randomTests.init(common.randomDataBinary, 'extractedOverallResult', 'extractedOverallResultLog', 'FIPS-140-2', function()
		{			
			// On completion of the tests, display the test results
			trngImg.displayProccessingStats();
		});
	},
		
	/**
	 * Show the number of extracted bits and number of messages
	 */
	displayProccessingStats: function()
	{
		// Show current status
		common.showProcessingMessage('Completed randomness extraction and tests.', true);
		
		// Calculate the collected data
		var totalExtractedBits = common.randomDataBinary.length;
		var totalNumOfMessages = Math.floor(totalExtractedBits / common.totalPadSizeBinary);
		
		// Format the values with the thousands separator
		totalExtractedBits = common.formatNumberWithCommas(totalExtractedBits);
		totalNumOfMessages = common.formatNumberWithCommas(totalNumOfMessages);
		
		// Show the other headings and update the totals
		$('#totalExtractedBits .collectionStatusBox').html(totalExtractedBits);
		$('#totalNumOfMessages .collectionStatusBox').html(totalNumOfMessages);
				
		// Show current status
		common.showProcessingMessage('Completed randomness extraction and tests. Now rendering extracted image...', true);
		
		// Make sure the status has updated, then render the image which can take a while if it is large
		setTimeout(function()
		{
			// Show the other headings and activate the other buttons
			$('h3.processedHeading').show();
			$('#btnOpenExportPadsSettings').removeAttr('disabled');
			$('.testingButtons').addClass('active');

			// Render the extracted data to a new HTML5 canvas
			trngImg.fillCanvasWithData(trngImg.extractedOutputCanvasId, common.randomDataBinary);

			// Final status
			common.showProcessingMessage('Processing complete.', true);
			
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