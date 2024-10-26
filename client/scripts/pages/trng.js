/*!
 * Jericho Comms - Information-theoretically secure communications
 * Copyright (c) 2013-2024  Joshua M. David
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
 * True Random Number Generator (TRNG) to extract random data from two photographs then whiten the results.
 * For full documentation see https://joshua-m-david.github.io/jerichoencryption/information.html#trngPage.
 */
var trngPage = {

	/** The first uploaded image */
	imageA: {
		canvas: null,        // The HTML5 canvas
		context: null,       // The 2D context of the image canvas
		canvasWidth: null,   // The canvas width
		canvasHeight: null,  // The canvas height
		loadComplete: false  // Whether the file has completed loading or not
	},

	/** The second uploaded image */
	imageB: {
		canvas: null,
		context: null,
		canvasWidth: null,
		canvasHeight: null,
		loadComplete: false
	},

	/** How many repeating/stuck pixels in the same location when comparing the two images */
	repeatingPixelCount: 0,

	/**
	 * Maximum percentage allowed (0.0001 %) of total repeating/stuck pixels in the same location
	 * in both images. For a 3000 x 4000 pixel image (120,000,000 pixels) this is about 12 pixels.
	 * Ideally there are no repeating/stuck pixels but it can happen by coincidence. If there are
	 * a small number it does not affect the security, the Von Neumann extractor is still run.
	 */
	maxSafeRepeatingPixelsMultiplier: 0.000001,

	/** An overlay of the first image with red pixels to show where the stuck/repeating pixels are */
	repeatingPixelDataImage: null,

	/**
	 * Keep track of which tests are finished for which dataset
	 */
	finishedTests: {
		entropyA: false,        // Least significant bits in Image A
		entropyB: false,        // Least significant bits in Image B
		entropyXored: false,    // Least significant bits in Image A and Image B XORed together
		entropyExtracted: false // Von Neumann extractor run on the XORed bits
	},

	/**
	 * The final test results for each dataset
	 */
	allFinishedTestResults: {
		entropyA: { allTestsPassed: false },        // Least significant bits in Image A
		entropyB: { allTestsPassed: false },        // Least significant bits in Image B
		entropyXored: { allTestsPassed: false },    // Least significant bits in Image A and Image B XORed together
		entropyExtracted: { allTestsPassed: false } // Von Neumann extractor run on the XORed bits
	},

	/**
	 * Initialise the page code
	 */
	init: function()
	{
		// Initialise the generic functionality
		trngPage.initBrowseFilesButton();
		trngPage.initResetButton();
		trngPage.initErrorHandler();
		trngPage.initProcessButton();

		// Initialise View buttons to show the repeating/stuck pixel locations
		trngPage.initViewRepeatingPixelIndexesButton();
		trngPage.initViewRepeatingPixelsImageButton();

		/**
		 * Initialise the View buttons to show the Least Significant Bits collected from the first and
		 * second images as black and white bitmaps using the original dimensions of the images
		 */
		trngPage.initBlackWhiteOriginalDimensionsImageViewButton({
			buttonClassName: 'jsViewLeastSigBitsBitmapImageButtonA',
			contentAnchorClassName: 'jsLeastSigBitsBitmapImageA',
			canvasClassName: 'jsLeastSigBitsBlackWhiteImageA',
			randomBitsName: 'randomBitsFirstImageBinary',
			originalImageName: 'imageA'
		});
		trngPage.initBlackWhiteOriginalDimensionsImageViewButton({
			buttonClassName: 'jsViewLeastSigBitsBitmapImageButtonB',
			contentAnchorClassName: 'jsLeastSigBitsBitmapImageB',
			canvasClassName: 'jsLeastSigBitsBlackWhiteImageB',
			randomBitsName: 'randomBitsSecondImageBinary',
			originalImageName: 'imageB'
		});

		/**
		 * Initialise the View buttons to show the bits collected as square black and white bitmaps
		 */
		trngPage.initBlackWhiteSquareDimensionsImageViewButton({
			buttonClassName: 'jsViewLeastSigBitsXoredBitmapButton',
			contentAnchorClassName: 'jsLeastSigBitsXoredBitmap',
			canvasClassName: 'jsLeastSigBitsXoredBlackWhite',
			randomBitsName: 'randomBitsXoredBinary'
		});
		trngPage.initBlackWhiteSquareDimensionsImageViewButton({
			buttonClassName: 'jsViewExtractedBitsBitmapButton',
			contentAnchorClassName: 'jsExtractedBitsBitmap',
			canvasClassName: 'jsExtractedBitsBlackWhite',
			randomBitsName: 'randomBitsExtractedBinary'
		});

		/**
		 * Initialise the View buttons to show the bits collected as colour bitmaps
		 */
		trngPage.initColourImageViewButton({
			buttonClassName: 'jsViewLeastSigBitsColourBitmapImageButtonA',
			contentAnchorClassName: 'jsLeastSigBitsColourBitmapImageA',
			canvasClassName: 'jsLeastSigBitsColourImageA',
			randomBitsName: 'randomBitsFirstImageBinary'
		});
		trngPage.initColourImageViewButton({
			buttonClassName: 'jsViewLeastSigBitsColourBitmapImageButtonB',
			contentAnchorClassName: 'jsLeastSigBitsColourBitmapImageB',
			canvasClassName: 'jsLeastSigBitsColourImageB',
			randomBitsName: 'randomBitsSecondImageBinary'
		});
		trngPage.initColourImageViewButton({
			buttonClassName: 'jsViewLeastSigBitsXoredColourBitmapButton',
			contentAnchorClassName: 'jsLeastSigBitsXoredColourBitmap',
			canvasClassName: 'jsLeastSigBitsXoredColour',
			randomBitsName: 'randomBitsXoredBinary'
		});
		trngPage.initColourImageViewButton({
			buttonClassName: 'jsViewExtractedBitsColourBitmapButton',
			contentAnchorClassName: 'jsExtractedBitsColourBitmap',
			canvasClassName: 'jsExtractedBitsColour',
			randomBitsName: 'randomBitsExtractedBinary'
		});

		// Initialise View buttons for showing results of the testing
		trngPage.initShowTestResultsButton({
			buttonClassName: 'jsViewLeastSigBitsTestResultsImageButtonA',
			contentAnchorClassName: 'jsLeastSigBitsTestResultsImageA'
		});
		trngPage.initShowTestResultsButton({
			buttonClassName: 'jsViewLeastSigBitsTestResultsImageButtonB',
			contentAnchorClassName: 'jsLeastSigBitsTestResultsImageB'
		});
		trngPage.initShowTestResultsButton({
			buttonClassName: 'jsViewLeastSigBitsXoredTestResultsButton',
			contentAnchorClassName: 'jsLeastSigBitsXoredTestResults'
		});
		trngPage.initShowTestResultsButton({
			buttonClassName: 'jsViewExtractedBitsTestResultsButton',
			contentAnchorClassName: 'jsExtractedBitsTestResults'
		});

		// Initialise the Show test results button
		trngPage.initShowTestsSummaryButton();

		// Initialise the export dialog
		exportPads.initExportPadsDialog();
	},

	/**
	 * When an image is uploaded, load it into HTML5 canvas
	 */
	initBrowseFilesButton: function()
	{
		// When the browse files button is clicked and files selected
		query.getCached('.jsImageLoader').on('change', function()
		{
			// Get the files
			var files = $(this).get(0).files;

			// If the number of files is not exactly two
			if (files.length !== 2)
			{
				// Clear the file name, size and type fields
				query.getCached('.jsFileNameA, .jsFileNameB').text('');
				query.getCached('.jsFileSizeA, .jsFileSizeB').text('');
				query.getCached('.jsFileTypeA, .jsFileTypeB').text('');

				// Show an error
				app.showStatus('error', 'Please select exactly two images to load');

				// Exit early so the user fixes the issue
				return false;
			}

			// Remove previous warnings and errors
			query.getCached('.jsFileTypeA, .jsFileTypeB').removeClass('isWarning');
			app.hideStatus();

			// Start timer
			app.startTime = new Date();
			app.showProcessingMessage('Loading images, please wait...', false);

			// Load the two files
			trngPage.loadFileInformation(files[0], 'A');
			trngPage.loadFileInformation(files[1], 'B');
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
		query.getCached('.jsFileName' + id).text(fileName);
		query.getCached('.jsFileSize' + id).text(fileSize + ' bytes');
		query.getCached('.jsFileType' + id).text(fileType);

		// If JPEG file type then show a warning with hover text
		if (fileType === 'image/jpeg')
		{
			query.getCached('.jsFileType' + id).addClass('isWarning');
			query.getCached('.jsFileType' + id).attr('title', 'For security do not use JPEG files, ' +
			                                         'use RAW files converted to PNG or BMP.');
		}

		// Initialise the image canvas and context
		trngPage['image' + id].canvas = document.querySelector('.jsImageCanvas' + id);
		trngPage['image' + id].context = trngPage['image' + id].canvas.getContext('2d');

		// Load the images into the canvas
		trngPage.loadImageIntoCanvas(file, id);
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
				trngPage['image' + id].canvas.width = image.width;
				trngPage['image' + id].canvas.height = image.height;
				trngPage['image' + id].context.drawImage(image, 0, 0);

				// Calculate the number of pixels in image
				var totalPhotoPixels = image.width * image.height;
				var formattedTotalPhotoPixels = common.formatNumberWithCommas(totalPhotoPixels);

				// Show the heading, number of pixels in the image and the number of input entropy bits (same as the number of pixels)
				query.getCached('.jsTotalPixelsImage' + id).text(formattedTotalPhotoPixels);
				query.getCached('.jsTotalEntropyInputBitsImage' + id).text(formattedTotalPhotoPixels);

				// Notify that file loading is complete
				trngPage.showFileLoadingComplete(id);
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
		trngPage['image' + id].loadComplete = true;

		// If both images have finished loading
		if (trngPage.imageA.loadComplete && trngPage.imageB.loadComplete)
		{
			// Enable the Process and Restart buttons, disable the image selection button
			query.getCached('.jsProcessImageButton').prop('disabled', false);
			query.getCached('.jsStartOverButton').prop('disabled', false);
			query.getCached('.jsImageLoader').prop('disabled', true);
			query.getCached('.jsImageLoaderLabel').addClass('disabled');

			// Show the View image buttons
			query.getCached('.jsFileInfo').show();
			trngPage.showAndInitViewButton('jsViewOriginalImageButtonA', 'jsOriginalImageHeaderA');
			trngPage.showAndInitViewButton('jsViewOriginalImageButtonB', 'jsOriginalImageHeaderB');

			// Show a status message
			app.showStatus('success', 'Completed loading of images. Now you can visually ' +
			               'inspect the images and process them when ready.', true);
		}
	},

	/**
	 * Shows a button e.g. View image, which when clicked will take you to view that image or the test results
	 * @param {String} buttonClassName The class name of the button
	 * @param {String} contentAnchorClassName The class name of where the image or test results are
	 */
	showAndInitViewButton: function(buttonClassName, contentAnchorClassName)
	{
		// Show the button then add click handler
		query.getCached('.' + buttonClassName).on('click', function()
		{
			// Show Rendering... text
			$(this).addClass('loading');

			// Set a short timeout so the loading text shows on the button
			setTimeout(() =>
			{
				// Hide other results
				query.getCached('.jsOutputAndResults > div').hide();

				// Show just the image or results they want to see
				query.getCached('.' + contentAnchorClassName).show();

				// Revert the button state to normal
				$(this).removeClass('loading');

			}, 30);
		});
	},

	/**
	 * Initialise the button to show what array index the repeating pixels occur at. This is useful for determining
	 * whether different sets of images are having issues at the same location, or whether it is just random occurrence.
	 * Sometimes it is hard to determine just looking at the red pixels overlayed on the original image alone.
	 */
	initViewRepeatingPixelIndexesButton: function()
	{
		// Show the button then add click handler
		query.getCached('.jsShowRepeatingPixelIndexesButton').on('click', function()
		{
			// Hide other results
			query.getCached('.jsOutputAndResults > div').hide();

			// If the image has already been rendered, don't re-render just show the image
			if ($(this).hasClass('loaded'))
			{
				// Show just the image or results they want to see
				query.getCached('.jsRepeatingPixelIndexesHeader').show();

				return true;
			}

			// Show loading text
			$(this).addClass('loading');

			// Set a short timeout so the loading text shows on the button
			setTimeout(() =>
			{
				// Join the indexes with commas in between e.g. 45, 1203, 3337
				var repeatingIndexes = trngPage.repeatingPixelIndexes.join(', ');

				// Store in the HTML (the button will show if requested), then show the pixel indexes
				query.getCached('.jsRepeatingPixelIndexes').text(repeatingIndexes);
				query.getCached('.jsRepeatingPixelIndexesHeader').show();

				// Set a flag to show it's already been rendered, then next time it can just be shown.
				// Also revert the button state to normal.
				$(this).addClass('loaded').removeClass('loading');

			}, 30);
		});
	},

	/**
	 * Initialise the button to show the repeating/stuck pixels in the same location in both images.
	 * Red pixels will be placed over top of the first original image where there were repeating/stuck pixels.
	 */
	initViewRepeatingPixelsImageButton: function()
	{
		// Show the button then add click handler
		query.getCached('.jsViewRepeatingPixelsButton').on('click', function()
		{
			// If the image has already been rendered, don't re-render just show the image
			if ($(this).hasClass('loaded'))
			{
				// Show just the image or results they want to see
				query.getCached('.jsRepeatingPixelsHeader').show();

				return true;
			}

			// Show loading text
			$(this).addClass('loading');

			// Set a short timeout so the loading text shows on the button
			setTimeout(() =>
			{
				// Get the height and width of the first image
				var imageHeight = trngPage['imageA'].canvas.height;
				var imageWidth = trngPage['imageA'].canvas.width;

				// Create object to be put directly into the canvas
				var imageData = new ImageData(trngPage.repeatingPixelDataImage, imageWidth, imageHeight);

				// Set new canvas dimensions
				query.getCached('.jsRepeatingPixelsCanvas').prop(
				{
					width: imageWidth,
					height: imageHeight
				});

				// Get the context
				var context = query.getCached('.jsRepeatingPixelsCanvas').get(0).getContext('2d');

				// Display the image
				context.putImageData(imageData, 0, 0);

				// Hide other results, show just the image or results they want to see
				query.getCached('.jsOutputAndResults > div').hide();
				query.getCached('.jsRepeatingPixelsHeader').show();

				// Show button as normal
				$(this).addClass('loaded').removeClass('loading');

			}, 30);
		});
	},

	/**
	 * Initialise the button to show the bits as a black and white bitmap. The image dimensions will be the same as
	 * the original image to more easily show the differences after obtaining the least significant bits. Strings are
	 * used as parameters so that the actual evaluation of the function is not run until all the data has been generated
	 * and the button is clicked.
	 * @param {Object} config The config to use with keys:
	 *     {String} buttonClassName The CSS class name of the button to click on to trigger the image to show
	 *     {String} contentAnchorClassName The CSS class name of the anchor id to show the content
	 *     {String} canvasClassName The CSS class name of the canvas where the random bits will be rendered
	 *     {String} randomBitsName The name of the variable containing the random bits to be rendered into the canvas
	 *     {String} originalImageName The name of the variable containing the original image canvas details
	 */
	initBlackWhiteOriginalDimensionsImageViewButton: function(config)
	{
		// Show the button then add click handler
		query.getCached('.' + config.buttonClassName).on('click', function()
		{
			// If the image has already been rendered, don't re-render just show the image
			if ($(this).hasClass('loaded'))
			{
				// Hide other results, then show just the image or results they want to see
				query.getCached('.jsOutputAndResults > div').hide();
				query.getCached('.' + config.contentAnchorClassName).show();

				// All done, return early
				return true;
			}

			// Show loading text
			$(this).addClass('loading');

			// Set a short timeout so the loading text shows on the button
			setTimeout(() =>
			{
				// Show the image
				trngTests.fillCanvasWithBlackWhiteUsingOriginalDimensions(
					config.canvasClassName,
					exportPads[config.randomBitsName],
					trngPage[config.originalImageName].canvas.width,
					trngPage[config.originalImageName].canvas.height,
				);

				// Hide other results, then show just the image
				query.getCached('.jsOutputAndResults > div').hide();
				query.getCached('.' + config.contentAnchorClassName).show();

				// Set a flag to show it's already been rendered, then next time it can just be shown.
				// Also revert the button state to normal.
				$(this).addClass('loaded').removeClass('loading');

			}, 30);
		});
	},

	/**
	 * Initialise the button to show the bits as a black and white bitmap. The image dimensions will be a square as the
	 * amount of data after extraction may be different to the original image. Strings are used as parameters so
	 * that the actual evaluation of the function is not run until all the data has been generated and the button is
	 * clicked.
	 * @param {Object} config The config to use with keys:
	 *     {String} buttonClassName The CSS class name of the button to click on to trigger the image to show
	 *     {String} contentAnchorClassName The CSS class name of the anchor id to show the content
	 *     {String} canvasClassName The CSS class name of the canvas where the random bits will be rendered
	 *     {String} randomBitsName The name of the variable containing the random bits to be rendered into the canvas
	 */
	initBlackWhiteSquareDimensionsImageViewButton: function(config)
	{
		// Show the button then add click handler
		query.getCached('.' + config.buttonClassName).on('click', function()
		{
			// If the image has already been rendered, don't re-render just show the image
			if ($(this).hasClass('loaded'))
			{
				// Hide other results, then show just the image or results they want to see
				query.getCached('.jsOutputAndResults > div').hide();
				query.getCached('.' + config.contentAnchorClassName).show();

				// All done, return early
				return true;
			}

			// Show loading text
			$(this).addClass('loading');

			// Set a short timeout so the loading text shows on the button
			setTimeout(() =>
			{
				// Show the image
				trngTests.fillCanvasWithBlackWhite(
					config.canvasClassName,
					exportPads[config.randomBitsName],
				);

				// Hide other results, then show just the image
				query.getCached('.jsOutputAndResults > div').hide();
				query.getCached('.' + config.contentAnchorClassName).show();

				// Set a flag to show it's already been rendered, then next time it can just be shown.
				// Also revert the button state to normal.
				$(this).addClass('loaded').removeClass('loading');

			}, 30);
		});
	},

	/**
	 * Initialise the button to show the bits as a colour bitmap. The image dimensions will be shown as a square
	 * because there is not a direct mapping of height and width back to the original image/s.
	 * @param {Object} config The config to use with keys:
	 *     {String} buttonClassName The CSS class name of the button to click on to trigger the image to show
	 *     {String} contentAnchorClassName The CSS class name of the anchor id to show the content
	 *     {String} canvasClassName The CSS class name of the canvas where the random bits will be rendered
	 *     {String} randomBitsName The name of the variable in the exportPads namespace containing the random bits
	 */
	initColourImageViewButton: function(config)
	{
		// Show the button then add click handler
		query.getCached('.' + config.buttonClassName).on('click', function()
		{
			// If the image has already been rendered, don't re-render just show the image
			if ($(this).hasClass('loaded'))
			{
				// Hide other results, then show just the image or results they want to see
				query.getCached('.jsOutputAndResults > div').hide();
				query.getCached('.' + config.contentAnchorClassName).show();

				// All done, the image is now shown
				return true;
			}

			// Show loading text
			$(this).addClass('loading');

			// Set a short timeout so the Rendering... text shows on the button
			setTimeout(() =>
			{
				// Show the image
				trngTests.fillCanvasWithColour(config.canvasClassName, exportPads[config.randomBitsName]);

				// Hide other results, then show just the image
				query.getCached('.jsOutputAndResults > div').hide();
				query.getCached('.' + config.contentAnchorClassName).show();

				// Set a flag to show it's already been rendered, then next time it can just be shown.
				// Also revert the button state to normal.
				$(this).addClass('loaded').removeClass('loading');

			}, 30);
		});
	},

	/**
	 * Initialise the button to show the test results for each group of entropy tests
	 * @param {Object} config The config to use with keys:
	 *     {String} buttonClassName The CSS class name of the button to click on to trigger the results to show
	 *     {String} contentAnchorClassName The CSS class name of the anchor id to show the content
	 */
	initShowTestResultsButton: function(config)
	{
		// Show the button then add click handler
		query.getCached('.' + config.buttonClassName).on('click', function()
		{
			// Show loading text
			$(this).addClass('loading');

			// Set a short timeout so the Rendering... text shows on the button
			setTimeout(() =>
			{
				// Hide other results, then show just the results requested
				query.getCached('.jsOutputAndResults > div').hide();
				query.getCached('.' + config.contentAnchorClassName).show();

				// Revert the button state to normal
				$(this).removeClass('loading');

			}, 30);
		});
	},

	/**
	 * Reloads the page so the user can start a new upload
	 */
	initResetButton: function()
	{
		// On Reset/Restart button click
		query.getCached('.jsStartOverButton').on('click', function()
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
			app.showStatus('error', 'Error occurred: ' + error + '. URL: ' + url + ' line: ' + line, true);
		};
	},

	/**
	 * Initialise the button to process the image, extract the entropy and run the tests
	 */
	initProcessButton: function()
	{
		// On the Process button click
		query.getCached('.jsProcessImageButton').on('click', function()
		{
			trngPage.processImages();
		});
	},

	/**
	 * Process the two images
	 */
	processImages: function()
	{
		// Start timer
		app.startTime = new Date();
		app.showProcessingMessage('Processing of images started, this may take a few minutes...', false);

		// Disable the button, as the canvas gets cleared after loading
		query.getCached('.jsProcessImageButton').attr('disabled', true);

		// Get RGBA image data array for both images
		var dataImageA = trngPage.getImageData('A');
		var dataImageB = trngPage.getImageData('B');

		// Start processing in the background using a web worker
		trngPage.startProcessingWebWorker(dataImageA, dataImageB);
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
		var canvasWidth = trngPage['image' + id].canvas.width;
		var canvasHeight = trngPage['image' + id].canvas.height;

		// Get the image data from the canvas as an array of sequential RGBA values
		var imgDataArr = trngPage['image' + id].context.getImageData(0, 0, canvasWidth, canvasHeight).data;

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
			trngPage.saveProcessingResults(event.data);
			trngPage.startRandomnessTests();

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
		// Store the repeating/stuck pixel locations
		trngPage.repeatingPixelIndexes = workerData.repeatingPixelIndexes;
		trngPage.repeatingPixelDataImage = workerData.repeatingPixelDataImage;

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
		app.showProcessingMessage('Completed randomness extraction. Starting randomness tests...', true);

		// Run the randomness tests on the least significant bits of the first image
		trngTests.init(exportPads.randomBitsFirstImageBinary, function(overallResults)
		{
			// On completion of the tests, notify that this set finished
			trngPage.displayTestResults('entropyA', overallResults, 'jsInputEntropyTestsPassImageA', 'jsLeastSigBitsOverallResultLogImageA');
		});

		// Run the randomness tests on the least significant bits of the second image
		trngTests.init(exportPads.randomBitsSecondImageBinary, function(overallResults)
		{
			trngPage.displayTestResults('entropyB', overallResults, 'jsInputEntropyTestsPassImageB', 'jsLeastSigBitsOverallResultLogImageB');
		});

		// Run the randomness tests on the least significant bits from both images XORed together
		trngTests.init(exportPads.randomBitsXoredBinary, function(overallResults)
		{
			trngPage.displayTestResults('entropyXored', overallResults, 'jsXoredEntropyTestsPass', 'jsLeastSigBitsXoredOverallResultLog');
		});

		// Run the randomness tests on the random bits after Von Neumann extraction
		trngTests.init(exportPads.randomBitsExtractedBinary, function(overallResults)
		{
			trngPage.displayTestResults('entropyExtracted', overallResults, 'jsExtractedTestsPass', 'jsExtractedBitsOverallResultLog');
		});
	},

	/**
	 * Show the number of extracted bits and number of messages
	 * @param {String} nameOfCompletedTest The name of the completed test to keep track of which ones are finished
	 * @param {Object} allResults Contains 'overallResult' pass/fail boolean, and the 'overallResultLog' which is the HTML test results
	 * @param {String} overallResultOutputClassName Where the overall result will be rendered after the tests are complete
	 * @param {String} overallResultLogOutputClassName Where the overall result logs will be rendered after the tests are complete
	 */
	displayTestResults: function(nameOfCompletedTest, allResults, overallResultOutputClassName, overallResultLogOutputClassName)
	{
		// Set the test as completed and cache the results for checking later
		trngPage.finishedTests[nameOfCompletedTest] = true;
		trngPage.allFinishedTestResults[nameOfCompletedTest].allTestsPassed = allResults.allTestsPassed;

		// Determine the CSS class
		var resultText = (allResults.allTestsPassed) ? 'success' : 'failure';
		var resultClassName = (allResults.allTestsPassed) ? 'isSuccess' : 'isFailed';

		// Generate the HTML to be rendered
		var outputHtml = trngTests.generateTestLogOutputHtml(allResults);

		// Update the overall result in the header and display the test result logs on the page
		query.getCached('.' + overallResultOutputClassName).addClass(resultClassName).text(resultText);
		query.getCached('.' + overallResultLogOutputClassName).append(outputHtml);

		// If all the tests aren't finished yet, exit early
		if (!trngPage.finishedTests.entropyA || !trngPage.finishedTests.entropyB || !trngPage.finishedTests.entropyXored || !trngPage.finishedTests.entropyExtracted)
		{
			return false;
		}

		// Show final totals and summary of everything
		trngPage.showFinalSummary();
	},

	/**
	 * Show final totals and summary of everything
	 */
	showFinalSummary: function()
	{
		// Show if is recommended to use the extracted data for messaging or not
		var isRecommendedToUse = true;
		var notRecommendedReasons = [];

		// If all the tests have now passed, calculate the number of bits collected then how many OTP messages can be sent
		var totalRepeatingPixels = trngPage.repeatingPixelIndexes.length;
		var totalXoredBits = exportPads.randomBitsXoredBinary.length;
		var totalExtractedBits = exportPads.randomBitsExtractedBinary.length;
		var availableBitsForMessages = totalExtractedBits - exportPads.bitLengthOfKeysRequiredForExport;
		var totalNumOfMessages = Math.floor(availableBitsForMessages / common.totalPadSizeBinary);

		// If the total number of messages is less than 0, show 0
		totalNumOfMessages = (totalNumOfMessages > 0) ? totalNumOfMessages : 0;

		// Format the values with the thousands separator
		var totalRepeatingPixelsFormatted = common.formatNumberWithCommas(totalRepeatingPixels);
		var totalXoredBitsFormatted = common.formatNumberWithCommas(totalXoredBits);
		var totalExtractedBitsFormatted = common.formatNumberWithCommas(totalExtractedBits);
		var totalNumOfMessagesFormatted = common.formatNumberWithCommas(totalNumOfMessages);

		// Update the totals, activate the Export button
		query.getCached('.jsTotalRepeatingPixels').text(totalRepeatingPixelsFormatted);
		query.getCached('.jsTotalXoredEntropyBits').text(totalXoredBitsFormatted);
		query.getCached('.jsTotalExtractedBits').text(totalExtractedBitsFormatted);
		query.getCached('.jsTotalNumOfMessages').text(totalNumOfMessagesFormatted);

		// Activate the Export and Show Test Results button
		query.getCached('.jsOpenExportPadsSettingsButton').prop('disabled', false);
		query.getCached('.jsShowTestsSummaryButton').prop('disabled', false);

		// Check if at least 2 messages can be sent (1 in either direction)
		// If the total number of messages created is less than this then they didn't use large enough photos
		if (totalNumOfMessages < 2)
		{
			// Set to red on number of messages
			query.getCached('.jsTotalNumOfMessages').addClass('isFailed');

			// Don't recommend to use
			isRecommendedToUse = false;
			notRecommendedReasons.push('Not enough messages for basic communication.');
		}

		// If there are no repeating/stuck pixels, change to green to indicate no issues
		if (totalRepeatingPixels === 0)
		{
			query.getCached('.jsTotalRepeatingPixels').addClass('isSuccess');
		}
		else {
			// Get the total number of pixels in both images, then use the number of pixels in the smallest image
			var totalPixelsInFirstImage = trngPage.imageA.canvas.width * trngPage.imageA.canvas.height;
			var totalPixelsInSecondImage = trngPage.imageB.canvas.width * trngPage.imageB.canvas.height;
			var leastNumOfPixels = (totalPixelsInFirstImage < totalPixelsInSecondImage) ? totalPixelsInFirstImage : totalPixelsInSecondImage;

			// If there are repeating pixels in the same location in the two photos then they need to try a different
			// combination of photos or even get a photo from a different camera (in the case of bad sensor / stuck
			// pixels). With large images of many megapixels there is a reasonable probability that there might be a
			// few pixels of the same colour in the same index in random locations, especially if there is sunlight in
			// the photo, so a small amount is ok as the Von Neumann extractor is still run afterwards anyway.
			var maxSafeRepeatingPixels = Math.round(leastNumOfPixels * trngPage.maxSafeRepeatingPixelsMultiplier);
			var styleClass = (totalRepeatingPixels <= maxSafeRepeatingPixels) ? 'isWarning' : 'isFailed';
			var titleMessage = 'Maximum of ' + maxSafeRepeatingPixels + ' is acceptable for these images. If there are '
			                 + 'more, try a different combination of photos or use photos from different cameras.';

			// Add style class and show on hover information warning
			query.getCached('.jsTotalRepeatingPixels').addClass(styleClass);
			query.getCached('.jsTotalRepeatingPixels').prop('title', titleMessage);

			// Don't recommend to use if too many repeating/stuck pixels
			if (totalRepeatingPixels > maxSafeRepeatingPixels)
			{
				isRecommendedToUse = false;
				notRecommendedReasons.push('Too many repeating/stuck pixels in these images.');
			}

			// Show buttons
			query.getCached('.jsShowRepeatingPixelIndexesButton').show();
			query.getCached('.jsViewRepeatingPixelsButton').show();
		}

		// With good source images, the tests should pass before Von Neumann whitening (at the XORed LSBs from both
		// images stage) and after whitening. If just accepting the results after whitening then this would ignore bad
		// source entropy. It's not reasonable to assume the LSBs from each image on their own will always pass the
		// tests so we don't take that into account for the final recommendation. This is also why the LSBs from two
		// images are XORed together so there is a higher chance of passing the tests.
		if (!(trngPage.allFinishedTestResults.entropyXored.allTestsPassed && trngPage.allFinishedTestResults.entropyExtracted.allTestsPassed))
		{
			isRecommendedToUse = false;
			notRecommendedReasons.push('Tests should pass on the XORed LSBs of both images and after Von Neumann whitening.');
		}

		// Set recommendation on whether to use or not
		query.getCached('.jsRecommendedToUse').addClass(isRecommendedToUse ? 'isSuccess' : 'isFailed');
		query.getCached('.jsRecommendedToUse').text(isRecommendedToUse ? 'Yes' : 'No');
		query.getCached('.jsRecommendedToUse').prop('title', isRecommendedToUse ? '' : notRecommendedReasons.join("\n"));

		// Show all other totals and buttons in the header
		query.getCached('.jsCollectionAmounts').show();

		// Show final complete status
		app.showStatus('success', 'Completed processing and randomness tests. ' +
					   'Click the View buttons above to see the results.', true);
	},

	/**
	 * Initialise a button to show the advanced information and summary of all the test results. We don't show this
	 * information intially to not overload the user with too much information and make the UI simpler. The main
	 * information, the number of messages and the recommendation to use is always shown.
	 */
	initShowTestsSummaryButton: function() {

		// Add click handler
		query.getCached('.jsShowTestsSummaryButton').on('click', function()
		{
			// Show the advanced testing summary information
			query.getCached('.jsTestingSummaryInfo').show();

			// Disable the button again as it's served its purpose
			query.getCached('.jsShowTestsSummaryButton').prop('disabled', true);
		});
	},

	/**
	 * The cleanup function to be run when moving to another page.
	 * This will reset the page to its initial state and clear any sensitive data.
	 */
	cleanup: function()
	{
		// Hide file information and overall results
		query.getCached('.jsFileInfo').hide();
		query.getCached('.jsCollectionAmounts').hide();

		// Hide all processing results information
		query.getCached('.jsOutputAndResults > div').hide();

		// Reset file 1 information
		query.getCached('.jsFileNameA').text('N/A');
		query.getCached('.jsFileSizeA').text('0');
		query.getCached('.jsFileTypeA').text('N/A');

		// Reset file 2 information
		query.getCached('.jsFileNameB').text('N/A');
		query.getCached('.jsFileSizeB').text('0');
		query.getCached('.jsFileTypeB').text('N/A');

		// Reset totals for Image 1 least significant bits
		query.getCached('.jsTotalPixelsImageA').text('0');
		query.getCached('.jsTotalEntropyInputBitsImageA').text('0');
		query.getCached('.jsInputEntropyTestsPassImageA').text('N/A').removeClass('isSuccess isFailed');

		// Reset totals for Image 2 least significant bits
		query.getCached('.jsTotalPixelsImageB').text('0');
		query.getCached('.jsTotalEntropyInputBitsImageB').text('0');
		query.getCached('.jsInputEntropyTestsPassImageB').text('N/A').removeClass('isSuccess isFailed');

		// Reset totals for XORed least significant bits of both images
		query.getCached('.jsTotalXoredEntropyBits').text('0');
		query.getCached('.jsXoredEntropyTestsPass').text('N/A').removeClass('isSuccess isFailed');

		// Reset final extracted totals
		query.getCached('.jsTotalExtractedBits').text('0');
		query.getCached('.jsTotalNumOfMessages').text('0').removeClass('isFailed');
		query.getCached('.jsExtractedTestsPass').text('N/A').removeClass('isSuccess isFailed');

		// Reset final recommendation
		query.getCached('.jsRecommendedToUse').text('N/A').prop('title', '').removeClass('isSuccess isFailed');

		// Reset file upload button
		query.getCached('.jsImageLoaderLabel').removeClass('disabled');
		query.getCached('.jsImageLoader').prop('disabled', false).val('');

		// Deactivate the other buttons
		query.getCached('.jsOpenExportPadsSettingsButton').prop('disabled', true);
		query.getCached('.jsProcessImageButton').prop('disabled', true);
		query.getCached('.jsStartOverButton').prop('disabled', true);
		query.getCached('.jsShowTestsSummaryButton').prop('disabled', true);

		// Set name of all canvases on the page to be cleared
		var canvasesToClear = [
			'jsExtractedBitsColour', 'jsExtractedBitsBlackWhite', 'jsLeastSigBitsXoredColour',
			'jsLeastSigBitsXoredBlackWhite', 'jsLeastSigBitsColourImageB', 'jsLeastSigBitsBlackWhiteImageB',
			'jsLeastSigBitsColourImageA', 'jsLeastSigBitsBlackWhiteImageA', 'jsImageCanvasB', 'jsImageCanvasA'
		];

		// Loop through the canvas names
		for (var i = 0; i < canvasesToClear.length; i++)
		{
			// Get the native JavaScript canvas element
			var canvasClassName = canvasesToClear[i];
			var canvas = query.getCached('.' + canvasClassName).get(0);

			// Clear the canvas
			canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height);
		}

		// Clear test results
		query.getCached('.jsExtractedBitsOverallResultLog').empty();
		query.getCached('.jsLeastSigBitsXoredOverallResultLog').empty();
		query.getCached('.jsLeastSigBitsOverallResultLogImageB').empty();
		query.getCached('.jsLeastSigBitsOverallResultLogImageA').empty();

		// Reset image A default values
		trngPage.imageA.canvas = null;
		trngPage.imageA.context = null;
		trngPage.imageA.canvasWidth = null;
		trngPage.imageA.canvasHeight = null;
		trngPage.imageA.loadComplete = false;

		// Reset image B default values
		trngPage.imageB.canvas = null;
		trngPage.imageB.context = null;
		trngPage.imageB.canvasWidth = null;
		trngPage.imageB.canvasHeight = null;
		trngPage.imageB.loadComplete = false;

		// Reset test passes to false
		trngPage.allFinishedTestResults.entropyA.allTestsPassed = false;
		trngPage.allFinishedTestResults.entropyB.allTestsPassed = false;
		trngPage.allFinishedTestResults.entropyXored.allTestsPassed = false;
		trngPage.allFinishedTestResults.entropyExtracted.allTestsPassed = false;

		// Cleanup export pads dialog and cached random bits
		exportPads.cleanup();
	}
};
