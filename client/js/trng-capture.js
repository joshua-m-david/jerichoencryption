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
 * Combines files with random hexadecimal string data into a single file which 
 * can be imported into an external tool for more strenuous randomness testing.
 */
var trngCapture = {
	
	/** A jQuery selector for the TRNG combiner page container */
	$page: null,
	
	/** The number of files that have been loaded so far */
	numFilesLoaded: 0,
	
	/** The total number of files selected to be loaded */
	totalNumFiles: 0,
	
	/** All the hexadecimal data from the files concatenated together */
	allDataHex: '',
	
	/** The display output row HTML */
	rowHtml: '',
	
	/**
	 * Initialise the page code
	 */
	init: function()
	{
		// Cache page selector for faster DOM lookups
		trngCapture.$page = $('.trngCapturePage');
		
		// Init
		trngCapture.initResetButton();
		trngCapture.startVideoCapture();
		trngCapture.initTakePictureButton();
	},
	
	/**
	 * Start video capture and prompt the user to permit the camera capture
	 */
	startVideoCapture: function()
	{
		// Set the object depending on browser support
		navigator.getMedia = (navigator.getUserMedia || navigator.webkitGetUserMedia || navigator.mozGetUserMedia);

		// Check if supported in this browser
		if (!navigator.getMedia)
		{
			common.showStatus('error', 'Webcam capture not supported in this browser.');
			return false;
		}

		// Get the video stream
		navigator.getMedia(
			{
				video: true,
				audio: false
			},
			
			// Success handler
			function(stream) {
				
				// Get the video element
				var video = document.querySelector('#video');
				
				// If Mozilla, set the stream
				if (navigator.mozGetUserMedia)
				{
					video.mozSrcObject = stream;
				}
				else {
					// Otherwise if using standards or Webkit, set the stream
					video.src = (window.URL || window.webkitURL).createObjectURL(stream);
				}
				
				// Play the video
				video.play();
				
				// Show the video stream
				trngCapture.$page.find('.videoStream').show();
				
				// Show an instructional message
				common.showStatus('success', 'You can now take photographs and save them when ready.', true);
			},
			
			// Failure handler
			function(error)
			{
				// If the camera is not available, show an error message
				if (error.toString().indexOf('NotFoundError') > -1)
				{
					common.showStatus('error', 'Check that your camera is plugged in then press Restart to try again.', true);
				}
				
				// Otherwise if they choose not to share the camera with the program, show an error message
				else if (error.toString().indexOf('SecurityError') > -1)
				{										
					common.showStatus('error', 'You must give permission to the camera in order to take pictures. Press Restart to try again.', true);
				}
				else {
					// Log some other error
					console.error(error);
				}
			}
		);
	},
	
	/**
	 * Initialise the button to capture a frame from the video
	 */
	initTakePictureButton: function()
	{
		// On the Take photograph button click
		trngCapture.$page.find('#btnTakePhoto').click(function()
		{
			// Get the elements
			var video = document.querySelector('#video');
			var photoCanvas = document.querySelector('#canvas');

			// Set the photo canvas to the same width and height as the video stream
			photoCanvas.width = video.videoWidth;
			photoCanvas.height = video.videoHeight;

			// Draw the photograph onto the HTML5 canvas
			photoCanvas.getContext('2d').drawImage(video, 0, 0, video.videoWidth, video.videoHeight);
			
			// Show the photograph
			trngCapture.$page.find('.capturedPhotograph').show();
			
			// Show an instructional message
			common.showStatus('success', '2. Right click on the captured photograph below and select Save Image As... to save the file in PNG format.', true);
		});
	},
				
	/**
	 * Reloads the page so the user can start a new upload
	 */
	initResetButton: function()
	{
		// On Reset button click
		trngCapture.$page.find('#btnRestart').click(function()
		{
			// Hard refresh the page (ignores browser cache)
			location.reload(true);
		});
	}
};