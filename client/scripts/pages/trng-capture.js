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
 * Combines files with random hexadecimal string data into a single file which
 * can be imported into an external tool for more strenuous randomness testing.
 */
var trngCapturePage = {

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
		// Init
		trngCapturePage.initResetButton();
		trngCapturePage.startVideoCapture();
		trngCapturePage.initTakePictureButton();
	},

	/**
	 * Start video capture and prompt the user to permit the camera capture
	 */
	startVideoCapture: function()
	{
		// Check if supported in this browser
		if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia)
		{
			app.showStatus('error', 'Webcam capture not supported in this browser.');
			return false;
		}

		// Enable video only (will pop up a prompt and ask the user)
		var constraints = { audio: false, video: true };

		// Get a stream from the webcam
		navigator.mediaDevices.getUserMedia(constraints).then(function(mediaStream)
		{
			// Get the raw JavaScript video element (not jQuery)
			var video = query.getCached('.jsWebcamStream')[0];

			// Once the stream is loaded
			video.srcObject = mediaStream;
			video.onloadedmetadata = function()
			{
				// Play the webcam stream
				video.play();

				// Show the Video header and video stream, also make the Take Photo Button clickable
				query.getCached('.jsVideoStreamContainer').show();
				query.getCached('.jsTakePhotoButton').removeClass('isDisabled');

				// Show an instructional message
				app.showStatus('success', 'You can now take photographs and save them when ready.', true);
			};
		})
		.catch(function(error)
		{
			// Convert the error to a string
			var errorString = error.toString();

			// If the camera is not available, show an error message
			if (errorString.indexOf('NotFoundError') > -1)
			{
				app.showStatus('error', 'Check that your camera is plugged in then press Restart to try again.', true);
			}

			// Otherwise if they choose not to share the camera with the program, show an error message
			else if ((errorString.indexOf('NotAllowedError') > -1) || (errorString.indexOf('NavigatorUserMediaError') > -1))
			{
				app.showStatus('error', 'You must give permission to the camera in order to take pictures. Press Restart to try again.', true);
			}
			else {
				// Otherwise show the actual error
				app.showStatus('error', error + '. Try again in another browser.', true);
			}
		});
	},

	/**
	 * Initialise the button to capture a frame from the video
	 */
	initTakePictureButton: function()
	{
		// On the Take photograph button click
		query.getCached('.jsTakePhotoButton').on('click', function()
		{
			// Prevent clicking if the button is disabled
			if ($(this).hasClass('isDisabled'))
			{
				return false;
			}

			// Get the raw JavaScript elements (not jQuery)
			var video = query.getCached('.jsWebcamStream')[0];
			var photoCanvas = query.getCached('.jsPhotoCanvas')[0];

			// Set the photo canvas to the same width and height as the video stream
			photoCanvas.width = video.videoWidth;
			photoCanvas.height = video.videoHeight;

			// Draw the photograph onto the HTML5 canvas
			photoCanvas.getContext('2d').drawImage(video, 0, 0, video.videoWidth, video.videoHeight);

			// Show the photograph
			query.getCached('.jsPhotographContainer').show();

			// Show an instructional message
			app.showStatus('success', '2. Right click on the captured photograph below and select Save Image As... '
			                           + 'to save the file in PNG format.', true);
		});
	},

	/**
	 * Reloads the page so the user can start a new upload
	 */
	initResetButton: function()
	{
		// On Reset/Restart button click
		query.getCached('.jsRestartButton').on('click', function()
		{
			// Hard refresh the page (ignores browser cache)
			location.reload(true);
		});
	},

	/**
	 * The cleanup function to be run when moving to another page.
	 * This will reset the page to its initial state, clearing the webcam stream and photo.
	 */
	cleanup: function()
	{
		// Get the raw JavaScript elements (not jQuery)
		var video = query.getCached('.jsWebcamStream')[0];
		var photoCanvas = query.getCached('.jsPhotoCanvas')[0];

		// If the video was started
		if (video !== null)
		{
			// Get the video stream and tracks
			var stream = video.srcObject;

			// If the stream was created
			if (stream !== null)
			{
				// Get the video tracks
				var tracks = stream.getTracks();

				// Stop the webcam
				tracks.forEach(function(track)
				{
					track.stop();
				});
			}

			// Clear the video element of past images
			video.src = '';

			// Get the canvas context
			var photoContext = photoCanvas.getContext('2d');

			// Clear the captured photo
			photoContext.clearRect(0, 0, photoCanvas.width, photoCanvas.height);

			// Hide the photograph container, make the Take Photo button disabled again
			query.getCached('.jsPhotographContainer').hide();
			query.getCached('.jsTakePhotoButton').addClass('isDisabled');

			// Reset to initial values
			trngCapturePage.numFilesLoaded = 0;
			trngCapturePage.totalNumFiles = 0;
			trngCapturePage.allDataHex = '';
			trngCapturePage.rowHtml = '';
		}
	}
};