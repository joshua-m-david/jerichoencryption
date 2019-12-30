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
 * Core functionality for the application functioning as a Single Page App
 */
var app = {

	/** Name of the program */
	programName: 'Jericho Comms',

	/** Current program version as an indicator to the user and to help with automatic importing from old versions later */
	programVersion: '1.5.4',

	/** Date object for when the application first started */
	startTime: null,

	/** A timer for hiding the status messages */
	statusTimeoutId: null,

	/**
	 * Loads the page to be displayed
	 * @param {String} newPageName The name of the new page to be loaded. This should be the differentiating part of the HTML class e.g.
	 *                             'home' to match the 'html.homePage' classname, the '.content.homePageContent' container element in
	 *                             index.html and the namespace of the code page e.g. homePage.init()
	 */
	loadPage: function(newPageName)
	{
		// Get the previous page from localStorage
		var previousPage = localStorage.getItem('previousPage');

		// If this is the first visit to the app and there's no previous page recorded in localStorage
		if ((previousPage === null) && (typeof newPageName === 'undefined'))
		{
			// Load the home page
			newPageName = 'home';
		}

		// If there was a page refresh or app reload, then the previous page should still be in localStorage and can be restored again.
		// This is a helpful feature for the user so they don't revert back to the home page if the page reloads or app is restarted.
		else if ((previousPage !== null) && (typeof newPageName === 'undefined'))
		{
			// Load the previous page
			newPageName = previousPage;
		}

		// Hide previous page's HTML and show the new page's HTML e.g. homePage
		$('html').removeClass().addClass(newPageName + 'Page');

		// Set the page title to the new page e.g. Home - Jericho Comms
		$(document).prop('title', common.capitaliseFirstLetter(newPageName) + ' - ' + app.programName);

		// Store the current page in localStorage to be reloaded upon page refresh, bookmarked link, or next app load
		localStorage.setItem('previousPage', newPageName);

		// Run the code that is specific for the new page e.g. homePage.init()
		if (typeof window[newPageName + 'Page'] !== 'undefined')
		{
			// Hide previous status messages
			app.hideStatus();

			// If previously on a page *and* that page's code has a cleanup function *and*
			// this is not after a page refresh (where the current page has not been set yet)
			if ((previousPage !== null) && (typeof window[previousPage + 'Page'].cleanup === 'function') && query.$currentPage !== null)
			{
				// Run the previous page's cleanup function to halt timers, clear any sensitive information etc
				window[previousPage + 'Page'].cleanup();
			}

			// Clear old selectors from the cache and initialise the cache for the new page
			query.clearCache();
			query.init(newPageName);

			// Run the code that is specific for the new page e.g. homePage.init()
			window[newPageName + 'Page'].init();

			// Initialise the main buttons which direct to other pages
			app.initPageLoadButtons();
		}
		else {
			// If the page is not found, this will be a developer error and this will be useful for debugging
			console.error('Page not found "' + newPageName + '". Probably missing JS script include for the file.', new Error().stack);
		}
	},

	/**
	 * Initialises all main page load buttons on each page to open the page corresponding with the clicked on button
	 */
	initPageLoadButtons: function()
	{
		// On click of any page load button in the current page
		query.getCached('.jsPageLoadButton').on('click', function()
		{
			// Get the button they clicked on and the corresponding page
			var clickedPage = $(this).attr('data-page');

			// Load the page
			app.loadPage(clickedPage);
		});
	},

	/**
	 * Shows a success, error or processing message. The processing message also has an animated gif.
	 * @param {String} type The type of the error which will match the CSS class 'success', 'error' or 'processing'
	 * @param {String} message The error or success message
	 * @param {Boolean} keepDisplayed Optional flag to keep the message on screen until manually cleared
	 */
	showStatus: function(type, message, keepDisplayed)
	{
		// Remove existing CSS classes, add the class depending on the type of message
		query.getCachedGlobal('.jsStatusMessage')
				.removeClass('isSuccess isWarning isError isProcessing')
				.addClass('is' + common.capitaliseFirstLetter(type));

		// Set the status message
		query.getCachedGlobal('.jsStatusMessageText').text(message);

		// Clear previous timeout so that new status messages being shown don't get prematurely
		// hidden by an old timer that is still running but just completes and hides the new message
		window.clearTimeout(app.statusTimeoutId);

		// Show the error or success message
		query.getCachedGlobal('.jsStatusMessage').show();

		// If the flag is not set to keep the message displayed
		if (!keepDisplayed)
		{
			// Set a timer to hide the status message after 14 seconds
			app.statusTimeoutId = setTimeout(function()
			{
				// Fade the message out in 300 ms
				query.getCachedGlobal('.jsStatusMessage').fadeOut(300);

			}, 14000);
		}
	},

	/**
	 * Clears the previous status message
	 */
	hideStatus: function()
	{
		// Remove past classes, hide the status block and clear the message
		query.getCachedGlobal('.jsStatusMessage')
				.removeClass('success error processing')
				.hide()
				.find('.message').text('');

		// Clear previous timeout so that new status messages being
		// shown don't get prematurely hidden by an old timer still running
		window.clearTimeout(app.statusTimeoutId);
	},

	/**
	 * Shows how long it took to process the data up to this point
	 * @param {String} message The status message to be displayed
	 * @param {Boolean} showTimeElapsed Whether to show how long it has taken so far, turn this off if just starting the process
	 */
	showProcessingMessage: function(message, showTimeElapsed)
	{
		// Current time
		var currentTime = new Date();

		// Calculate time taken in milliseconds and seconds
		var milliseconds = currentTime.getTime() - app.startTime.getTime();
		var seconds = (milliseconds / 1000).toFixed(1);

		// Show the time the process started if applicable
		var timeElapsedMessage = (showTimeElapsed) ? ' Total time elapsed: ' + milliseconds + ' ms (' + seconds + ' s)' : '';

		// Show status on page
		app.showStatus('processing', message + timeElapsedMessage, true);
	}
};