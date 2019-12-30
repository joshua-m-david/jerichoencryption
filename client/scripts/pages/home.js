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
 * Functions for the home page
 */
var homePage = {

	/**
	 * Initialise the page
	 */
	init: function()
	{
		// Show the current version of the program
		homePage.showProgramVersion();
	},

	/**
	 * Show the current version of the program
	 */
	showProgramVersion: function()
	{
		// Set the version text e.g. v2.0.0
		query.getCached('.jsProgramVersion').text('v' + app.programVersion);
	}
};