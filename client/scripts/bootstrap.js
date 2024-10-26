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
 * Initial one and only DOM ready function to bootstrap and initialise the entire application
 */
$(function()
{
	// Load the index page if this is the first load, otherwise load a previously loaded page if they refreshed the page
	app.loadPage();
});
