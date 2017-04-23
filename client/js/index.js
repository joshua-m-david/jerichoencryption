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
 * Functions for the index page
 */
var index = {
	
	/**
	 * Open the sub menu for generating random data
	 */
	initGenerateMenu: function()
	{
		$('.btnOpenGeneratePadsMenu').click(function()
		{	
			$('.generatePadsSubMenu').show();
			$('.mainMenu').hide();
		});
	},
	
	/**
	 * Show the current version of the program
	 */
	showProgramVersion: function()
	{
		$('.programVersion').text('v' + common.programVersion);
	}
};

$(function()
{
	index.initGenerateMenu();
	index.showProgramVersion();
});