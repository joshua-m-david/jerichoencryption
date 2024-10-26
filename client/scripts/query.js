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
 * Functions for caching jQuery selectors and returning cached selectors to save re-querying the DOM each time and give
 * better performance. At some point it will be time to remove jQuery and just rely on the DOM and vanilla JS which is
 * much more powerful now. At that point it will be simple to just rewrite parts of this file to use native selectors.
 *
 * Basic usage:
 * 1) To get a jQuery element call query.getCached('.somePageElementClassName'); which will return the element in the
 *    current page.
 * 2) If the element is not in the page call query.getCachedGlobal('.someDialogClassName'); and it will return the
 *    element from anywhere.
 * 3) If the element should not be cached there are .get and .getGlobal functions. These should be used so cleanup can
 *    be run when switching to another page.
 */
var query = {

	/** Cache of the selectors */
	cachedSelectors: {},

	/** List of the used selectors that were not cached, useful for cleanup on new page load */
	usedUncachedSelectors: {},

	/** Current page of the site to reduce the search space */
	$currentPage: null,

	/**
	 * Initialise the jQuery selector cache for the current page
	 * @param {String} pageName The page name for the current page e.g. 'home' or 'chat'
	 */
	init: function(pageName)
	{
		// Cache's the current page's selector e.g. $('.homePageContent')
		query.$currentPage = $('.' + pageName + 'PageContent');
	},

	/**
	 * Finds the jQuery selector in the current page. The results of this query are not cached.
	 * This is useful for selecting dynamic elements which may change and the results should not be cached.
	 * @param {String} jQuerySelector A jQuery selector string e.g. '.jsSomeClass' etc
	 * @returns {Object} Returns the jQuery object for that selector
	 */
	get: function(jQuerySelector)
	{
		// Store that this query was used, so it can be turned off later
		query.usedUncachedSelectors[jQuerySelector] = true;

		// Fetch the jQuery element
		return query.$currentPage.find(jQuerySelector);
	},

	/**
	 * Finds the jQuery selector anywhere in the site and caches it. The results of this query are not cached.
	 * This is useful for selecting dynamic elements which may change and the results should not be cached.
	 * It is also useful for selecting an element in a dialog for which the HTML is not in the current page.
	 * @param {String} jQuerySelector A jQuery selector string e.g. '.jsSomeClass' etc
	 * @returns {Object} Returns the jQuery object for that selector
	 */
	getGlobal: function(jQuerySelector)
	{
		// Store that this query was used, so it can be turned off later
		query.usedUncachedSelectors[jQuerySelector] = true;

		// Fetch the jQuery element
		return $(jQuerySelector);
	},

	/**
	 * Finds the jQuery selector in the current page and caches it. Getting from the current page likely has a quicker
	 * lookup and performance benefit. If the selector has already been requested before it will get it from cache.
	 * @param {String} jQuerySelector A jQuery selector string e.g. '.jsSomeClass' etc
	 * @returns {Object} Returns the jQuery object for that selector and caches it in case it is used later on
	 */
	getCached: function(jQuerySelector)
	{
		// If the selector doesn't exist yet
		if (typeof query.cachedSelectors[jQuerySelector] === 'undefined')
		{
			// Find the element in the current page and cache the jQuery object
			query.cachedSelectors[jQuerySelector] = query.$currentPage.find(jQuerySelector);
		}

		// Return the jQuery object
		return query.cachedSelectors[jQuerySelector];
	},

	/**
	 * Finds the jQuery selector anywhere in the site and caches it. If the selector has already been requested before it will
	 * get it from cache. This is useful for when selecting an element in a dialog for which the HTML is not in the current page.
	 * @param {String} jQuerySelector A jQuery selector string e.g. '.jsSomeClass' etc
	 * @returns {Object} Returns the jQuery object for that selector and caches it in case it is used later on
	 */
	getCachedGlobal: function(jQuerySelector)
	{
		// If the selector doesn't exist yet
		if (typeof query.cachedSelectors[jQuerySelector] === 'undefined')
		{
			// Find the element anywhere in the app and cache the jQuery object
			query.cachedSelectors[jQuerySelector] = $(jQuerySelector);
		}

		// Return the jQuery object
		return query.cachedSelectors[jQuerySelector];
	},

	/**
	 * Clear the cache because a new page will be loaded
	 */
	clearCache: function()
	{
		// Loop through all the cached selectors
		Object.keys(query.cachedSelectors).forEach(function(selector)
		{
			// Remove any event handlers attached to the elements
			query.cachedSelectors[selector].off();
		});

		// Loop through all the used uncached selectors
		Object.keys(query.usedUncachedSelectors).forEach(function(selector)
		{
			// Remove any event handlers attached to the elements
			$(selector).off();
		});

		// Reset the caches of selectors
		query.cachedSelectors = {};
		query.usedUncachedSelectors = {};

		// Reset the current page
		query.$currentPage = null;
	}
};
