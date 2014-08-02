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

// Import scripts to be used
importScripts('common.js');
importScripts('trng-photo.js');

// Get data from the process which started the worker thread
self.addEventListener('message', function(e)
{
	// Send the processed data back to the main thread
	self.postMessage({
		'threadId': e.data.threadId,
		'datasetId': e.data.datasetId,
		'datasetBinaryData': trngImg.convertFromImageData(e.data.dataset)
	});
		
}, false);