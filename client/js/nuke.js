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
 * Function to delete everything from the local device storage and clear messages on the server
 */
var nuke = {
		
	/**
	 * Initialises the process to delete everything from the server and local database
	 */
	initialiseAutoNuke: function()
	{
		// On button click
		$('#btnInitiateAutoNuke').click(function()
		{
			// Make sure there is data in the database
			if (db.padData.info.serverAddressAndPort === null)
			{
				common.showStatus('error', 'No data in local database to delete');
				return false;
			}
			
			// Get the server address and key
			var serverAddressAndPort = db.padData.info.serverAddressAndPort;
			var serverKey = db.padData.info.serverKey;
						
			// Package the data to be sent to the server
			var data = {
				'user': db.padData.info.user,
				'apiAction': 'autoNuke'
			};
			
			// Deploy the nuke
			common.sendRequestToServer(data, serverAddressAndPort, serverKey, function(validResponse, responseDataJson)
			{
				// Always nuke the local database
				db.nukeDatabase();
				
				// If the server response is authentic
				if (validResponse)
				{
					// Convert from JSON to object
					var responseData = JSON.parse(responseDataJson);
										
					// If it cleared the server
					if (responseData.success)
					{
						common.showStatus('success', 'Local database nuked successfully. ' + responseData.statusMessage);
					}
					else {
						// Failed to clear the server
						common.showStatus('error', 'Local database nuked successfully. ' + responseData.statusMessage);
					}					
				}
				
				// If response check failed it means there was probably interference from attacker altering data or MAC
				else if (validResponse === false)
				{	
					common.showStatus('error', 'Local database has been nuked successfully. However an unauthentic response from server was detected. The server may still contain data, try wiping it manually.');
				}
				
				else {
					// Most likely cause is user has incorrect server url or key entered.
					// Another alternative is the attacker modified their request while en route to the server
					common.showStatus('error', 'Local database has been nuked successfully. However there was an error contacting server or your data was modified by an attacker in transit. Double check you are connected to the network and that the client and server configurations are correct. The server may still contain data, try wiping it manually.');
				}
			});
		});
	}
};