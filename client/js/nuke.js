/*
	Jericho Chat - Information-theoretically secure communications.
	Copyright (C) 2013  Joshua M. David

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation in version 3 of the License.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see [http://www.gnu.org/licenses/].
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
		$('#btnInitiateAutoNuke').click(function()
		{
			// Make sure there is data in the database
			if (db.padData.info.serverAddressAndPort == null)
			{
				common.showStatus('error', 'No data in local database to delete');
				return false;
			}
			
			// Fix the url for any excess slashes
			var serverAddress = common.standardiseUrl(db.padData.info.serverAddressAndPort, 'auto-nuke.php');
			
			// Create AJAX request to chat server
			$.ajax(
			{
				url: serverAddress,
				type: 'POST',
				dataType: 'json',
				data: {
					'username': db.padData.info.serverUsername,			// Username to connect to the server
					'password': db.padData.info.serverPassword,			// Password to connect to the server
					'autoNuke': true									// Tell the server to nuke everything
				},
				success: function(data)
				{
					// Get message back from server, and protect against XSS
					var statusMessage = common.htmlEncodeEntities(data.statusMessage);
					
					// If it saved to the database
					if (data.success)
					{
						// Delete everything in memory and the local database
						db.nukeDatabase();
						common.showStatus('success', 'Local database and server database nuked successfully.');
					}
					else {
						// Otherwise nuke local database anyway and show error from the server
						db.nukeDatabase();
						common.showStatus('error', statusMessage);
					}
				},
				error: function(jqXHR, textStatus, errorThrown)
				{
					// Otherwise nuke local database anyway and display error
					db.nukeDatabase();
					common.showStatus('error', 'Error contacting server, check you are connected to the internet and that server setup is correct.');
				}
			});

		});
	}
};