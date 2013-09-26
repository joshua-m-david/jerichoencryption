/*
	Jericho Encrypted Chat
	Copyright (c) 2013 Joshua M. David

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software, design and associated documentation files (the "Software"), 
	to deal in the Software including without limitation the rights to use, copy, 
	modify, merge, publish, distribute, and to permit persons to whom the Software 
	is furnished to do so, subject to the following conditions:

	1) The above copyright notice and this permission notice shall be included in
	   all copies of the Software and any other software that utilises part or all
	   of the Software (the "Derived Software").
	2) Neither the Software nor any Derived Software may be sold, published, 
	   distributed or otherwise dealt with for financial gain without the express
	   consent of the copyright holder.
	3) Derived Software must not use the same name as the Software.
	4) The Software and Derived Software must not be used for evil purposes.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
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
					'autoNuke': true,									// Tell the server to nuke everything
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
	},
};