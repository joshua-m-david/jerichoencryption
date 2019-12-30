#!/bin/bash
#
# Jericho Comms - Information-theoretically secure communications
# Copyright (c) 2013-2019  Joshua M. David
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation in version 3 of the License.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see [http://www.gnu.org/licenses/].


#------------------------------------------
# Get the number of users in the chat group
#------------------------------------------
getNumOfChatUsers()
{
	#--------------------------------------------
	# Read the number of users for the chat group
	echo
	echo -e "${yellowColour}How many users in the chat group? (2 - 7):${defaultColour} \c"
	local chatUsers=2
	read chatUsers


	#-----------------------------------------------------------------
	# Check if the range of users is between 2 and 7 users (inclusive)
	if [[ "$chatUsers" -ge 1 && "$chatUsers" -le 7 ]]; then
		echo
		echo -e "Entered $chatUsers users."
	else
		# If they made an invalid choice, default to 2 users
		chatUsers=2
		echo
		echo -e "${redColour}Incorrect entry, defaulting to $chatUsers users."
		echo -e "${redColour}This can be changed later in the configuration.${defaultColour}"
	fi


	#------------------------------
	# Set global to be output later
	groupNumUsers="$chatUsers"
}


#----------------------------------
# Copy server files to the web root
#----------------------------------
copyServerFilesToWebRoot()
{
	#--------------------------------------
	# Copy the server files to the web root
	echo
	echo -e "${greenColour}Copying server API files to web path $groupInstallDir/${defaultColour}"
	echo
	cp -r . "$groupInstallDir/"


	#---------------------------------------------------------
	# Change group ownership of the files to Apache's www-data
	chgrp -R www-data "$groupInstallDir"


	#--------------------------------------------------------------------------
	# Set group to only have read permissions on files in the install directory
	# Set group to have read and execute permissions on directories in the install directory
	find "$groupInstallDir" -type f -exec chmod 644 -c '{}' \;
	find "$groupInstallDir" -type d -exec chmod 755 -c '{}' \;


	#-------------------------------------------------------
	# Show the directory contents for informational purposes
	echo
	echo -e "${greenColour}Listing directory contents of $groupInstallDir/${defaultColour}"
	echo
	ls -al "$groupInstallDir"
}


#---------------------------------------
# Ask the user for the database password
#---------------------------------------
requestDatabasePassword()
{
	#---------------------------------------
	# Ask the user for the database password
	echo
	echo -e "${yellowColour}Enter the database password from the original install:${defaultColour} \c"
	local databasePassword=""
	read databasePassword


	#--------------------------------------------
	# Remove any newlines from the entered string
	databasePassword=$(echo "$databasePassword"|tr -d '\n')


	#-----------------------------------------------
	# Set global to be used in a few other functions
	serverDatabasePassword="$databasePassword"
}


#------------------------------------------------------------------------
# Get a cryptographically strong psuedo-random 512 bit key in hexadecimal
#------------------------------------------------------------------------
createGroupApiKey()
{
	#-----------------------------------------------
	# Set global to be used in a few other functions
	groupApiKey=$(getRandomBytesAsHexString 64)
}


#----------------------------------------------------------------------------
# Generate a random group name of 64 bits in hexadecimal. This is mainly just
# for having a unique directory name for the files, database name etc.
#----------------------------------------------------------------------------
createGroupName()
{
	#-----------------------------------------
	# Set global to be used in other functions
	groupName=$(getRandomBytesAsHexString 8)
	echo
	echo -e "${greenColour}Using randomly generated group name: $groupName.${defaultColour}"
	echo
}


#---------------------------
# Create group database name
#---------------------------
createGroupDatabaseName()
{
	#-----------------------------------------
	# Set global to be used in other functions
	groupDatabaseName="jerichodb$groupName"
}


#-----------------------------------------
# Set the group web installation directory
#-----------------------------------------
createGroupInstallDir()
{
	#--------------------------------------
	# Set global for use in other functions
	groupInstallDir="/var/www/$groupName"
}


#--------------------------------------------
# Create group port for connecting to the API
#--------------------------------------------
createGroupPort()
{
	#-----------------------------------
	# List rules on the firewall already
	echo
	echo -e "${greenColour}Listing incoming ports accepted by the firewall:${defaultColour}"
	echo
	ufw status verbose


	#--------------------------------------------------
	# Get the port number to use for the new chat group
	echo
	echo -e "${greenColour}NB: The default chat group uses HTTP port 80. It is recommended to use the${defaultColour}"
	echo -e "${greenColour}alternative HTTP port 8008, or 8080 - 8087 port range for other groups.${defaultColour}"
	echo
	echo -e "${yellowColour}Enter a port for the group to use:${defaultColour} \c"
	local chatGroupPort=80
	read chatGroupPort


	#-------------------------------------------------------------------
	# Check if the port is in the range of 1 and the maximum (inclusive)
	if [[ "$chatGroupPort" -ge 1 && "$chatGroupPort" -le 65535 ]]; then
		echo
		echo -e "Entered port number $chatGroupPort."
		echo
	else
		# If they made an invalid choice, exit
		echo
		echo -e "${redColour}Incorrect port entry.${defaultColour}"
		echo
		return 1
	fi


	#--------------------------------------
	# Set global for use in other functions
	groupPort="$chatGroupPort"
}


#---------------------------------------------------------------
# Make the firewall allow incoming connections to the group port
#---------------------------------------------------------------
addGroupPortToFirewall()
{
	#-------------------------------
	# Allow the port on the firewall
	ufw allow "$groupPort"
}


#------------------------------------------------------------
# Replace various values in the group's PHP API configuration
#------------------------------------------------------------
replaceConfigurationValues()
{
	#-----------------------------------------------
	# Replace the number of users in the config file
	echo
	echo -e "${greenColour}Replacing API configuration values...${defaultColour}"
	echo
	local searchA="numberOfUsers = 2;"
	local replaceA="numberOfUsers = $groupNumUsers;"
	sed -i -e "s/$searchA/$replaceA/g" "$groupInstallDir/config/config.php"


	#--------------------------
	# Replace the group API key
	local searchB="jerichoserverkey"
	local replaceB="$groupApiKey"
	sed -i -e "s/$searchB/$replaceB/g" "$groupInstallDir/config/config.php"


	#--------------------------
	# Replace the database name
	local searchC="jerichodb"
	local replaceC="$groupDatabaseName"
	sed -i -e "s/$searchC/$replaceC/g" "$groupInstallDir/config/config.php"


	#----------------------------------------------------------------------------------
	# Replace the database password in the API configuration and in the unit tests file
	local searchD="jerichopassword"
	local replaceD="$serverDatabasePassword"
	sed -i -e "s/$searchD/$replaceD/g" "$groupInstallDir/config/config.php"
	sed -i -e "s/$searchD/$replaceD/g" "$groupInstallDir/tests/config.php"
}


#---------------------------
# Run the PHPUnit unit tests
#---------------------------
runPhpUnitTests()
{
	#--------------------------------------
	# Change to web directory and run tests
	echo
	echo -e "${greenColour}Running unit tests...${defaultColour}"
	echo
	cd "$groupInstallDir" && phpunit


	#------------------------------
	# Go back to original directory
	cd "$scriptPath"
}


#---------------------------------
# Output configuration for viewing
#---------------------------------
outputConfig()
{
	#-------------------------
	# Get the public server IP
	serverIpAddress=$(ip route get 8.8.8.8 | sed -n '/src/{s/.*src *\([^ ]*\).*/\1/p;q}')


	#-----------------------------------------------------------------------------
	# Output all the configuration necessary for clients to connect for this group
	echo
	echo -e "${blueColour}Outputting server group configuration, note down these values:${defaultColour}"
	echo
	echo -e "${greenColour}Group name:${defaultColour} $groupName"
	echo -e "${greenColour}Group configuration file:${defaultColour} $groupInstallDir/config/config.php"
	echo -e "${greenColour}Group total users:${defaultColour} $groupNumUsers"
	echo -e "${greenColour}Group API address and port:${defaultColour} http://$serverIpAddress:$groupPort/"
	echo -e "${greenColour}Group API key:${defaultColour} $groupApiKey"


	#----------------------------------------------------------------------------------
	# Output the database password in case they need it later for creating other groups
	echo
	echo -e "${blueColour}Outputting database password for creating other groups, note down this value:${defaultColour}"
	echo
	echo -e "${greenColour}Server database password:${defaultColour} $serverDatabasePassword"
}


#--------------------------------------
# Finishes the addition of a chat group
#--------------------------------------
completeGroupAddition()
{
	#---------------------------------
	# Create the API key for the group
	createGroupApiKey


	#-------------------------------------------------
	# Copy server files to the web root for this group
	copyServerFilesToWebRoot


	#----------------------
	# Replace database name
	local searchStringA="jerichodb"
	local replaceStringA="$groupDatabaseName"
	sed -i -e "s/$searchStringA/$replaceStringA/g" "$groupInstallDir/scripts/create-prod-tables-postgresql.sql"


	#---------------------------------------------------
	# Execute script to create the group database tables
	echo
	echo -e "${greenColour}Creating chat group production database tables...${defaultColour}"
	echo
	sudo -u postgres psql -a -f "$groupInstallDir/scripts/create-prod-tables-postgresql.sql"


	#----------------------------------------------------------
	# Edit virtual host config to use the new port of the VHost
	echo
	echo -e "${greenColour}Configuring Apache for the chat group...${defaultColour}"
	echo
	local searchStringB="groupPort"
	local replaceStringB="$groupPort"
	sed -i -e "s/$searchStringB/$replaceStringB/g" "$groupInstallDir/scripts/apache-virtual-host.conf"


	#---------------------------------------------------------------------------------------
	# Add port to Apache ports configuration so that Apache serves the files on the new port
	printf "Listen $groupPort\n" >> /etc/apache2/ports.conf


	#------------------------------------------------------------------------------------------------------
	# Edit virtual host config to use the new directory of the group. NB: using # instead of / as separator
	# so that the /var/www/groupname is replaced properly see: unix.stackexchange.com/a/378991
	local searchStringC="groupInstallDir"
	local replaceStringC="$groupInstallDir"
	sed -i -e "s#$searchStringC#$replaceStringC#g" "$groupInstallDir/scripts/apache-virtual-host.conf"


	#-----------------------------------------------------------------------------
	# Copy virtual host config to Apache sites-available directory and activate it
	echo
	echo -e "${greenColour}Activating chat group site...${defaultColour}"
	echo
	cp "$groupInstallDir/scripts/apache-virtual-host.conf" "/etc/apache2/sites-available/$groupName.conf"
	a2ensite "$groupName.conf"


	#---------------------------------------------------
	# Replace the API configuration values for the group
	replaceConfigurationValues


	#---------------------------------------------------------------
	# Make the firewall allow incoming connections to the group port
	addGroupPortToFirewall


	#-------------------------------------------------------------
	# Restart Apache for the new configuration and modules to work
	restartApache


	#-------------------
	# Run the unit tests
	runPhpUnitTests


	#-----------------------------------------
	# Output new group chat configuration here
	outputConfig


	#---------------------------------------------
	# Prompt to clear the bash history and console
	clearBashHistoryAndConsole
}


#---------------------------------------------------------------
# Adds a default chat group to the server after the main install
#---------------------------------------------------------------
configureDefaultGroup()
{
	#----------------------
	# Output status message
	echo
	echo -e "${blueColour}Creating the default chat group...${defaultColour}"


	#---------------------------------------------------------------------------------
	# Some things are set for the default group in the setup.sh file e.g. the database
	# name, install dir, group name, port etc so we just need the number of users
	getNumOfChatUsers


	#-------------------
	# Complete the tasks
	completeGroupAddition
}


#--------------------------------------
# Adds another chat group to the server
#--------------------------------------
configureAdditionalChatGroup()
{
	#----------------------
	# Output status message
	echo
	echo -e "${blueColour}Creating an additional chat group...${defaultColour}"


	#-------------------------------------------------------------------------------
	# Get the number of chat users for the group which sets the global groupNumUsers
	getNumOfChatUsers


	#---------------------------------------
	# Ask the user for the database password
	requestDatabasePassword


	#----------------------------------------------------------
	# Set the port that the API will use to determine the group
	createGroupPort


	#---------------------------
	# Create a random group name
	createGroupName


	#----------------------------
	# Set the group database name
	createGroupDatabaseName


	#----------------------
	# Set the group web dir
	createGroupInstallDir


	#-------------------
	# Complete the tasks
	completeGroupAddition
}
