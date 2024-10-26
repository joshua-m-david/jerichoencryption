#!/bin/bash
#
# Jericho Comms - Information-theoretically secure communications
# Copyright (c) 2013-2024  Joshua M. David
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


#------------------------------------------------------------------------
# Get a cryptographically strong psuedo-random 512 bit key in hexadecimal
#------------------------------------------------------------------------
createGroupApiKey()
{
	#-----------------------------------------------
	# Set global to be used in a few other functions
	groupApiKey=$(getRandomBytesAsHexString 64)
}


#----------------------------------------------------------------------------------
# Generate a random group id of 64 bits in hexadecimal. This is mainly for having a
# unique id to identify the group's communications and their associated database.
#----------------------------------------------------------------------------------
createGroupId()
{
	#-----------------------------------------
	# Set global to be used in other functions
	groupId=$(getRandomBytesAsHexString 8)
	echo
	echo -e "${greenColour}Using randomly generated group ID: $groupId.${defaultColour}"
	echo
}


#-------------------------
# Create group database ID
#-------------------------
createGroupDatabaseName()
{
	#-----------------------------------------
	# Set global to be used in other functions
	groupDatabaseName="jerichodb$groupId"
}


#------------------------------------------------------------
# Replace various values in the group's PHP API configuration
#------------------------------------------------------------
replaceConfigurationValues()
{
	echo
	echo -e "${greenColour}Replacing API configuration values...${defaultColour}"
	echo

	# Call PHP script to add a group
	php "$scriptPath/scripts/update-config.php" "add" "$groupId" "$groupDatabaseName" "$groupApiKey" "$groupNumUsers"
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
	cd "$webDir" && phpunit


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
	echo -e "${blueColour}Outputting server group configuration, note or copy these values:${defaultColour}"
	echo
	echo -e "${greenColour}Server address:${defaultColour} http://$serverIpAddress/"
	echo -e "${greenColour}Group total users:${defaultColour} $groupNumUsers"
	echo -e "${greenColour}Group ID:${defaultColour} $groupId"
	echo -e "${greenColour}Group API key:${defaultColour} $groupApiKey"
}


#-----------------------------------
# Lists the chat group on the server
#-----------------------------------
listChatGroups()
{
	#-------------------------------------------
	# Call PHP script to list the current groups
	echo
	echo -e "${greenColour}Listing current chat groups...${defaultColour}"
	echo
	php "$scriptPath/scripts/update-config.php" "list"

	# Add check for if the command failed
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${redColour}PHP is not installed, run the installation first.${defaultColour}"
		echo
		return 1;
	fi
}


#-------------------------------------
# Removes a chat group from the server
#-------------------------------------
removeChatGroup()
{
	#------------------------
	# List the current groups
	listChatGroups

	# Add check for if the command failed
	if [[ $? > 0 ]]
	then
		return 1;
	fi


	#--------------------------------------
	# Read the index of the array to delete
	echo
	echo -e "${yellowColour}Enter the number of the group to delete, or C to cancel:${defaultColour} \c"
	local groupIndex=0
	read groupIndex


	#----------------------
	# Exit out if requested
	if [[ "$groupIndex" == "c" ]]
	then
		echo
		echo -e "${redColour}Cancelled removing a chat group."
		echo
		return 1;
	fi


	#------------------------------------
	# Make sure only integers are entered
	if ! [[ "$groupIndex" =~ ^[0-9]+$ ]]
	then
		echo
		echo -e "${redColour}Only integers may be entered."
		echo
		return 1;
	fi


	#-----------------------------------
	# Get Group ID and the database name
	groupId=$(php "$scriptPath/scripts/update-config.php" "getgroupid" "$groupIndex")
	groupDatabaseName="jerichodb$groupId"


	#---------------
	# Drop the table
	echo
	echo -e "${greenColour}Dropping database $groupDatabaseName...${defaultColour}"
	echo
	psql -U postgres -c "DROP DATABASE jerichodb$groupId"


	#--------------------------------------------------------------
	# Call PHP script to remove the group from the JSON config file
	echo
	echo -e "${greenColour}Removing the group from the configuration...${defaultColour}"
	echo
	php "$scriptPath/scripts/update-config.php" "remove" "$groupIndex"


	#---------------------------
	# Re-list the current groups
	listChatGroups
}


#--------------------------------
# Adds a chat group to the server
#--------------------------------
addChatGroup()
{
	#----------------------
	# Output status message
	echo
	echo -e "${blueColour}Creating an additional chat group...${defaultColour}"


	#-------------------------------------------------------------------------------
	# Get the number of chat users for the group which sets the global groupNumUsers
	getNumOfChatUsers


	#---------------------------
	# Create a random group name
	createGroupId


	#----------------------------
	# Set the group database name
	createGroupDatabaseName


	#---------------------------------
	# Create the API key for the group
	createGroupApiKey


	#------------------------------------------------------------------
	# Replace database name, create a copy of the script then modify it
	local databaseSetupScriptPath="$webDir/scripts/create-prod-tables-postgresql-$groupDatabaseName.sql"
	local searchStringA="jerichodb"
	local replaceStringA="$groupDatabaseName"
	cp "$scriptPath/scripts/create-prod-tables-postgresql.sql" "$databaseSetupScriptPath"
	sed -i -e "s/$searchStringA/$replaceStringA/g" "$databaseSetupScriptPath"


	#---------------------------------------------------
	# Execute script to create the group database tables
	echo
	echo -e "${greenColour}Creating chat group production database tables...${defaultColour}"
	echo
	psql -U postgres -a -f "$databaseSetupScriptPath"


	# Add check for if the command failed
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${redColour}Failed creating chat group production database and tables...${defaultColour}"
		echo
		exit 1
	fi


	#---------------------------------------------------
	# Replace the API configuration values for the group
	replaceConfigurationValues


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
