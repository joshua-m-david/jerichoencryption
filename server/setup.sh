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


# The Jericho Comms server installation script requirements are:
# - Ubuntu Server 18.04.x or later
# - A working internet connection
# - The script must be run as root e.g. sudo ./setup.sh or login first e.g. sudo su


#-------------------------------------------------------------------
# Set shell echo colour constants (from stackoverflow.com/a/5947802)
defaultColour="\033[0m"
blueColour="\033[0;34m"
greenColour="\033[0;32m"
redColour="\033[0;31m"
yellowColour="\033[1;33m"


#------------------------------------------------------------------------------------
# Initialise global variables. These are also available in the sourced scripts below.
groupId=""
groupApiKey=""
groupDatabaseName=""
groupNumUsers=2
scriptPath=""
serverDatabasePassword=""
serverIpAddress=""
webDir="/var/www/html"


#------------------------------------------------
# Make sure only the root user can run the script
if [ "$(id -u)" != "0" ]; then
	echo
	echo -e "${redColour}This script must be run as the root user account to install dependency"
	echo -e "${redColour}packages, configure the applications and initialise the server API."
	echo
	echo -e "${defaultColour}For example: sudo ./setup.sh"
	echo
	exit 1
fi


#---------------------------------------------------------------------------------------
# Get absolute path to this script, e.g. /home/user/jericho-comms-vX.X.X/server/setup.sh
script=$(readlink -f "$0")


#------------------------------------------------------------------------------------------
# Thus, the absolute directory path to the script is /home/user/jericho-comms-vX.X.X/server
scriptPath=$(dirname "$script")


#-------------------------------------------------------------------------------
# Change to the current script path and server directory so it works the same if
# executing the script from inside the /server directory or outside it
cd "$scriptPath"


#------------------------
# Load additional scripts
source "$scriptPath/scripts/setup-dependency-install.sh"
source "$scriptPath/scripts/setup-group-modifications.sh"
source "$scriptPath/scripts/setup-security-cleanup.sh"
source "$scriptPath/scripts/setup-uninstall.sh"


#----------------
# Setup main menu
while true
do
	#------------------------------------
	# Display the banner and menu options
	clear
	echo
	echo "      #                                     ####                            ";
	echo "      # ##### ####  #  ###  #   #  ###     #    #  ###  #    # #    #  ###  ";
	echo "      # #     #   # # #   # #   # #   #    #      #   # ##  ## ##  ## #     ";
	echo "      # ####  #   # # #     ##### #   #    #      #   # # ## # # ## #  ###  ";
	echo " #    # #     ####  # #     #   # #   #    #      #   # #    # #    #     # ";
	echo " #    # #     #  #  # #   # #   # #   #    #    # #   # #    # #    # #   # ";
	echo "  ####  ##### #   # #  ###  #   #  ###      ####   ###  #    # #    #  ###  ";
	echo "                                                                            ";
	echo "               Server installation and configuration main menu              ";
	echo "                                  v2.0.0                                    ";
	echo
	echo
	echo -e "${blueColour}Choose from the list of options below:${defaultColour}"
	echo
	echo -e "${yellowColour}1${defaultColour} - Perform full installation of the server dependencies and chat API."
	echo -e "${yellowColour}2${defaultColour} - Add a chat group"
	echo
	echo -e "${yellowColour}L${defaultColour} - List chat groups"
	echo -e "${yellowColour}R${defaultColour} - Remove a chat group"
	echo -e "${yellowColour}C${defaultColour} - Clear any sensitive data from the bash history and console."
	echo -e "${yellowColour}U${defaultColour} - Uninstall and revert server to its original state."
	echo -e "${yellowColour}Q${defaultColour} - Quit menu back to console."
	echo


	#------------------------------------------
	# Read the chosen menu option from the user
	# -e enables interpretation of backslash escapes
	# \c makes sure it does not output the trailing newline
	echo -e "${yellowColour}Enter an option:${defaultColour} \c"
	read userSelection


	#------------------------
	# Lowercase the selection
	userSelectionLowercase=${userSelection,,}


	#-------------------------------------------------------------
	# Run the function corresponding to the option that was chosen
	case "$userSelectionLowercase" in
		1) mainInstall ;;
		2) addChatGroup ;;
		l) listChatGroups ;;
		r) removeChatGroup ;;
		c) clearBashHistoryAndConsole ;;
		u) uninstall ;;
		q) exit ;;
		*) echo -e "${redColour}No option selected.${defaultColour}"
	esac


	#-----------------------------------------------------------------------------
	# Read a keyboard input from the user to clear the screen and re-show the menu
	echo
	echo -e "${yellowColour}Press Enter to return to main menu selection:${defaultColour} \c"
	read input
done
