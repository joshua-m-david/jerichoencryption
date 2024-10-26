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


#----------------------------------------------------
# Clear the bash history and console of passwords etc
#----------------------------------------------------
clearBashHistoryAndConsole()
{
	#----------------------------------------------------
	# Ask the user if they wish to clear the bash history
	echo
	echo -e "${blueColour}For security you should clear the output of this script from the bash${defaultColour}"
	echo -e "${blueColour}shell once you have copied the group configuration.${defaultColour}"
	echo
	echo -e "${yellowColour}Do you wish to clear now? (y or n)${defaultColour}"
	read clearBashShellUserResponse


	#-------------------------------------
	# If they enter Y or y on the keyboard
	if [[ "$clearBashShellUserResponse" == "Y" || "$clearBashShellUserResponse" == "y" ]]; then


		#--------------------------------------------------------------------------------------------
		# Clear the bash history, overwrite ~/.bash_history immediately and clear the console as well
		echo
		echo -e "${greenColour}Clearing bash history...${defaultColour}"
		echo
		sleep 1
		history -c
		history -w
		reset
	else


		#---------------------------------------------------------------------------
		# Otherwise let them do it at their own convenience if they're still testing
		echo
		echo -e "${redColour}History not cleared. You should do this later from the main menu.${defaultColour}"
	fi
}
