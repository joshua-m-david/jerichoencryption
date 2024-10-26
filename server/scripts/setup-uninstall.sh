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


#--------------------------------------------
# Revert the server back to how it was before
#--------------------------------------------
uninstall()
{
	#------------------------------
	# Get the installed PHP version
	getPhpVersion


	#----------------------
	# Stop running services
	echo
	echo -e "${greenColour}Stopping Apache and PostgreSQL services...${defaultColour}"
	echo
	systemctl stop apache2
	systemctl stop postgresql


	#--------------------------------
	# Remove installed PHP extensions
	echo
	echo -e "${greenColour}Removing PHP and PHP extensions...${defaultColour}"
	echo
	apt-get -y remove --purge "php$phpVersion-common"
	apt-get -y remove --purge "php$phpVersion-mbstring"
	apt-get -y remove --purge "php$phpVersion-dev"
	apt-get -y remove --purge phpunit
	apt-get -y remove --purge php-pgsql
	apt-get -y remove --purge php


	#-------------------------------------------
	# Remove installed Apache modules and Apache
	echo
	echo -e "${greenColour}Removing Apache and Apache extensions...${defaultColour}"
	echo
	apt-get -y remove --purge libapache2-mod-php
	apt-get -y remove --purge libapache2-mod-security2
	apt-get -y remove --purge apache2


	#------------------------------------
	# Remove PostgreSQL client and server
	echo
	echo -e "${greenColour}Removing PostgreSQL...${defaultColour}"
	echo
	apt-get -y remove --purge postgresql\*
	apt-get -y remove --purge postgresql-common


	#----------------------
	# Final package cleanup
	echo
	echo -e "${greenColour}Cleaning up remaining package data...${defaultColour}"
	echo
	apt-get -y autoremove


	#-----------------------------
	# Remove files and directories
	echo
	echo -e "${greenColour}Cleaning up files and directories...${defaultColour}"
	echo
	rm -rf /var/www
	rm -rf /etc/apache2
	rm -rf /etc/php
	rm -rf /etc/postgresql/
	rm -rf /etc/postgresql-common/
	rm -rf /var/lib/postgresql/
	rm -rf /usr/lib/php
	rm -f /etc/cron.d/jericho


	#---------------------------------------------
	# Disable and revert firewall rules to default
	ufw --force disable
	ufw --force reset
}
