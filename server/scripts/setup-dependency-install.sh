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


#-------------------------------------------------------------------------------
# Configure a basic firewall. This is the first step before doing anything else.
#-------------------------------------------------------------------------------
setupFirewall()
{
	#------------------------------------------------------------------------------------------
	# Set rules so only SSH (port 22) traffic will be allowed through to the web server for now
	# This assumes the admin wants to administer the server via SSH. They can of course remove
	# this rule if they have another way to manage the server.
	echo
	echo -e "${greenColour}Configuring firewall to allow only SSH traffic...${defaultColour}"
	echo
	ufw default deny
	ufw allow 22


	#-----------------------------------------------------------------------------------------
	# Enable the firewall and ignore the warning that it might disable existing SSH connection
	ufw --force enable
	ufw status verbose
}


#---------------------
# Update package lists
#---------------------
updatePackages()
{
	#---------------------
	# Update package lists
	echo
	echo -e "${greenColour}Updating package lists from the repository...${defaultColour}"
	echo
	apt-get -y update


	#--------------------------
	# Update installed software
	echo
	echo -e "${greenColour}Installing latest updates of packages currently installed...${defaultColour}"
	echo
	apt-get -y upgrade
}


#------------------------------------------
# Install Apache web server and ModSecurity
#------------------------------------------
installWebServer()
{
	#--------------------------
	# Install Apache web server
	echo
	echo -e "${greenColour}Installing Apache web server...${defaultColour}"
	echo
	apt-get -y install apache2


	#----------------------------------------------------------------------------------
	# Removes the default index.html file which is put there by the Apache installation
	echo
	echo -e "${greenColour}Removing default Apache index.html file...${defaultColour}"
	echo
	rm -f /var/www/html/index.html


	#-------------------------------
	# Install and enable ModSecurity
	echo
	echo -e "${greenColour}Installing ModSecurity...${defaultColour}"
	echo
	apt-get -y install libapache2-mod-security2
	a2enmod security2


	#--------------------------------------------------------------------------------------------
	# Replace the "Server: Apache/2.4.x (Ubuntu)" in the network response with "Server: nginx" so
	# NSA/TAO etc waste time trying their exploits for Nginx instead of their Apache exploits
	echo -e "ServerTokens Full" >> /etc/apache2/apache2.conf
	echo -e "SecServerSignature \"nginx\"\n" >> /etc/apache2/apache2.conf


	#-----------------------
	# Turn on rewrite engine
	sudo a2enmod rewrite
}


#-------------------------------------------------------------------
# Gets random bytes as a lowercase hex string which are suitable for
# cryptographic use. To use, pass the number of bytes required e.g.
# key=$(getRandomBytesAsHexString 64)
#-------------------------------------------------------------------
getRandomBytesAsHexString()
{
	#------------------------------------------------------------------
	# Get the number of bytes from the parameter passed to the function
	local numOfBytes=$1


	#----------------------------------------------------------------------
	# Get a cryptographically strong psuedo-random x bit key in hexadecimal
	local randomKey=$(hexdump -n $numOfBytes -e '4/4 "%08X"' /dev/urandom)


	#----------------------------------------------------
	# Convert the capital letters in the key to lowercase
	local keyLowercase=${randomKey,,}


	#---------------------------------
	# Remove any newlines from the key
	local keyLowercaseNoNewLines=$(echo $keyLowercase|tr -d '\n')


	#---------------------------------------------------------
	# Output the key so it can be captured by the calling code
	echo $keyLowercaseNoNewLines
}


#----------------------------
# Install PostgreSQL database
#----------------------------
installDatabase()
{
	#-------------------------------------------------------------
	# Install the PostgreSQL client for connecting to the database
	echo
	echo -e "${greenColour}Installing the PostgreSQL client for connecting to the database...${defaultColour}"
	echo
	apt-get -y install postgresql-client


	#------------------------------
	# Install the PostgreSQL server
	echo
	echo -e "${greenColour}Installing the PostgreSQL server...${defaultColour}"
	echo
	apt-get -y install postgresql


	#---------------------------------------------------------------------------
	# Create a cryptographically strong psuedo-random 128 bit key in hexadecimal
	local databasePassword=$(getRandomBytesAsHexString 16)


	#---------------------
	# Create database user
	echo
	echo -e "${greenColour}Creating database user...${defaultColour}"
	echo
	sudo -u postgres psql -c "CREATE USER jerichouser WITH PASSWORD '$databasePassword';"


	#-----------------------------------------------
	# Create test database and tables for unit tests
	echo
	echo -e "${greenColour}Creating test database and tables...${defaultColour}"
	echo
	sudo -u postgres psql -a -f "$scriptPath/scripts/create-test-tables-postgresql.sql"


	#------------------------------
	# Set global to be output later
	serverDatabasePassword="$databasePassword"
}


#------------------------------
# Get the installed PHP version
#------------------------------
getPhpVersion()
{
	#--------------------------------------------------------------------------------
	# Get the major version e.g. 7 and minor version e.g. 2 of PHP which is installed
	local phpMajorVersion=$(php -r 'echo PHP_MAJOR_VERSION;')
	local phpMinorVersion=$(php -r 'echo PHP_MINOR_VERSION;')


	#----------------------------------------------------------------------------
	# Set the version e.g. 7.2 as a global which might be used by other functions
	phpVersion="$phpMajorVersion.$phpMinorVersion"
}


#----------------------------------------
# Install PHP which handles the API logic
#----------------------------------------
installPhp()
{
	#------------
	# Install PHP
	echo
	echo -e "${greenColour}Installing PHP...${defaultColour}"
	echo
	apt-get -y install php


	#---------------------------------------------------------
	# Set the installed PHP version for use in other functions
	getPhpVersion
}


#------------------------------------------------
# Builds and installs the Skein-512 PHP extension
#------------------------------------------------
installSkeinPhpExtension()
{
	#-------------------------------------------------------------------------------------
	# Copy the files elsewhere first so build files don't end up in the original directory
	echo
	echo -e "${greenColour}Building and installing the Skein-512 PHP extension...${defaultColour}"
	echo
	cp -r "$scriptPath/library/skein/" /var/www/skein


	#----------------------------------------------
	# Build and install the Skein-512 PHP extension
	cd /var/www/skein
	phpize
	./configure --enable-skein
	make clean
	make
	make install
	make test


	#--------------------------------------------------
	# Add the extension to the end of the PHP ini files
	echo "extension=skein.so" >> /etc/php/$phpVersion/apache2/php.ini
	echo "extension=skein.so" >> /etc/php/$phpVersion/cli/php.ini


	#----------------------------------------
	# Return back up to the /server directory
	cd "$scriptPath"
}


#---------------------------------
# Install necessary PHP extensions
#---------------------------------
installPhpExtensions()
{
	#------------------------------
	# Install PHP module for Apache
	echo
	echo -e "${greenColour}Installing PHP module for Apache...${defaultColour}"
	echo
	apt-get -y install libapache2-mod-php


	#---------------------------------
	# Install PHP PostgreSQL extension
	echo
	echo -e "${greenColour}Installing PHP PostgreSQL extension...${defaultColour}"
	echo
	apt-get -y install php-pgsql


	#--------------------------------------------------------------------------
	# Install Multi-byte encoding dependency for unit tests on the command line
	echo
	echo -e "${greenColour}Installing multi-byte encoding dependency for PHP unit tests...${defaultColour}"
	echo
	apt-get -y install "php$phpVersion-mbstring"


	#-------------------------------------------------------------------
	# Install the PHP development package for compiling Skein-512 module
	echo
	echo -e "${greenColour}Installing PHP development package...${defaultColour}"
	echo
	apt-get -y install "php$phpVersion-dev"


	#--------------------------------------------
	# Builds and installs the Skein PHP extension
	installSkeinPhpExtension


	#-------------------------------------------
	# Install the PHPUnit unit testing framework
	echo
	echo -e "${greenColour}Installing PHPUnit unit testing framework...${defaultColour}"
	echo
	apt-get -y install phpunit


	#-------------------
	# Restart PostgreSQL
	echo
	echo -e "${greenColour}Restarting PostgreSQL...${defaultColour}"
	echo
	systemctl restart postgresql
}


#-----------------------------------
# Setup Secure Network Time Protocol
#-----------------------------------
setupNetworkTimeSync()
{
	#--------------------------------------------------------------------
	# Configure NTPSec, a security-hardened implementation of the Network
	# Time Protocol to keep the server clock up to date with UTC time
	echo
	echo -e "${greenColour}Installing NTPSec to keep the server clock up to date...${defaultColour}"
	echo
	apt-get -y install ntpsec


	#-------------------------
	# Force sync the clock now
	echo
	echo -e "${greenColour}Syncing the clock to an NTP server...${defaultColour}"
	echo
	service ntp stop
	ntpd -gq
	service ntp start


	#--------------------------------------------------------------
	# Get random numbers between 0 and x for the hours and minutes:
	firstHour=$[ ( $RANDOM % 23 ) ]
	secondHour=$[ ( $RANDOM % 23 ) ]
	minutes=$[ ( $RANDOM % 59 ) ]


	#-------------------------------------------------------------------------
	# Add cron job to sync the time at e.g. 03:21 and 14:49 every day and also
	# every reboot. This makes it harder to identify servers running Jericho
	# if it's updating the system clock at a different time for every install.
	echo
	echo -e "${greenColour}Adding Cron schedule to sync the clock at $firstHour:$minutes and"
	echo -e "$secondHour:$minutes every day and also on every reboot...${defaultColour}"
	echo
	cp "$scriptPath/scripts/cronjob.txt" /etc/cron.d/jericho


	#------------------------------------------------------------
	# Copy NTP time syncronisation script for the Cron job to run
	cp "$scriptPath/scripts/timesync.sh" /var/www/timesync.sh


	#------------------------------------
	# Replace the minutes in the cron job
	search=":minutes:"
	replace="$minutes"
	sed -i -e "s/$search/$replace/g" /etc/cron.d/jericho


	#---------------------------------------
	# Replace the first hour in the cron job
	search=":firsthour:"
	replace="$firstHour"
	sed -i -e "s/$search/$replace/g" /etc/cron.d/jericho


	#----------------------------------------
	# Replace the second hour in the cron job
	search=":secondhour:"
	replace="$secondHour"
	sed -i -e "s/$search/$replace/g" /etc/cron.d/jericho
}


#-----------------------------------------------
# Remove default Apache VHosts and configuration
#-----------------------------------------------
cleanupApacheInstallDefaults()
{
	#----------------------------------------------
	# Remove default VHosts and configuration files
	echo
	echo -e "${greenColour}Removing default Apache virtual host configurations...${defaultColour}"
	echo
	rm /etc/apache2/sites-available/*.conf
	rm /etc/apache2/sites-enabled/*.conf


	#--------------------------------------
	# Replace the default Apache ports file
	echo
	echo -e "${greenColour}Removing default Apache ports configuration...${defaultColour}"
	echo
	cp scripts/apache-ports.conf /etc/apache2/ports.conf
}


#-----------------------------------------------------------
# Restart Apache to load the configuration files and modules
#-----------------------------------------------------------
restartApache()
{
	echo
	echo -e "${greenColour}Restarting Apache to load new modules...${defaultColour}"
	echo
	systemctl restart apache2
}


#-------------------------------------------------------
# Show status message with the created database password
#-------------------------------------------------------
showCompletion()
{
	#--------------------
	# Show status message
	echo
	echo -e "${blueColour}Main installation script succeeded...${defaultColour}"
	echo
	echo -e "${greenColour}Server database password:${defaultColour} $serverDatabasePassword"
	echo
}


#------------------------------------------------------------------------------
# Main install function to install all dependencies and setup the default group
#------------------------------------------------------------------------------
mainInstall()
{
	#-----------------------------------------------------------------------------------------
	# Show initial start message and pause for 3 seconds so they have time to read the warning
	echo
	echo -e "${redColour}Warning: This script is designed to be run on a clean server install.${defaultColour}"
	echo -e "${redColour}If this is not the case, press Ctrl + C to abort or you may lose data.${defaultColour}"
	echo
	echo -e "${blueColour}Running main installation script...${defaultColour}"
	echo
	sleep 3


	#--------------------------------
	# Perform main dependency install
	setupFirewall
	updatePackages
	installWebServer
	installDatabase
	installPhp
	installPhpExtensions
	setupNetworkTimeSync
	cleanupApacheInstallDefaults
	showCompletion


	#-------------------------
	# Add a default chat group
	configureDefaultGroup
}
