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


#---------------------
# Update package lists. NB: if required for development, to update to the latest time (e.g. if restored from VM snapshot
# which would put the clock out of date and apt-get update would no longer work) the following command can be used:
# sudo date -s '2023-01-02 10:45:00'
#---------------------
updatePackageList()
{
	#-------------------------------------------------------------------------------
	# Update package lists for packages that need upgrading as well as new packages
	echo
	echo -e "${greenColour}Updating package lists from the repository...${defaultColour}"
	echo
	apt-get -y update

	# Add check for if the package installation failed due to network error etc, then recursively try run again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch the package list, retrying...${defaultColour}"
		echo
		sleep 3
		updatePackageList
	fi
}


#----------------
# Update packages
#----------------
updatePackages()
{
	#--------------------------------------------------------------------------
	# Download and install the updates for each outdated package and dependency
	echo
	echo -e "${greenColour}Installing latest updates of packages currently installed...${defaultColour}"
	echo
	apt-get -y upgrade

	# Add check for if the package installation failed due to network error etc, then recursively try run again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch and install the packages, retrying...${defaultColour}"
		echo
		sleep 3
		updatePackages
	fi
}


#-------------------------
# Install a basic firewall
#-------------------------
installFirewall()
{
	#------------------------------------------------------------
	# Install the Uncomplicated Firewall (UFW) so we can set some basic rules
	echo
	echo -e "${greenColour}Installing the Uncomplicated Firewall (UFW)...${defaultColour}"
	echo
	apt-get -y install ufw

	# Add check for if the package installation failed due to network error etc, then recursively try run again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch and install the package, retrying...${defaultColour}"
		echo
		sleep 3
		installFirewall
	fi
}


#--------------------------
# Install Apache web server
#--------------------------
installWebServer()
{
	#--------------------------
	# Install Apache web server
	echo
	echo -e "${greenColour}Installing Apache web server...${defaultColour}"
	echo
	apt-get -y install apache2

	# Add check for if fetch failed, then try run the function again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch and install package, retrying...${defaultColour}"
		echo
		sleep 3
		installWebServer
	fi
}


#-------------------------------
# Install ModSecurity for Apache
#-------------------------------
installModSecurity()
{
	#-------------------------------
	# Install and enable ModSecurity
	echo
	echo -e "${greenColour}Installing ModSecurity...${defaultColour}"
	echo
	apt-get -y install libapache2-mod-security2

	# Add check for if fetch failed, then try run the function again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch and install package, retrying...${defaultColour}"
		echo
		sleep 3
		installModSecurity
	fi
}


#-----------------------------------
# Install PostgreSQL database client
#-----------------------------------
installDatabaseClient()
{
	#-------------------------------------------------------------
	# Install the PostgreSQL client for connecting to the database
	echo
	echo -e "${greenColour}Installing the PostgreSQL client for connecting to the database...${defaultColour}"
	echo
	apt-get -y install postgresql-client

	# Add check for if fetch failed, then try run the function again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch and install package, retrying...${defaultColour}"
		echo
		sleep 3
		installDatabaseClient
	fi
}


#-----------------------------------
# Install PostgreSQL database server
#-----------------------------------
installDatabaseServer()
{
	#------------------------------
	# Install the PostgreSQL server
	echo
	echo -e "${greenColour}Installing the PostgreSQL server...${defaultColour}"
	echo
	apt-get -y install postgresql

	# Add check for if fetch failed, then try run the function again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch and install package, retrying...${defaultColour}"
		echo
		sleep 3
		installDatabaseServer
	fi
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

	# Add check for if fetch failed, then try run the function again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch and install package, retrying...${defaultColour}"
		echo
		sleep 3
		installPhp
	fi


	#--------------------------------------------------------------------------------
	# Get the major version e.g. 7 and minor version e.g. 2 of PHP which is installed
	local phpMajorVersion=$(php -r 'echo PHP_MAJOR_VERSION;')
	local phpMinorVersion=$(php -r 'echo PHP_MINOR_VERSION;')


	#----------------------------------------------------------------------------
	# Set the version e.g. 7.2 as a global which might be used by other functions
	phpVersion="$phpMajorVersion.$phpMinorVersion"
	echo
	echo -e "${greenColour}PHP version $phpVersion installed.${defaultColour}"
	echo
}


#------------------------------
# Install PHP module for Apache
#------------------------------
installPhpApacheExtension()
{
	#------------------------------
	# Install PHP module for Apache
	echo
	echo -e "${greenColour}Installing PHP module for Apache...${defaultColour}"
	echo
	apt-get -y install libapache2-mod-php

	# Add check for if fetch failed, then try run the function again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch and install package, retrying...${defaultColour}"
		echo
		sleep 3
		installPhpApacheExtension
	fi
}


#---------------------------------
# Install PHP PostgreSQL extension
#---------------------------------
installPhpPostgresExtension()
{
	#---------------------------------
	# Install PHP PostgreSQL extension
	echo
	echo -e "${greenColour}Installing PHP PostgreSQL extension...${defaultColour}"
	echo
	apt-get -y install php-pgsql

	# Add check for if fetch failed, then try run the function again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch and install package, retrying...${defaultColour}"
		echo
		sleep 3
		installPhpPostgresExtension
	fi
}


#------------------------------------------
# Install PHP multi-byte encoding extension
#------------------------------------------
installPhpMultiByteEncodingExtension()
{
	#--------------------------------------------------------------------------
	# Install Multi-byte encoding dependency for unit tests on the command line
	echo
	echo -e "${greenColour}Installing multi-byte encoding dependency for PHP unit tests...${defaultColour}"
	echo
	apt-get -y install "php$phpVersion-mbstring"

	# Add check for if fetch failed, then try run the function again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch and install package, retrying...${defaultColour}"
		echo
		sleep 3
		installPhpMultiByteEncodingExtension
	fi
}


#---------------------------------------------------------
# Install PHP development extension
#---------------------------------------------------------
installPhpDevelopmentExtension()
{
	#-------------------------------------------------------------------
	# Install the PHP development package for compiling Skein-512 module
	echo
	echo -e "${greenColour}Installing PHP development package...${defaultColour}"
	echo
	apt-get -y install "php$phpVersion-dev"

	# Add check for if fetch failed, then try run the function again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch and install package, retrying...${defaultColour}"
		echo
		sleep 3
		installPhpDevelopmentExtension
	fi
}


#-----------------------------------
# Install PHP unit testing extension
#-----------------------------------
installPhpUnitTestingExtension()
{
	#-------------------------------------------
	# Install the PHPUnit unit testing framework
	echo
	echo -e "${greenColour}Installing PHPUnit unit testing framework...${defaultColour}"
	echo
	apt-get -y install phpunit

	# Add check for if fetch failed, then try run the function again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch and install package, retrying...${defaultColour}"
		echo
		sleep 3
		installPhpUnitTestingExtension
	fi
}


#-----------------------------------
# Setup Secure Network Time Protocol
#-----------------------------------
installNetworkTimeSyncPackage()
{
	#-----------------------------------------------------------------------------------
	# Disable systemd-timesyncd and configure NTPsec, a security-hardened implementation
	# of the Network Time Protocol to keep the server clock up to date with UTC time.
	echo
	echo -e "${greenColour}Installing NTPsec to keep the server clock up to date...${defaultColour}"
	echo
	systemctl stop systemd-timesyncd.service
	systemctl disable systemd-timesyncd.service
	systemctl mask systemd-timesyncd.service
	apt-get -y install ntpsec

	# Add check for if fetch failed, then try run the function again
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${yellowColour}Failed to fetch and install package, retrying...${defaultColour}"
		echo
		sleep 3
		installNetworkTimeSyncPackage
	fi
}


#------------------------------------------------------------------------------------
# Configure a basic firewall. This is the first step before configuring anything else
#------------------------------------------------------------------------------------
configureFirewall()
{
	#-----------------------------------------------------------------------------------------
	# Set rules so only SSH (port 22) and Web (port 80) traffic will be allowed through to the
	# web server. This assumes the admin wants to administer the server via SSH. They can of
	# course remove this rule if they have another way to manage the server.
	echo
	echo -e "${greenColour}Configuring firewall to allow only SSH and HTTP traffic...${defaultColour}"
	echo
	ufw default deny
	ufw allow 22
	ufw allow 80


	#-----------------------------------------------------------------------------------------
	# Enable the firewall and ignore the warning that it might disable existing SSH connection
	ufw --force enable
	ufw status verbose
}


#---------------------------------
# Configure ModSecurity for Apache
#---------------------------------
configureModSecurity()
{
	#---------------
	# Enable the mod
	a2enmod security2


	#--------------------------------------------------------------------------------------------
	# Replace the "Server: Apache/2.4.x (Ubuntu)" in the network response with "Server: nginx" so
	# NSA/TAO etc waste time trying their exploits for Nginx instead of their Apache exploits
	echo
	echo -e "${greenColour}Replacing server headers...${defaultColour}"
	echo
	echo -e "ServerTokens Full" >> /etc/apache2/apache2.conf
	echo -e "SecServerSignature \"nginx\"\n" >> /etc/apache2/apache2.conf


	#-----------------------
	# Turn on rewrite engine
	echo
	echo -e "${greenColour}Enabling rewrite module...${defaultColour}"
	echo
	a2enmod rewrite
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


#---------------------------------
# Configure the PostgreSQL install
#---------------------------------
configureDatabase()
{
	#-----------------------------------------------------------------------------------
	# Create a cryptographically strong psuedo-random 128 bit DB password in hexadecimal
	serverDatabasePassword=$(getRandomBytesAsHexString 16)


	#---------------------
	# Create database user
	echo
	echo -e "${greenColour}Creating database user 'jerichouser'...${defaultColour}"
	echo
	sudo -iu postgres psql -c "CREATE USER jerichouser WITH PASSWORD '$serverDatabasePassword';"

	# Add check for if the command failed
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${redColour}Failed creating database user...${defaultColour}"
		echo
		exit 1
	fi


	# Output password for debugging
	#------------------------------
	echo
	echo -e "${greenColour}Database user 'jerichouser' created with password: $serverDatabasePassword${defaultColour}"
	echo


	# Update local authentication method so we can run scripts locally without prompting for password
	#------------------------------------------------------------------------------------------------
	search="local   all             postgres                                peer"
	replace="local   all             postgres                                trust"
	sudo sed -i -e "s/$search/$replace/g" /etc/postgresql/13/main/pg_hba.conf
	sudo systemctl restart postgresql


	#-----------------------------------------------------------------------------------
	# Create test database and tables for unit tests. NB: requires chmod a+rx (read and
	# execute permissions for all users) on the sql script files to run. Also NB:
	# requires en_US.UTF-8 locale. If this is not on the system it can be added with:
	# sudo dpkg-reconfigure locales. You can verify it is installed by running: locale -a.
	# After that you would need to restart with: sudo service postgresql restart then
	# re-run the script.
	# https://stackoverflow.com/questions/9736085/run-a-postgresql-sql-file-using-command-line-arguments/12085561#12085561
	echo
	echo -e "${greenColour}Creating test database and tables...${defaultColour}"
	echo
	psql -U postgres -a -f "$scriptPath/scripts/create-test-tables-postgresql.sql"


	# Add check for if the command failed
	if [[ $? > 0 ]]
	then
		echo
		echo -e "${redColour}Failed creating test database and tables...${defaultColour}"
		echo
		exit 1
	fi
}


#------------------------------------------------
# Builds and installs the Skein-512 PHP extension
#------------------------------------------------
configureSkeinPhpExtension()
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


	#---------------------
	# Show success message
	echo
	echo -e "${greenColour}Skein-512 PHP extension installed.${defaultColour}"
	echo
}


#------------------------------------------------------------------------------------------------------------
# Configures the Secure Network Time Protocol
# NB: not using NTS yet, ref: https://docs.ntpsec.org/latest/NTS-QuickStart.html. Other NTS servers can be
# added by editing /etc/ntpsec/ntp.conf configuration file, adding servers and restarting the ntpsec service.
#------------------------------------------------------------------------------------------------------------
configureNetworkTimeSyncPackage()
{
	#--------------------------------------------------------------------------
	# Force sync the clock now, NB: creating a directory for logs to hide error
	echo
	echo -e "${greenColour}Restarting NTPsec and syncing the clock...${defaultColour}"
	echo
	mkdir -p /var/log/ntpsec
	systemctl restart ntpsec


	#--------------------------------------------------------------------------
	# Show the status, NB: using --no-pager is the same as piping output to cat
	# e.g. systemctl status ntpsec.service | cat
	echo
	echo -e "${greenColour}Showing NTPsec status...${defaultColour}"
	echo
	systemctl status ntpsec.service --no-pager


	#--------------------
	# Showing NTP servers
	echo
	echo -e "${greenColour}Showing NTP servers...${defaultColour}"
	echo
	ntpq -pn


	#--------------------------------------------------------------
	# Get random numbers between 0 and x for the hours and minutes:
	firstHour=$[ ( $RANDOM % 23 ) ]
	secondHour=$[ ( $RANDOM % 23 ) ]
	minutes=$[ ( $RANDOM % 59 ) ]


	#-------------------------------------------------------------------------
	# Add cron job to sync the time at e.g. 03:21 and 14:49 every day and also
	# every reboot. This makes it harder to identify servers running the program
	# if it's updating the system clock at a different time for every install.
	echo
	echo -e "${greenColour}Adding Cron schedule to sync the clock at $firstHour:$minutes and"
	echo -e "$secondHour:$minutes every day and also on every reboot...${defaultColour}"
	echo
	cp "$scriptPath/scripts/cronjob.txt" /etc/cron.d/jericho


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


#------------------------------
# Do Apache Virtual Host config
#------------------------------
configureApacheVirtualHost()
{
	#----------------------------------------------------------------------------------
	# Removes the default index.html file which is put there by the Apache installation
	echo
	echo -e "${greenColour}Removing default Apache index.html file...${defaultColour}"
	echo
	rm -f $webDir/index.html


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


	#-----------------------------------------------------------------------------
	# Copy virtual host config to Apache sites-available directory and activate it
	echo
	echo -e "${greenColour}Activating chat server...${defaultColour}"
	echo
	cp scripts/apache-virtual-host.conf /etc/apache2/sites-available/jericho-virtual-host.conf
	a2ensite jericho-virtual-host.conf
}


#-------------------------------------------------------------
# Configure the API for operation (excluding chat group setup)
#-------------------------------------------------------------
configureApi()
{
	#-------------------------------------------------------------------------------------------------------
	# Copy the server files to the web root (NB: should already be in the $scriptPath dir where setup.sh is)
	echo
	echo -e "${greenColour}Copying server API files to web path $webDir/${defaultColour}"
	echo
	cp -r . "$webDir/"


	#---------------------------------------------------------
	# Change group ownership of the files to Apache's www-data
	chgrp -R www-data "$webDir"


	#---------------------------------------------------------------------------------
	# Set group to only have read permissions on files in the web API directory
	# Set group to have read & execute permissions on directories in the web directory
	find "$webDir" -type f -exec chmod 644 -c '{}' \;
	find "$webDir" -type d -exec chmod 755 -c '{}' \;


	#-----------------------------------------------
	# Set specific scripts to be executable for cron
	sudo chmod +x "$webDir/scripts/clean-database.php"
	sudo chmod +x "$webDir/scripts/timesync.sh"


	#-------------------------------------------------------
	# Show the directory contents for informational purposes
	echo
	echo -e "${greenColour}Listing directory contents of $webDir/${defaultColour}"
	echo
	ls -al "$webDir"


	#-----------------------------------------------------------------------------------------------
	# Replace the user database password (NB: the API uses the same user and password for connection
	# but a new database and new tables are created per chat group so their data is separate)
	search="jerichopassword"
	replace="$serverDatabasePassword"
	sed -i -e "s/$search/$replace/g" "$webDir/config/config.json"
	sed -i -e "s/$search/$replace/g" "$webDir/tests/config/config.json"
}


#----------------------------------------------------------------------
# Restart Apache to load the configuration files/modules and PostgreSQL
#----------------------------------------------------------------------
restartServices()
{
	#---------------
	# Restart Apache
	echo
	echo -e "${greenColour}Restarting Apache to load new modules...${defaultColour}"
	echo
	systemctl restart apache2


	#-------------------
	# Restart PostgreSQL
	echo
	echo -e "${greenColour}Restarting PostgreSQL...${defaultColour}"
	echo
	systemctl restart postgresql
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


	#----------------------------------------------------
	# Initial preparation for installing APT dependencies
	updatePackageList
	updatePackages

	#---------------------------------------------------------------
	# Perform main APT dependency installs (NB: these are done first
	# in case we need to retry each due to temporary network error)
	installFirewall
	installWebServer
	installModSecurity
	installDatabaseClient
	installDatabaseServer
	installPhp
	installPhpApacheExtension
	installPhpPostgresExtension
	installPhpMultiByteEncodingExtension
	installPhpDevelopmentExtension
	installPhpUnitTestingExtension
	installNetworkTimeSyncPackage

	#------------------------------------------
	# Configure the applications and extensions
	configureFirewall
	configureModSecurity
	configureDatabase
	configureSkeinPhpExtension
	configureNetworkTimeSyncPackage
	configureApacheVirtualHost
	configureApi

	# Final tasks
	restartServices
	showCompletion
}
