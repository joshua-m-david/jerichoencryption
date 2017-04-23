#!/bin/bash
#
# Jericho Comms - Information-theoretically secure communications
# Copyright (c) 2013-2017  Joshua M. David
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation in version 3 of the License.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see [http://www.gnu.org/licenses/].


# Jericho Comms server installation script requirements:
# - Ubuntu Server 16.04.x or later
# - Working internet connection
# - Run the script as sudo or under the root user (e.g. sudo su)


#---------------------------------------
# Make sure only root can run the script
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root. For example: sudo ./setup.sh"
   exit 1
fi


#---------------------------------------------------------------------------------------
# Get absolute path to this script, e.g. /home/user/jericho-comms-v1.5.3/server/setup.sh
script=$(readlink -f "$0")

# Thus, the absolute path to the script is /home/user/jericho-comms-v1.5.3/server/
scriptPath=$(dirname "$script")

# Change to the current script path
cd "$scriptPath"


#----------------------------
# Start question for the user
echo "Do you wish to start the installation of Jericho Comms server? (y or n)"
read startInstallUserResponse

# Exit out if 'Y' or 'y' is not entered
if [[ "$startInstallUserResponse" == "Y" || "$startInstallUserResponse" == "y" ]]; then
    echo
	echo "Proceeding with installation..."
else
	echo
	echo "Installation cancelled."
	exit 0
fi


#-------------------------------------------------------------
# Prompt user for MySQL password as it is used in a few places
echo
echo "Enter a password for MySQL:"

# Read response from user
read passwordMySql


#----------------------------------------------------
# Ask the user if they have a domain they wish to use
echo
echo "Do you wish to use a domain name with the server? (y or n)"

# Read response from user
read enterDomainName

# Exit out if 'Y' or 'y' is not entered
if [[ "$enterDomainName" == "Y" || "$enterDomainName" == "y" ]]; then

	# Read response from user
	echo
	echo "Enter the domain name e.g. example.com:"
	read domainName
else
	echo
	echo "No domain name entered, server will be accessible by direct IP only."
	echo "This can be changed later in the Virtual Host configuration."
fi


#------------------------------------------
# Get the number of users in the chat group
echo
echo "How many users in the chat group? (2, 3, 4, 5, 6, or 7)"
read numOfChatUsers

# Check if the range of users is between 2 and 7 users (inclusive)
if [ "$numOfChatUsers" -ge 2 -a "$numOfChatUsers" -le 7 ]; then
	echo
	echo "Entered $numOfChatUsers users."
else
	# Invalid choice, default to 2 users
	numOfChatUsers=2
	echo
	echo "Incorrect entry, defaulting to $numOfChatUsers users. This can be changed later in the configuration."
fi


#------------------------------------------
# Display that the installation is starting
echo
echo "Starting installation..."

# Update package lists
echo
echo "Updating package lists from the repository..."
echo
apt-get -y update

# Update installed software
echo
echo "Installing the newest versions of all packages currently installed on the system..."
echo
apt-get -y upgrade


#----------------------------------------------------------------------------------
# Pre-set password for MySQL so the tasksel installation process does not prompt it
sudo debconf-set-selections <<< "mysql-server mysql-server/root_password password $passwordMySql"
sudo debconf-set-selections <<< "mysql-server mysql-server/root_password_again password $passwordMySql"


#---------------------------------------------------------------------
# Install Apache, MySQL and PHP using the tasksel installation process
echo
echo "Installing Apache, MySQL and PHP..."
echo
apt-get -y install lamp-server^


#-------------------------------------------------------------------------------------
# Install dependency MCrypt for PHP which is used for generating secure random numbers
echo
echo "Installing dependency Mcrypt for PHP..."
echo
apt-get -y install php7.0-mcrypt
phpenmod mcrypt


#--------------------------------------------------------------------------
# Install Multi-byte encoding dependency for unit tests on the command line
echo
echo "Installing multi-byte encoding dependency for PHP unit tests..."
echo
apt-get -y install php7.0-mbstring


#-------------------------------------------
# Install the PHP module development package
echo
echo "Installing PHP module development package..."
echo
apt-get -y install php7.0-dev


#----------------------------------------------------------------------------------
# Removes the default index.html file which is put there by the Apache installation
echo
echo "Removing default Apache index.html file..."
echo
rm -f /var/www/html/index.html


#--------------------------------------
# Copy the server files to the web root
echo
echo "Installing server files..."
echo
cp -rR . /var/www/html/

# Change ownership of the files to Apache's www-data
chown -R www-data:www-data /var/www/html/

# Set directory permissions to 755 and files to 644
find /var/www/html -type d -exec chmod 755 {} +
find /var/www/html -type f -exec chmod 644 {} +

# Set NTP time syncronisation script to executable for the Cron job to run
chmod +x /var/www/html/timesync.sh

# Show the directory contents for informational purposes
echo
echo "Listing directory contents of /var/www/html/"
echo
ls -al /var/www/html


#---------------------------------------
# Replace the default Apache config file
echo
echo "Updating Apache virtual host configuration..."
echo
cp apache-virtual-host.conf /etc/apache2/sites-available/000-default.conf

# If a domain name was entered
if [[ ${domainName:+1} ]]; then

	# Replace and enable the ServerName in the Apache virtual host file
	search="#ServerName example.com"
	replace="ServerName $domainName"
    sed -i -e "s/$search/$replace/g" /etc/apache2/sites-available/000-default.conf

	# Replace and enable the ServerAlias in the Apache virtual host file with wildcard to accept all requests from subdomains too
	search="#ServerAlias www.example.com"
	replace="ServerAlias *.$domainName"
	sed -i -e "s/$search/$replace/g" /etc/apache2/sites-available/000-default.conf

	# Output new Apache virtual host file
	echo
	echo "Updated Apache virtual host file with domain '$domainName':"
fi

# Display the virtual host file
echo
echo "Apache virtual host file at /etc/apache2/sites-available/000-default.conf:"
echo
cat /etc/apache2/sites-available/000-default.conf


#----------------------------------------------
# Build and install the Skein-512 PHP extension
echo
echo "Building and installing the Skein-512 extension..."
echo
cd lib/skein/
phpize
./configure --enable-skein
make clean
make
make install
make test

# Cleanup from previous install if the script is re-run
search="extension=skein.so"
replace=""
sed -i -e "s/$search/$replace/g" /etc/php/7.0/apache2/php.ini
sed -i -e "s/$search/$replace/g" /etc/php/7.0/cli/php.ini

# Add the extension to the end of the PHP ini files
echo "extension=skein.so" >> /etc/php/7.0/apache2/php.ini
echo "extension=skein.so" >> /etc/php/7.0/cli/php.ini

# Display the lines of the php.ini files
echo
echo "Last line of /etc/php/7.0/apache2/php.ini file:"
echo
tail -n1 /etc/php/7.0/apache2/php.ini
echo
echo "Last line of /etc/php/7.0/cli/php.ini file:"
echo
tail -n1 /etc/php/7.0/cli/php.ini

# Return out of the /lib/skein/ directory back up to the /server/ directory
cd ..
cd ..


#-----------------------------------------------------------------------------------
# Restart Apache to load the new virtual host configuration and new Skein-512 module
echo
echo "Restarting Apache to load the new virtual host configuration and new Skein-512 module..."
echo
service apache2 restart


#-------------------------------------------------------------
# Install database on MySQL and suppress warnings to /dev/null
echo
echo "Installing database on MySQL..."
echo
mysql -u root "-p$passwordMySql" < createtables.sql 2>/dev/null

# Show which tables were installed
echo "Tables installed:"
echo
mysql -u root "-p$passwordMySql" -e "use jericho; show tables;" 2>/dev/null


#--------------------------------------------
# Replace various values in the configuration
echo
echo "Replacing configuration values..."
echo

# Replace the number of users in the config file
search="numberOfUsers = 2;"
replace="numberOfUsers = $numOfChatUsers;"
sed -i -e "s/$search/$replace/g" /var/www/html/config/config.php

# Get a cryptographically strong psuedo-random 512 bit key in hexadecimal
serverKey=$(hexdump -n 64 -e '4/4 "%08X"' /dev/urandom)

# Convert the capital letters in the key to lowercase
serverKeyLowercase=${serverKey,,}

# Display generated key
echo
echo "Generated server key: $serverKeyLowercase"
echo "This can be changed later in the configuration."

# Replace the default server key
search="serverKey = '89975057bac787e526aba890440dd89f95f2ea14a1779dcd3ff4bac215418a7566dafb5bf19417ec6d152f636ba8eb3ac4bb823086da8541798f67c3a1055d2e';"
replace="serverKey = '$serverKeyLowercase';"
sed -i -e "s/$search/$replace/g" /var/www/html/config/config.php

# Replace the database password in the configuration
search="'covert'"
replace="'$passwordMySql'"
sed -i -e "s/$search/$replace/g" /var/www/html/config/config.php

# Replace the database password in the unit tests file
search="'covert'"
replace="'$passwordMySql'"
sed -i -e "s/$search/$replace/g" /var/www/html/tests.php

# Output configuration file
echo
echo "Configuration file /var/www/html/config/config.php updated."
echo
cat /var/www/html/config/config.php


#----------------------------------------------------------------------------------------------------------------------
# Configure a basic firewall so only SSH (port 22) and HTTP (port 80) traffic will be allowed through to the web server
echo
echo "Configuring firewall so only SSH (port 22) and HTTP (port 80) traffic are allowed through..."
echo
ufw default deny
ufw allow 22
ufw allow 80
ufw logging on

# Enable the firewall and ignore the warning that it might disable existing SSH connection
ufw --force enable
ufw status


#--------------------------------------------------
# Configure NTP to keep the server clock up to date
echo
echo "Installing the Network Time Protocol to keep the server clock up to date..."
echo
apt-get -y install ntp

# Force sync the clock now
echo
echo "Syncing the clock to an NTP server..."
echo
service ntp stop
ntpd -gq
service ntp start

# Add Cron job to sync the time at 03:00 and 15:00 every day and also on every reboot
echo
echo "Adding Cron schedule to sync the clock at 03:00 and 15:00 every day and also on every reboot..."
echo
cp /var/www/html/cronjob.txt /etc/cron.d/jericho


#-------------------------------------------------
# Fetch and verify PHPUnit then run the unit tests
echo
echo "Fetching and verifying PHPUnit library to run unit tests..."
echo

# Don't delete phpunit.phar after the tests are complete
clean=0

# Get GPG key and compare the fingerprint
gpg --fingerprint D8406D0D82947747293778314AA394086372C20A
if [ $? -ne 0 ]; then
    echo -e "\033[33mDownloading PGP Public Key...\033[0m"
    gpg --recv-keys D8406D0D82947747293778314AA394086372C20A
    # Sebastian Bergmann <sb@sebastian-bergmann.de>
    gpg --fingerprint D8406D0D82947747293778314AA394086372C20A
    if [ $? -ne 0 ]; then
        echo -e "\033[31mCould not download PGP public key for verification\033[0m"
        exit
    fi
fi

# Clean up old files if they exist
if [ "$clean" -eq 1 ]; then
    if [ -f phpunit.phar ]; then
        rm -f phpunit.phar
    fi
    if [ -f phpunit.phar.asc ]; then
        rm -f phpunit.phar.asc
    fi
fi

# Grab the latest release and its signature
if [ ! -f phpunit.phar ]; then
    wget https://phar.phpunit.de/phpunit.phar
fi
if [ ! -f phpunit.phar.asc ]; then
    wget https://phar.phpunit.de/phpunit.phar.asc
fi

# Verify before running
gpg --verify phpunit.phar.asc phpunit.phar
if [ $? -eq 0 ]; then
    echo
    echo -e "\033[33mBegin Unit Testing\033[0m"

	# Run the server code testing suite
    php phpunit.phar phpunit /var/www/html/tests.php

	# Cleanup
    if [ "$clean" -eq 1 ]; then
        echo -e "\033[32mCleaning Up!\033[0m"
        rm -f phpunit.phar
        rm -f phpunit.phar.asc
    fi
else
	# Bad signature move the file to temp directory
    echo
    chmod -x phpunit.phar
    mv phpunit.phar /tmp/bad-phpunit.phar
    mv phpunit.phar.asc /tmp/bad-phpunit.phar.asc
    echo -e "\033[31mSignature did not match! PHPUnit has been moved to /tmp/bad-phpunit.phar\033[0m"
	echo "Unit tests were not run."
fi


#-------------------------------------------
# Final output and instructions for the user
echo
echo "Installation complete!"
echo
echo "Copy and paste the following server address and key into the client program to test the server connection:"
echo

# If the domain is set, output that
if [[ ${domainName:+1} ]]; then
	echo "Server address:  http://$domainName";
else
	# Get the public server IPs (maybe there is IPv4 and IPv6)
	serverIpAddresses=($(hostname -I))

	# Loop through and display them
	for serverIpAddress in "${serverIpAddresses[@]}"
	do
		echo "Server address:  http://$serverIpAddress"
	done
fi

# Output the server key and MySQL password in case they need it
echo "Server key:  $serverKeyLowercase"
echo
echo "Remember the MySQL password entered earlier (or save it in a password manager) for future use."
echo
echo "MySQL password:  $passwordMySql"


#----------------------------------------------------
# Ask the user if they wish to clear the bash history
echo
echo "For security you should clear the output of this script from the bash shell. Do you wish to do this now? (y or n)"
read clearBashShellUserResponse

# Clear the bash history, overwrite ~/.bash_history immediately and clear the console as well
if [[ "$clearBashShellUserResponse" == "Y" || "$clearBashShellUserResponse" == "y" ]]; then
	echo
    echo "Clearing bash history..."
	sleep 1 && history -c && history -w && clear
else
	# Otherwise let them do it at their own convenience if they're still testing
	echo
	echo "History not cleared. You should do this later with the command:"
	echo "history -c && history -w && clear"
	exit 0
fi
