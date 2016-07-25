#!/bin/bash

SCRIPTS=/var/scripts

# Check if root
        if [ "$(whoami)" != "root" ]; then
        echo
        echo -e "\e[31mSorry, you are not root.\n\e[0mYou must type: \e[36msudo \e[0mbash nginx_install.sh"
        echo
        exit 1
fi

# Create scripts dir
mkdir -p $SCRIPTS

# Get virtual hosts
wget -q https://raw.githubusercontent.com/enoch85/scripts/master/nginx/443.sh -P $SCRIPTS
wget -q https://raw.githubusercontent.com/enoch85/scripts/master/nginx/80.sh -P $SCRIPTS

# Check if hosts gor downloaded correctly
      	if [ -f $SCRIPTS/443.sh ]; then
      		echo "443.sh OK!"
      	else
      		echo "443.sh was not downloaded"
		exit 1
	fi

        if [ -f $SCRIPTS/80.sh ]; then
                echo "80.sh OK!"
        else
                echo "80.sh was not downloaded"
                exit 1
        fi

# Ask for domain name SSL
cat << ENTERDOMAIN
+---------------------------------------------------------------+
|    Please enter the domain name you will use for the SSL host.|
|    Like this: example.com, or owncloud.example.com (1/2)	|
+---------------------------------------------------------------+
ENTERDOMAIN
	echo
	read domain443
        echo
        echo "Enter the domain name for the HTTP host:"
        read domain80
        echo
        echo "Enter the NGINX IP:"
        read nginxip
        echo
        echo "Enter the Apache host IP:"
        read apacheip
	function ask_yes_or_no() {
    	read -p "$1 ([y]es or [N]o): "
    	case $(echo $REPLY | tr '[A-Z]' '[a-z]') in
        y|yes) echo "yes" ;;
        *)     echo "no" ;;
    	esac
}
echo
if [[ "no" == $(ask_yes_or_no "Is this correct? $domain443, $domain80, $nginxip, $apacheip") ]]
	then
echo
echo
cat << ENTERDOMAIN2
+---------------------------------------------------------------+
|    OK, try again. (2/2) 					|
|    Please enter the domain name you will use for the SSL host.|
|    Like this: example.com, or owncloud.example.com		|
|    It's important that it's correct, because the script is 	|
|    based on what you enter					|
+---------------------------------------------------------------+
ENTERDOMAIN2
	echo
	echo "Enter the domain name for the SSL host:"
    	read domain443
    	echo
	echo "Enter the domain name for the HTTP host:"
	read domain80
	echo
	echo "Enter the NGINX IP:"
	read nginxip
	echo
	echo "Enter the Apache host IP:"
	read apacheip
fi


# Edit the domain and IP
sed -i "s|example.com|$domain443|g" $SCRIPTS/443.sh
sed -i "s|nginxip|$nginxip|g" $SCRIPTS/443.sh
sed -i "s|apacheip|$apacheip|g" $SCRIPTS/443.sh
sed -i "s|example.com|$domain80|g" $SCRIPTS/80.sh
sed -i "s|nginxip|$nginxip|g" $SCRIPTS/80.sh
sed -i "s|apacheip|$apacheip|g" $SCRIPTS/80.sh

# Create dir for SSL certs
mkdir -p /etc/ssl/$domain443

# Activate hosts
bash $SCRIPTS/443.sh
bash $SCRIPTS/80.sh
service nginx configtest
if [[ $? > 0 ]]
then
	echo "Something went wrong, exiting..."
        exit 1
else
	echo "Configtest OK!"
	sleep 5
fi

# Update system
apt-get install aptitude -y
apt-get update -q2 -y
aptitude full-upgrade -y

# Reboot
reboot
