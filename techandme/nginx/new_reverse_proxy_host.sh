#!/bin/bash

# This script sets up a new host for a host on Nginx Reverse Proxy that are connected to Cloudflare.
# Based on:
# https://www.techandme.se/update-your-nginx-config-with-the-latest-ip-ranges-from-cloudflare/
# https://www.techandme.se/set-up-nginx-reverse-proxy/

set -e

## DOMAIN.HOSTNAME 	= 	example.techandme
## URL 			= 	example.techandme.se
DOMAIN="example"
HOSTNAME=$DOMAIN.techandme
URL=$HOSTNAME.se

# Ports
APACHEPORT="80"
NGINXPORT="443"

# IP
APACHEHOSTIP="192.168.8.100"
NGINXHOSTIP="192.168.4.201"

# Error message 404 500 502 503 504
ERRORMSG="Down for maintenance. Please try again in a few minutes..."
SECONDS=4
REDIRECT=https://techandmedown.fsgo.se/

# SSL
SSLPATH="/etc/letsencrypt/live/$URL"
CERTNAME="fullchain.pem"
KEY="privkey.pem"
HTTPS_CONF="/etc/nginx/sites-available/$DOMAIN.conf"

# CF script dir
CFDIR="/etc/nginx/sites-available/cloudflare_ip"

# Nginx variables
upstream='$upstream'
host='$host'
remote_addr='$remote_addr'
proxy_add_x_forwarded_for='$proxy_add_x_forwarded_for'
request_uri='$request_uri'

##################################################

# Remove dirs for script
if [ -d $CFDIR/$HOSTNAME ];
then
        rm -r $CFDIR/$HOSTNAME
fi

if [ -f /etc/nginx/sites-enabled/$DOMAIN.conf ];
then 
        rm /etc/nginx/sites-enabled/$DOMAIN.conf
fi

if [ -f /etc/nginx/sites-available/$DOMAIN.conf ];
then 
        rm /etc/nginx/sites-available/$DOMAIN.conf
fi

# Create cf dir
mkdir $CFDIR
mkdir $CFDIR/$HOSTNAME


# cloudflare-new-ip.sh
if [ -f $CFDIR/$HOSTNAME/cloudflare-new-ip.sh ];
        then
        echo "CFNEWIP exists"
else
        touch "$CFDIR/$HOSTNAME/cloudflare-new-ip.sh"
        cat << CFNEWIP > "$CFDIR/$HOSTNAME/cloudflare-new-ip.sh"
( cat $CFDIR/$HOSTNAME/nginx-$DOMAIN-before ; wget -O- https://www.cloudflare.com/ips-v4 | sed 's/.*/     	set_real_ip_from &;/' ; cat $CFDIR/$HOSTNAME/nginx-$DOMAIN-after ) > $HTTPS_CONF
CFNEWIP
fi


# Error message when server is down
if [ -f /usr/share/nginx/html/$DOMAIN-error.html ];
then
        rm /usr/share/nginx/html/$DOMAIN-error.html
        touch "/usr/share/nginx/html/$DOMAIN-error.html"
        cat << NGERROR > "/usr/share/nginx/html/$DOMAIN-error.html"
<!DOCTYPE html>
<html>
<head>
   <!-- HTML meta refresh URL redirection -->
   <meta http-equiv="refresh"
   content="$SECONDS; url=$REDIRECT">
</head>
<body>
   <p>$ERRORMSG</p>
</body>
</html>
NGERROR
fi


# Let's Encrypt
echo "Generating SSL certificate..."
systemctl stop nginx.service
bash /opt/letsencrypt/letsencrypt-auto certonly --standalone -d $URL
if [[ $? > 0 ]]
then
	systemctl start nginx.service
	exit 1
else
	crontab -u root -l | { cat; echo "@monthly /etc/nginx/sites-available/scripts/letsencryptrenew.sh"; } | crontab -u root -
	systemctl start nginx.service
fi

mkdir -p /etc/nginx/sites-available/scripts
cat << CRONTAB > "/etc/nginx/sites-available/scripts/letsencryptrenew.sh"
#!/bin/sh
systemctl stop nginx.service
set -e
if ! /opt/letsencrypt/letsencrypt-auto renew > /var/log/letsencrypt/renew.log 2>&1 ; then
        echo Automated renewal failed:
        cat /var/log/letsencrypt/renew.log
        exit 1
fi
systemctl start nginx.service
if [[ $? -gt 0 ]]
then
        echo "Let's Encrypt FAILED!"--$(date +%Y-%m-%d_%H:%M) >> /var/log/letsencrypt/cronjob.log
        reboot
else
        echo "Let's Encrypt SUCCESS!"--$(date +%Y-%m-%d_%H:%M) >> /var/log/letsencrypt/cronjob.log
fi
CRONTAB

chmod +x /etc/nginx/sites-available/scripts/letsencryptrenew.sh


# Generate DHparams chifer
if [ -f $SSLPATH/dhparams.pem ];
        then
        echo "$SSLPATH/dhparams.pem exists"
else
openssl dhparam -out $SSLPATH/dhparams.pem 4096
fi


# Nginx before
if [ -f $CFDIR/$HOSTNAME/nginx-$DOMAIN-before ];
        then
        echo "nginx-$DOMAIN-before exists"
else
        touch "$CFDIR/$HOSTNAME/nginx-$DOMAIN-before"
        cat << NGBEFORE > "$CFDIR/$HOSTNAME/nginx-$DOMAIN-before"
server {
        # Cloudflare IP that is masked by mod_real_ip

	error_page 404 500 502 503 504 /$DOMAIN-error.html;
        location = /$DOMAIN-error.html {
                root /usr/share/nginx/html;
                internal;
        }
NGBEFORE
fi


# Nginx after
if [ -f $CFDIR/$HOSTNAME/nginx-$DOMAIN-after ];
        then
        echo "nginx-$DOMAIN-after exists"
else
        touch "$CFDIR/$HOSTNAME/nginx-$DOMAIN-after"
        cat << NGAFTER > "$CFDIR/$HOSTNAME/nginx-$DOMAIN-after"

	real_ip_header     X-Forwarded-For;
        real_ip_recursive  on;

        listen $NGINXHOSTIP:$NGINXPORT ssl http2;

        ssl on;
        ssl_certificate $SSLPATH/$CERTNAME;
        ssl_certificate_key $SSLPATH/$KEY;
	ssl_dhparam $SSLPATH/dhparams.pem;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:10m;
        ssl_stapling on;
        ssl_stapling_verify on;

        # Only use safe chiphers
	ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
	ssl_prefer_server_ciphers on;
	
	# Add secure headers
	add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
	add_header X-Content-Type-Options nosniff;
	
        server_name $URL;
        set $upstream $APACHEHOSTIP:$APACHEPORT;

        location / {
                proxy_pass_header Authorization;
                proxy_pass http://$upstream;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP  $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_http_version 1.1;
                proxy_set_header Connection "";
                proxy_buffering off;
                proxy_request_buffering off;
		client_max_body_size 0;
                proxy_read_timeout  36000s;
                proxy_redirect off;
                proxy_ssl_session_reuse off;
        }
}

server {
  listen $NGINXHOSTIP:$APACHEPORT;
  server_name $URL;
  return 301 https://$URL$request_uri;
}
NGAFTER
fi


# Write new host
bash $CFDIR/$HOSTNAME/cloudflare-new-ip.sh


# Check which port is used and change settings accordingly
if [ $APACHEPORT -eq 443 ];then
sed -i "s|proxy_pass http://|proxy_pass https://|g" $CFDIR/$HOSTNAME/nginx-$DOMAIN-after
sed -i "s|proxy_ssl_session_reuse on|proxy_ssl_session_reuse off|g" $CFDIR/$HOSTNAME/nginx-$DOMAIN-after
fi


# Put the conf in new_ip_cloudflare.sh
sed -i "1s|^|bash $CFDIR/$HOSTNAME/cloudflare-new-ip.sh\n|" /etc/nginx/sites-available/scripts/new_ip_cloudflare.sh


# Enable host
ln -s /etc/nginx/sites-available/$DOMAIN.conf /etc/nginx/sites-enabled/$DOMAIN.conf
service nginx configtest
if [[ $? > 0 ]]
then
	echo "Host creation for $URL has failed."
        exit 1
else
	bash $CFDIR/$HOSTNAME/cloudflare-new-ip.sh
	service nginx reload
	echo
	echo "Host for $URL created and activated!"
	exit 0
fi
