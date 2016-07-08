#!/bin/bash

# This script sets up a new host for a host on Nginx Reverse Proxy that are connected to Cloudflare.
# Based on:
# https://www.techandme.se/update-your-nginx-config-with-the-latest-ip-ranges-from-cloudflare/
# https://www.techandme.se/set-up-nginx-reverse-proxy/


set -e

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
ERRORMSG="Down for maintenance. You are now being redirected to our co-location server..."
SECONDS=4 
REDIRECT=https://techandme.fsgo.se

# SSL
SSLPATH="/etc/nginx/ssl/techandme"
CERTNAME="techandme_wild"
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

# Create dirs for script
mkdir $CFDIR/$HOSTNAME

# Generate $HTTPS_CONF
if [ -f $HTTPS_CONF ];
        then
        echo "Virtual Host exists"
else
        touch "$HTTPS_CONF"
        cat << HTTPS_CREATE > "$HTTPS_CONF"
server {

	real_ip_header     X-Forwarded-For;
        real_ip_recursive  on;

        listen $NGINXHOSTIP:$NGINXPORT ssl;

        ssl on;
        ssl_certificate $SSLPATH/$CERTNAME.pem;
        ssl_certificate_key $SSLPATH/$CERTNAME.key;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

        # Only use safe chiffers
	ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
	ssl_prefer_server_ciphers on;

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
  return 301 https://$DOMAIN/$request_uri;
}
HTTPS_CREATE
fi

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
        echo "$DOMAIN-error.html exists"
else
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

        listen $NGINXHOSTIP:$NGINXPORT ssl;

        ssl on;
        ssl_certificate $SSLPATH/$CERTNAME.pem;
        ssl_certificate_key $SSLPATH/$CERTNAME.key;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

        # Only use safe chiffers
	ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';

	ssl_prefer_server_ciphers on;
        server_name $URL;
        set $upstream  $APACHEHOSTIP:$NGINXPORT;

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

# Put the conf in new_ip_cloudflare.sh
sed -i "1s|^|bash $CFDIR/$HOSTNAME/cloudflare-new-ip.sh\n|" /etc/nginx/sites-available/scripts/new_ip_cloudflare.sh

# Enable host
ln -s /etc/nginx/sites-available/$DOMAIN.conf /etc/nginx/sites-enabled/$DOMAIN.conf
service nginx configtest
if [[ $? > 0 ]]
then
	echo "Host creation for $URL had failed."
        exit 1
else
	bash $CFDIR/$HOSTNAME/cloudflare-new-ip.sh
	echo
	echo "Host for $URL created and activated!"
	exit 0
fi
