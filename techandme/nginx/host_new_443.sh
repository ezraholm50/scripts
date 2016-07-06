set -e

## SSL ##

DOMAIN="rutorrent"
HOSTNAME=$DOMAIN.techandme
URL=$HOSTNAME.se

# IP
APACHEHOSTIP="192.168.8.100"
NGINXHOSTIP="192.168.4.201"

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

        listen $NGINXHOSTIP:443 ssl;

        ssl on;
        ssl_certificate $SSLPATH/$CERTNAME.pem;
        ssl_certificate_key $SSLPATH/$CERTNAME.key;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

        # Only use safe chiffers
	ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
	ssl_prefer_server_ciphers on;

        server_name $URL;
        set $upstream $APACHEHOSTIP:80;

        location / {
                proxy_pass_header Authorization;
                proxy_pass https://$upstream;
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
  listen $NGINXHOSTIP:80;
  server_name $URL;
  return 301 https://$DOMAIN/$request_uri;
}
HTTPS_CREATE

echo "$HTTPS_CONF was successfully created"
fi

# cloudflare-new-ip.sh
if [ -f $CFDIR/$HOSTNAME/cloudflare-new-ip.sh ];
        then
        echo "CFNEWIP exists"
else
        touch "$CFDIR/$HOSTNAME/cloudflare-new-ip.sh"
        cat << CFNEWIP > "$CFDIR/$HOSTNAME/cloudflare-new-ip.sh"
( cat $CFDIR/$HOSTNAME/nginx-oc-before ; wget -O- https://www.cloudflare.com/ips-v4 | sed 's/.*/     	set_real_ip_from &;/' ; cat $CFDIR/$HOSTNAME/nginx-oc-after ) > $HTTPS_CONF
CFNEWIP


# ( cat /etc/nginx/sites-available/cloudflare_ip//nginx-oc-before ; wget -O- https://www.cloudflare.com/ips-v4 | sed 's/.*/     	set_real_ip_from &;/' ; cat /etc/nginx/sites-available/cloudflare_ip//nginx-oc-after ) > /etc/nginx/sites-available/rutorrent.conf


echo "$CFDIR/$HOSTNAME/cloudflare-new-ip.sh was successfully created"
fi

# Nginx before
if [ -f $CFDIR/$HOSTNAME/nginx-$DOMAIN-before ];
        then
        echo "nginx-oc-before exists"
else
        touch "$CFDIR/$HOSTNAME/nginx-$DOMAIN-before"
        cat << NGBEFORE > "$CFDIR/$HOSTNAME/nginx-$DOMAIN-before"
server {
        # Cloudflare IP som maskeras av mod_real_ip

	error_page 404 500 502 503 504 /$DOMAIN_error.html;
        location = /$DOMAIN_error.html {
                root /usr/share/nginx/html;
                internal;
        }
NGBEFORE

echo "$CFDIR/$HOSTNAME/nginx-$DOMAIN-before was successfully created"
fi

# Nginx after
if [ -f $CFDIR/$HOSTNAME/nginx-$DOMAIN-after ];
        then
        echo "nginx-oc-after exists"
else
        touch "$CFDIR/$HOSTNAME/nginx-$DOMAIN-after"
        cat << NGAFTER > "$CFDIR/$HOSTNAME/nginx-$DOMAIN-after"

	real_ip_header     X-Forwarded-For;
        real_ip_recursive  on;

        listen $NGINXHOSTIP:443 ssl;

        ssl on;
        ssl_certificate $SSLPATH/$CERTNAME.pem;
        ssl_certificate_key $SSLPATH/$CERTNAME.key;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

        # Only use safe chiffers
	ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';

	ssl_prefer_server_ciphers on;
        server_name $URL;
        set $upstream  $APACHEHOSTIP:443;

        location / {
                proxy_pass_header Authorization;
                proxy_pass https://$upstream;
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
  listen $NGINXHOSTIP:80;
  server_name $URL;
  return 301 https://$URL$request_uri;
}
NGAFTER
echo "$CFDIR/$HOSTNAME/nginx-$DOMAIN-after was successfully created"
fi

# Put the conf in new_ip_cloudflare.sh
sed -i '1s/^/"bash $CFDIR/$HOSTNAME/cloudflare-new-ip.sh"\n/' /etc/nginx/sites-enabled/new_ip_cloudflare.sh

# Enable host
ln -s /etc/nginx/sites-available/$DOMAIN.conf /etc/nginx/sites-enabled/$DOMAIN.conf
service nginx configtest
