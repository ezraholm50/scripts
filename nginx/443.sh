HTTPS_CONF="/etc/nginx/sites-available/443.conf"
APACHEHOSTIP="apacheip"
NGINXHOSTIP="nginxip"
SSLPATH="/etc/ssl"
DOMAIN="example.com"
CERTNAME="certificate"
# Nginx variables
upstream='$upstream'
host='$host'
remote_addr='$remote_addr'
proxy_add_x_forwarded_for='$proxy_add_x_forwarded_for'
request_uri='$request_uri'

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
        ssl_certificate $SSLPATH/$DOMAIN/$CERTNAME.pem;
        ssl_certificate_key $SSLPATH/$DOMAIN/$CERTNAME.key;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

        # Only use safe chiffers
	ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
	ssl_prefer_server_ciphers on;

        server_name $DOMAIN;
        set $upstream $APACHEHOSTIP:443;

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
  server_name $DOMAIN;
  return 301 https://$DOMAIN/$request_uri;
}

HTTPS_CREATE
echo "$HTTPS_CONF was successfully created"
sleep 3
fi

# Enable host
ln -s /etc/nginx/sites-available/443.conf /etc/nginx/sites-enabled/443.conf
