HTTP_CONF="/etc/nginx/sites-available/80.conf"
APACHEHOSTIP="apacheip"
NGINXHOSTIP="nginxip"
DOMAIN="example.com"
# Nginx variables
upstream='$upstream'
host='$host'
remote_addr='$remote_addr'
proxy_add_x_forwarded_for='$proxy_add_x_forwarded_for'
request_uri='$request_uri'

# Generate $HTTP_CONF
if [ -f $HTTP_CONF ];
        then
        echo "Virtual Host exists"
else
        touch "$HTTP_CONF"
        cat << HTTP_CREATE > "$HTTP_CONF"
server {

	real_ip_header     X-Forwarded-For;
        real_ip_recursive  on;

        listen $NGINXHOSTIP:80;

        server_name $DOMAIN;
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
  listen $NGINXHOSTIP:443;
  server_name $DOMAIN;
  return 301 https://$DOMAIN/$request_uri;
}

HTTP_CREATE
echo "$HTTP_CONF was successfully created"
sleep 3
fi

# Enable host
ln -s /etc/nginx/sites-available/80.conf /etc/nginx/sites-enabled/80.conf
