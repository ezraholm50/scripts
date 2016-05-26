#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

REMOTE=root@example.com
MYSQLPASS=password
now=$(date)
WPATHMAIN=/var/www/html/techandme_se
WPATHSHOP=/var/www/html/shop_techandme
SOURCE=/var/www/html/
DESTINATION=$REMOTE:/var/www/techandme

# Check remote host
echo "Checking remote host: $REMOTE..."
ssh -q -o BatchMode=yes -o ConnectTimeout=10 $REMOTE exit
if [[ $? > 0 ]]
then
        echo "SSH Fail! $now" >> /var/log/backup_fsgo.log
	echo "$?"
        exit 1
else

# Export databases locally
echo "Exporting shop main database locally..."
cd $WPATHSHOP
wp db export mysql_backup.sql --allow-root
mv $WPATHSHOP/mysql_backup.sql /var/www/html/shop_mysql_backup.sql
chown root:root /var/www/html/shop_mysql_backup.sql

echo "Exporting main database locally..."
cd $WPATHMAIN
wp db export mysql_backup.sql --allow-root
mv $WPATHMAIN/mysql_backup.sql /var/www/html/main_mysql_backup.sql
chown root:root /var/www/html/main_mysql_backup.sql

# Sync the files to $REMOTE
echo "Syncing files..."
rsync -axz -e 'ssh' \
        --numeric-ids \
        --delete -r \
	--bwlimit=5000 \
        $SOURCE $DESTINATION

# Change wp-config.php on $REMOTE
echo "Chagning address in wp-config.php..."
ssh $REMOTE "sed -i 's|https://www.techandme.se|https://techandme.fsgo.se|g' /var/www/techandme/techandme_se/wp-config.php"
ssh $REMOTE "sed -i 's|https://shop.techandme.se|https://techandmeshop.fsgo.se|g' /var/www/techandme/shop_techandme/wp-config.php"

# Import database on $REMOTE
echo "Exporting main database remote..."
ssh $REMOTE "mysql -u root -p$MYSQLPASS -o techandme_se < /var/www/techandme/main_mysql_backup.sql"
echo "Exporting shop database remote..."
ssh $REMOTE "mysql -u root -p$MYSQLPASS -o techandme_shop < /var/www/techandme/shop_mysql_backup.sql"
fi
if [[ $? > 0 ]]
then
	nowafter=$(date)
	echo "Fail! $now - $nowafter" >> /var/log/backup_fsgo.log
	exit 1
else
	nowafter=$(date)
	echo "Success! $now  - $nowafter" >> /var/log/backup_fsgo.log
	exit 0
fi
