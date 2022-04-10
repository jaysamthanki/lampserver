#!/bin/bash
# Ubuntu 20 Webserver Setup
# ChangeLog
# 2022-04-10 Add ModSec
# Variables MYSQLPASSWORD HOSTNAME SERVERADMINEMAIL FQDN

echo "Techie Networks LAMP Server Build v3.1"

if [ $# -ne 3 ]
then
  echo Usage: LAMP {hostname} {fqdn} {serveradminemail} 
  echo Example: LAMP TNDC3WS004 tndc3ws004.techienetworks.com support@techienetworks.com
  exit 1
fi

HOSTNAME='tndc8ws003'
FQDN='tndc8ws003.techienetworks.com'
SERVERADMINEMAIL='support@techienetworks.com'

HOSTNAME=$1
FQDN=$2
SERVERADMINEMAIL=$3

echo "Generating random password for mysql"
MYSQLPASSWORD=`tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1`

echo "Setting up build location"
cd
mkdir /root/build
cd /root/build

# Install prereqs
echo "Installing Packages"
apt update
apt install -y net-tools postfix apache2 libapache2-mod-security2 dos2unix mariadb-server gcc fail2ban php7.4-fpm php7.4-mbstring php7.4-opcache php7.4-mbstring php7.4-mysql php7.4-intl php7.4-soap php7.4-xml php-pear php7.4-zip php7.4-gd php7.4-dev php7.4-curl php7.4-imagick python3-certbot-apache 

# setup postfix to use the hostname and install as internet site

# PHP Setup
a2enmod proxy_fcgi setenvif
a2enconf php7.4-fpm
a2enmod headers
a2enmod security2

echo "Installing php timezonedb"
pecl channel-update pecl.php.net > /dev/null
pecl install timezonedb > /dev/null
echo 'extension=timezonedb.so'> /etc/php/7.4/mods-available/timezonedb.ini
ln -s /etc/php/7.4/mods-available/timezonedb.ini /etc/php/7.4/fpm/conf.d/30-timezonedb.ini

# Mariadb Setup
# ~~~~~~~~~~~~~
echo "Setting up MySQL"

echo "[mysqld]" > /etc/mysql/conf.d/skipnameresolve.cnf
echo "skip-name-resolve" >> /etc/mysql/conf.d/skipnameresolve.cnf

echo "[mysqld]" > /etc/mysql/conf.d/innodb.cnf
echo "innodb_file_per_table" >> /etc/mysql/conf.d/innodb.cnf

systemctl enable mariadb.service
systemctl start mariadb.service
/usr/bin/mysqladmin -u root password $MYSQLPASSWORD
echo "[client]" > ~/.my.cnf
echo "password=$MYSQLPASSWORD" >> ~/.my.cnf
chmod 600 ~/.my.cnf
echo "DELETE FROM mysql.user WHERE User=''" | mysql
echo "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')" | mysql
echo "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'" | mysql
echo "FLUSH PRIVILEGES" | mysql


# Certbot
# ~~~~~~~
echo "Installing CertBot"
certbot register --agree-tos -m $SERVERADMINEMAIL -n
echo "0 0,12 * * * root python3 -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew -q" | sudo tee -a /etc/crontab > /dev/null

# ld2chroot
# ~~~~~~~~~
cd
cd build
wget https://raw.githubusercontent.com/jaysamthanki/lampserver/master/l2chroot.txt
mv -f l2chroot.txt /usr/bin/ld2chroot
dos2unix /usr/bin/ld2chroot
chmod 755 /usr/bin/ld2chroot

# Update Webs
# ~~~~~~~~~~~
cd
cd build
wget https://raw.githubusercontent.com/jaysamthanki/lampserver/master/updatewebs.txt
mv -f updatewebs.txt /usr/bin/updatewebs
dos2unix /usr/bin/updatewebs
chmod 755 /usr/bin/updatewebs

# Mini Sendmail
# ~~~~~~~~~~~~~
echo "Building minisendmail"

cd /root/build
wget http://www.acme.com/software/mini_sendmail/mini_sendmail-1.3.8.tar.gz
tar -xzvf mini_sendmail-1.3.8.tar.gz
cd mini_sendmail-1.3.8
replace 'getlogin()' '"www-data"' -- mini_sendmail.c
make
cp mini_sendmail /usr/bin/mini_sendmail


# Setup Apache
# ~~~~~~~~~~~~
echo "Setting up apache"
cd
cd build
wget https://raw.githubusercontent.com/jaysamthanki/lampserver/master/make-dummy-cert.sh
chmod 755 make-dummy-cert.sh
mv make-dummy-cert.sh /usr/sbin
dos2unix /usr/sbin/make-dummy-cert.sh

ln -s /var/log/apache2/ /etc/apache2/logs

# Mod Sec
mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

SecRuleEngine On
SecAuditLogParts ABCEFHJKZ

cd
cd build
wget https://github.com/coreruleset/coreruleset/archive/v3.3.0.tar.gz
tar xvf v3.3.0.tar.gz

make-dummy-cert.sh /etc/ssl/certs/$FQDN.crt

a2enmod expires
a2enmod headers
a2enmod rewrite
a2enmod socache_shmcb
a2enmod ssl

read -d '' output <<- EOF
<Directory /data/>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
</Directory>

ServerName $HOSTNAME
ServerAdmin $SERVERADMINEMAIL
Protocols h2 h2c http/1.1

AddOutputFilterByType DEFLATE text/plain
AddOutputFilterByType DEFLATE text/plain
AddOutputFilterByType DEFLATE text/html
AddOutputFilterByType DEFLATE text/xml
AddOutputFilterByType DEFLATE text/css
AddOutputFilterByType DEFLATE application/xml
AddOutputFilterByType DEFLATE application/xhtml+xml
AddOutputFilterByType DEFLATE application/rss+xml
AddOutputFilterByType DEFLATE application/javascript
AddOutputFilterByType DEFLATE application/x-javascript

#Listen 443 https
SSLPassPhraseDialog builtin
SSLSessionCache         shmcb:/run/httpd/sslcache(512000)
SSLSessionCacheTimeout  300
SSLRandomSeed startup file:/dev/urandom  256
SSLRandomSeed connect builtin
SSLCryptoDevice builtin

# Harden
SSLCompression off
SSLHonorCipherOrder On
SSLCertificateFile /etc/ssl/certs/$FQDN.crt
SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH:!3DES:!DES:!RC4
SSLVerifyClient none
SSLProxyEngine off
<IfModule mime.c>
        AddType application/x-x509-ca-cert      .crt
        AddType application/x-pkcs7-crl         .crl
</IfModule>

SetEnvIf User-Agent ".*MSIE.*" nokeepalive ssl-unclean-shutdown downgrade-1.0 force-response-1.0

SSLUseStapling on
SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
#SSLSessionTickets Off
#Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
#Header always set X-Frame-Options DENY
#Header always set X-Content-Type-Options nosniff

<Location "/.server-status">
    SetHandler server-status
    Require ip 127.0.0.1
    # Uncomment and provide your secured network
    # Require ip 10.0.0.0/8
</Location>
EOF

echo "$output" > /etc/apache2/conf-available/techie.conf

ln -s /etc/apache2/conf-available/techie.conf /etc/apache2/conf-enabled/techie.conf

service apache2 restart

# logrotate for httpd
read -d '' output <<- EOF
/var/log/apache2/*/*.log {
        daily
        missingok
        rotate 14
        compress
        delaycompress
        notifempty
        create 640 root adm
        sharedscripts
        postrotate
                if invoke-rc.d apache2 status > /dev/null 2>&1; then
                    invoke-rc.d apache2 reload > /dev/null 2>&1; 
                fi;
        endscript
        prerotate
                if [ -d /etc/logrotate.d/httpd-prerotate ]; then 
                        run-parts /etc/logrotate.d/httpd-prerotate; 
                fi; 
        endscript
}

EOF

echo "$output" > /etc/logrotate.d/apache2-sites

# User Skeleton
cd /opt
mkdir skel
mkdir skel/logs
mkdir skel/tmp

# PHP-FPM Setup
mv /etc/php/7.4/fpm/pool.d/www.conf /etc/php/7.4/fpm/pool.d/www.conf.disabled
touch /etc/php/7.4/fpm/pool.d/www.conf
systemctl enable php7.4-fpm.service



# create a shortcut script to create webs
# usage: createweb username domainname.tld
read -d '' output <<- EOF
#!/bin/sh
if [ \$# -ne 3 ]
then
  echo Usage: createweb {username} {websitedomainname} {password}
  echo Example: createweb somedomainuser somedomain.com password
  exit 1
fi
echo Creating User...
useradd -b /var/www -d /var/www/\$1 -m -k /opt/skel -s /bin/false \$1
chmod 755 /var/www/\$1
mkdir /var/www/\$1/\$2
echo Setting up Password...
echo "\$3" | passwd --stdin \$1
echo "\$3" > /var/www/\$1/password
chmod 600 /var/www/\$1/password
echo Setting Up Apache...
ln -s /var/www/\$1/logs /var/log/httpd/\$1
cp /etc/httpd/conf.d/template /etc/httpd/conf.d/hosts/\$2
replace DOMAIN \$2 -- /etc/httpd/conf.d/hosts/\$2
replace USER \$1 -- /etc/httpd/conf.d/hosts/\$2
echo Setting up PHP-FPM...
cp /etc/php-fpm.d/phpfpm.template /etc/php-fpm.d/\$2.conf
replace USER \$1 -- /etc/php-fpm.d/\$2.conf
replace DOMAIN \$2 -- /etc/php-fpm.d/\$2.conf
echo Setting up MySQL...
echo "CREATE DATABASE \$1;" | mysql
echo "GRANT ALL PRIVILEGES ON \$1.* to \$1@'%' identified by '\$3';" | mysql
echo Setting up chroot jail...
mkdir /var/www/\$1/dev
mkdir /var/www/\$1/bin
mkdir /var/www/\$1/etc
mkdir /var/www/\$1/lib64
mkdir -p /var/www/\$1/usr/lib64
mkdir -p /var/www/\$1/etc/pki/nssdb
mkdir -p /var/www/\$1/var/lib/php/session
mkdir -p /var/www/\$1/usr/share
mknod -m 444 /var/www/\$1/dev/random c 1 8
mknod -m 444 /var/www/\$1/dev/urandom c 1 9
cp /etc/hosts /var/www/\$1/etc/
cp /etc/resolv.conf /var/www/\$1/etc/
cp /etc/localtime /var/www/\$1/etc/
cp /etc/networks /var/www/\$1/etc/
cp /etc/protocols /var/www/\$1/etc/
cp /etc/services /var/www/\$1/etc/
cp /etc/nsswitch.conf /var/www/\$1/etc/
cp /etc/host.conf /var/www/\$1/etc/
cp /etc/pki/nssdb/* /var/www/\$1/etc/pki/nssdb/
cp /lib64/libnss* /var/www/\$1/lib64/
cp /usr/lib64/libnsspem.so /var/www/\$1/usr/lib64/
cp /usr/lib64/libsoftokn3.so /var/www/\$1/usr/lib64/
cp /usr/lib64/libsqlite3.so.0 /var/www/\$1/usr/lib64/
cp /usr/bin/mini_sendmail /var/www/\$1/bin/sendmail
cp /bin/sh /var/www/\$1/bin/sh
cp /lib64/libfreeblpriv3.so /var/www/\$1/lib64/
cp /lib64/libsoftokn3.so /var/www/\$1/lib64/
ln -s /usr/share/zoneinfo  /var/www/\$1/usr/share/zoneinfo
echo "127.0.0.1	\$2 www.\$2 \$1.$FQDN"	>> /var/www/\$1/etc/hosts
ld2chroot /var/www/\$1 /bin/sh
chown \$1.\$1 -R /var/www/\$1
chown root.root /var/www/\$1
echo Reloading Services...
service httpd reload
service php-fpm reload
EOF

echo "$output" > /usr/sbin/createweb
chmod 700 /usr/sbin/createweb

# chroot jail ssh
cd /etc/ssh

echo "Port 24" > sshd_config24
echo "Protocol 2" >> sshd_config24
echo "SyslogFacility AUTHPRIV" >> sshd_config24
echo "HostKey /etc/ssh/ssh_host_rsa_key" >> sshd_config24
echo "PermitRootLogin no" >> sshd_config24
echo "PasswordAuthentication yes" >> sshd_config24
echo "GSSAPIAuthentication yes" >> sshd_config24
echo "GSSAPICleanupCredentials yes" >> sshd_config24
echo "UsePAM yes" >> sshd_config24
echo "AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES" >> sshd_config24
echo "AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT" >> sshd_config24
echo "AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE" >> sshd_config24
echo "AcceptEnv XMODIFIERS" >> sshd_config24
echo "X11Forwarding yes" >> sshd_config24
echo "ChrootDirectory /var/www/%u" >> sshd_config24
echo "Subsystem       sftp    internal-sftp -u 0002" >> sshd_config24

# Startup on reboot
echo "/usr/sbin/sshd -f /etc/ssh/sshd_config24" >> /etc/rc.d/rc.local
chmod +x /etc/rc.d/rc.local


# Script to auto install Word Press
# ~~~~~
read -d '' output <<- EOF
#!/bin/sh
if [ \$# -ne 2 ]
then
  echo Usage: installwp {username} {domain}
  echo Example: installwp test test.com
  exit 1
fi

cd /var/www/\$1
wget https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz
rm -rf latest.tar.gz
mv /var/www/\$1/wordpress/* /var/www/\$1/\$2
rm -rf /var/www/\$1/wordpress


cp /var/www/\$1/\$2/wp-config-sample.php /var/www/\$1/\$2/wp-config.php
perl -pi -e "s/database_name_here/\$1/g" /var/www/\$1/\$2/wp-config.php
perl -pi -e "s/username_here/\$1/g" /var/www/\$1/\$2/wp-config.php
perl -pi -e "s/password_here/\`cat /var/www/\$1/password\`/g" /var/www/\$1/\$2/wp-config.php
perl -pi -e "s/localhost/127.0.0.1/g" /var/www/\$1/\$2/wp-config.php
perl -i -pe'
  BEGIN {
    @chars = ("a" .. "z", "A" .. "Z", 0 .. 9);
    push @chars, split //, "!@#%^&*()-_ []{}<>~\`+=,.;:/?|";
    sub salt { join "", map \$chars[ rand @chars ], 1 .. 64 }
  }
  s/put your unique phrase here/salt()/ge
' /var/www/\$1/\$2/wp-config.php

chown \$1.\$1 /var/www/\$1/\$2 -R
EOF

echo "$output" > /usr/sbin/installwp
chmod 700 /usr/sbin/installwp

# Setup Postfix to accept email from all ips
postconf -e inet_interfaces=all

createweb test test.com $MYSQLPASSWORD
systemctl start php-fpm.service
systemctl start httpd.service


# Fail2ban
read -d '' output <<- EOF
[sshd]
enabled = true

[apache-xmlrpc]
enabled  = true
port     = http,https
filter   = apache-xmlrpc
logpath  = /var/log/apache2/*/*-access.log
maxretry = 6

EOF

echo "$output" > /etc/fail2ban/jail.d/tnlamp.conf

read -d '' output <<- EOF
[Definition]
failregex = ^<HOST> .*POST .*xmlrpc\.php.*
ignoreregex =

EOF

echo "$output" > /etc/fail2ban/filter.d/apache-xmlrpc.conf

systemctl enable fail2ban.service
systemctl start fail2ban.service
systemctl restart firewalld.service


wget https://packages.microsoft.com/config/ubuntu/21.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt-get update;   sudo apt-get install -y apt-transport-https &&   sudo apt-get update &&   sudo apt-get install -y dotnet-sdk-5.0
apt-get install -y aspnetcore-runtime-5.0
dotnet dev-certs https

