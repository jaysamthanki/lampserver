#!/bin/bash
# Ubuntu 22 Webserver Setup
# ChangeLog
# 2022-05-31 Add Ubuntu 22 support
# 2022-04-10 Add ModSec
# Variables MYSQLPASSWORD HOSTNAME SERVERADMINEMAIL FQDN

echo "Techie Networks LAMP Server Build v3.2"

if [ $# -ne 3 ]
then
  echo Usage: LAMP {hostname} {fqdn} {serveradminemail} 
  echo Example: LAMP TNDC3WS004 tndc3ws004.techienetworks.com support@techienetworks.com
  exit 1
fi

HOSTNAME='ubuntu22'
FQDN='ubuntu22.techie.org'
SERVERADMINEMAIL='support@domain.tld'

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
apt install -y net-tools postfix apache2 libapache2-mod-security2 \
dos2unix mariadb-server \
gcc fail2ban php8.1-fpm php8.1-mbstring \
php8.1-opcache php8.1-mbstring php8.1-mysql \
php8.1-intl php8.1-soap php8.1-xml php-pear php8.1-zip php8.1-gd php8.1-dev php8.1-curl \
python3-certbot-apache dotnet-sdk-6.0 aspnetcore-runtime-6.0

# setup postfix to use the hostname and install as internet site

# PHP Setup
echo "Installing php timezonedb"
pecl channel-update pecl.php.net > /dev/null
pecl install timezonedb 
echo 'extension=timezonedb.so'> /etc/php/8.1/mods-available/timezonedb.ini
ln -s /etc/php/8.1/mods-available/timezonedb.ini /etc/php/8.1/fpm/conf.d/30-timezonedb.ini

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
#mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
#apt -y remove modsecurity-crs

#read -d '' output <<- EOF
#SecRuleEngine On
#SecAuditLogParts ABCEFHJKZ
#IncludeOptional /etc/apache2/modsecurity-crs/crs-setup.conf
#IncludeOptional /etc/apache2/modsecurity-crs/rules/*.conf
#EOF

#echo "$output" > /etc/modsecurity/techie.conf

#mkdir /etc/apache2/modsecurity-crs/
#git clone https://github.com/coreruleset/coreruleset /etc/apache2/modsecurity-crs
#mv /etc/apache2/modsecurity-crs/crs-setup.conf.example /etc/apache2/modsecurity-crs/crs-setup.conf

#cd
#cd build
#wget https://github.com/coreruleset/coreruleset/archive/v3.3.0.tar.gz
#tar xvf v3.3.0.tar.gz

make-dummy-cert.sh /etc/ssl/certs/$FQDN.crt

a2enmod expires
a2enmod headers
a2enmod rewrite
a2enmod socache_shmcb
a2enmod ssl
a2enmod proxy_fcgi setenvif
a2enconf php8.1-fpm
a2enmod headers
a2enmod cache
#a2enmod security2

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
mv /etc/php/8.1/fpm/pool.d/www.conf /etc/php/8.1/fpm/pool.d/www.conf.disabled
touch /etc/php/8.1/fpm/pool.d/www.conf
systemctl enable php8.1-fpm.service

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
echo "/usr/sbin/sshd -f /etc/ssh/sshd_config24" >> /etc/rc.local
chmod +x /etc/rc.local

# Setup Postfix to accept email from all ips
postconf -e inet_interfaces=all

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

### .net Core 6
echo "Installing Dot Net Core 6"
dotnet dev-certs https --trust
