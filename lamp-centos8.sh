#!/bin/sh
# Centos 8 Webserver Setup
# Variables MYSQLPASSWORD HOSTNAME SERVERADMINEMAIL FQDN

echo "Techie Networks LAMP Server Build v2.01"

if [ $# -ne 3 ]
then
  echo Usage: LAMP {hostname} {fqdn} {serveradminemail} 
  echo Example: LAMP TNDC3WS004 tndc3ws004.techienetworks.com support@techienetworks.com
  exit 1
fi

HOSTNAME=$1
FQDN=$2
SERVERADMINEMAIL=$3


#HOSTNAME='centos'
#FQDN='centos.jt.techie.gd'
#SERVERADMINEMAIL='support@techienetworks.com'

echo "Generating random password for mysql"
MYSQLPASSWORD=`tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1`

echo "Setting up base profile"
echo $'#\x21/bin/sh' > /etc/profile.d/x.sh
echo "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin" >> /etc/profile.d/x.sh
chmod 755 /etc/profile.d/x.sh

echo "Setting up build location"
cd
mkdir /root/build
cd /root/build

# Disable selinux
echo "Disabling SELINUX"
setenforce 0
echo "SELINUX=disabled" > /etc/sysconfig/selinux

echo "Turning off services"
# Turn off unneeded services
systemctl disable abrt-ccpp.service
systemctl disable abrt-oops.service
systemctl disable abrtd.service
systemctl disable atd.service
systemctl disable auditd.service
systemctl disable avahi-daemon.service
systemctl disable avahi-daemon.socket
systemctl disable fprintd.service
systemctl disable iprdump.service
systemctl disable iprinit.service
systemctl disable iprupdate.service
systemctl disable kdump.service
systemctl disable plymouth-start.service
systemctl disable polkit.service
systemctl disable wpa_supplicant.service

systemctl stop abrt-ccpp.service
systemctl stop abrt-oops.service
systemctl stop abrtd.service
systemctl stop atd.service
systemctl stop auditd.service
systemctl stop avahi-daemon.service
systemctl stop avahi-daemon.socket
systemctl stop fprintd.service
systemctl stop iprdump.service
systemctl stop iprinit.service
systemctl stop iprupdate.service
systemctl stop kdump.service
systemctl stop plymouth-start.service
systemctl stop polkit.service
systemctl stop wpa_supplicant.service

# Install EPEL
echo "Installing EPEL"
dnf install -y epel-release

echo "Installing REMI"
dnf install https://rpms.remirepo.net/enterprise/remi-release-8.rpm
dnf module enable php:remi-7.4

# Install prereqs
echo "Installing Packages"
dnf erase -y iwl100-firmware iwl105-firmware iwl135-firmware iwl2000-firmware iwl2030-firmware iwl3160-firmware iwl1000-firmware iwl3945-firmware iwl4965-firmware iwl5000-firmware iwl5150-firmware iwl6000-firmware iwl6000g2a-firmware iwl6000g2b-firmware  iwl6050-firmware iwl7260-firmware iwl7265-firmware
dnf group install "Development Tools" -y
dnf -y --enablerepo=PowerTools install glibc-static
dnf install -y postfix httpd dos2unix mariadb-server php-fpm gcc git wget net-tools mod_ssl psmisc fail2ban php-devel php-pear php-gd php-opcache php-mbstring php-mysqlnd php-json php-soap

# Required for chroot
echo "Installing php timezonedb"
pecl channel-update pecl.php.net > /dev/null
pecl install timezonedb > /dev/null
echo 'extension=timezonedb.so'> /etc/php.d/timezonedb.ini

# Mariadb Setup
# ~~~~~~~~~~~~~
echo "Setting up MySQL"

echo "[mysqld]" > /etc/my.cnf.d/skipnameresolve.cnf
echo "skip-name-resolve" >> /etc/my.cnf.d/skipnameresolve.cnf

echo "[mysqld]" > /etc/my.cnf.d/innodb.cnf
echo "innodb_file_per_table" >> /etc/my.cnf.d/innodb.cnf

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
cd
cd build
wget https://dl.eff.org/certbot-auto
mv certbot-auto /usr/bin/certbot-auto
chown root /usr/bin/certbot-auto
chmod 0755 /usr/bin/certbot-auto
certbot-auto register --agree-tos -m $SERVERADMINEMAIL -n
echo "0 0,12 * * * root python3 -c 'import random; import time; time.sleep(random.random() * 3600)' && /usr/bin/certbot-auto renew -q" | sudo tee -a /etc/crontab > /dev/null

# ld2chroot
# ~~~~~~~~~
wget https://raw.githubusercontent.com/jaysamthanki/lampserver/master/l2chroot.txt
mv -f l2chroot.txt /usr/bin/ld2chroot
dos2unix /usr/bin/ld2chroot
chmod 755 /usr/bin/ld2chroot

# Update Webs
# ~~~~~~~~~~~
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
replace 'getlogin()' '"apache"' -- mini_sendmail.c
make
cp mini_sendmail /usr/bin/mini_sendmail

# Setup Apache
# ~~~~~~~~~~~~
echo "Setting up apache"
mv /etc/httpd/conf.modules.d/01-cgi.conf /etc/httpd/conf.modules.d/01-cgi.conf.disabled
mv /etc/httpd/conf.modules.d/00-dav.conf /etc/httpd/conf.modules.d/00-dav.conf.disabled
mv /etc/httpd/conf.modules.d/00-lua.conf /etc/httpd/conf.modules.d/00-lua.conf.disabled
mv /etc/httpd/conf.modules.d/00-proxy.conf /etc/httpd/conf.modules.d/00-proxy.conf.disabled

echo "LoadModule proxy_module modules/mod_proxy.so" >> /etc/httpd/conf.modules.d/00-proxy-stripped.conf
echo "LoadModule proxy_fcgi_module modules/mod_proxy_fcgi.so" >> /etc/httpd/conf.modules.d/00-proxy-stripped.conf

# Base Strip
read -d '' output <<- EOF
LoadModule access_compat_module modules/mod_access_compat.so
LoadModule alias_module modules/mod_alias.so
LoadModule auth_basic_module modules/mod_auth_basic.so
LoadModule authn_file_module modules/mod_authn_file.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule authz_user_module modules/mod_authz_user.so
LoadModule deflate_module modules/mod_deflate.so
LoadModule dir_module modules/mod_dir.so
LoadModule expires_module modules/mod_expires.so
LoadModule filter_module modules/mod_filter.so
LoadModule headers_module modules/mod_headers.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule logio_module modules/mod_logio.so
LoadModule mime_module modules/mod_mime.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule setenvif_module modules/mod_setenvif.so
LoadModule socache_shmcb_module modules/mod_socache_shmcb.so
LoadModule status_module modules/mod_status.so
LoadModule unixd_module modules/mod_unixd.so

EOF

echo "$output" > /etc/httpd/conf.modules.d/00-base-strip.conf

touch /etc/sysconfig/httpd

mkdir /etc/httpd/conf.d/hosts

# turn on vhosting
echo "Include conf.d/hosts/*" >> /etc/httpd/conf.d/01-EnableVirtualHost.conf

# Server Name settings
echo "ServerName $HOSTNAME" > /etc/httpd/conf.d/03-ServerName.conf

# Server Admin settings
echo "ServerAdmin $SERVERADMINEMAIL" > /etc/httpd/conf.d/04-ServerAdmin.conf

# Turn on HTTP2
echo "Protocols h2 h2c http/1.1" > /etc/httpd/conf.d/07-http2.conf

# Turn on gzip
echo "AddOutputFilterByType DEFLATE text/plain" > /etc/httpd/conf.d/08-gzip.conf
echo "AddOutputFilterByType DEFLATE text/html" >> /etc/httpd/conf.d/08-gzip.conf
echo "AddOutputFilterByType DEFLATE text/xml" >> /etc/httpd/conf.d/08-gzip.conf
echo "AddOutputFilterByType DEFLATE text/css" >> /etc/httpd/conf.d/08-gzip.conf
echo "AddOutputFilterByType DEFLATE application/xml" >> /etc/httpd/conf.d/08-gzip.conf
echo "AddOutputFilterByType DEFLATE application/xhtml+xml" >> /etc/httpd/conf.d/08-gzip.conf
echo "AddOutputFilterByType DEFLATE application/rss+xml" >> /etc/httpd/conf.d/08-gzip.conf
echo "AddOutputFilterByType DEFLATE application/javascript" >> /etc/httpd/conf.d/08-gzip.conf
echo "AddOutputFilterByType DEFLATE application/x-javascript" >> /etc/httpd/conf.d/08-gzip.conf

# SSL
read -d '' output <<- EOF
Listen 443 https
SSLPassPhraseDialog builtin
SSLSessionCache         shmcb:/run/httpd/sslcache(512000)
SSLSessionCacheTimeout  300
SSLRandomSeed startup file:/dev/urandom  256
SSLRandomSeed connect builtin
SSLCryptoDevice builtin

# Harden
SSLCompression off
SSLHonorCipherOrder On
SSLCertificateFile /etc/pki/tls/certs/$FQDN.crt
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

EOF

echo "$output" > /etc/httpd/conf.d/05-SSL.conf

# Server Status Url
read -d '' output <<- EOF
<Location "/.server-status">
    SetHandler server-status
    Require ip 127.0.0.1
    # Uncomment and provide your secured network
    # Require ip 10.0.0.0/8
</Location>
EOF

echo "$output" > /etc/httpd/conf.d/06-ServerStatus.conf

mv /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/ssl.conf.disabled
touch /etc/httpd/conf.d/ssl.conf

mv /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/welcome.conf.disabled
touch /etc/httpd/conf.d/welcome.conf

mv /etc/httpd/conf.d/autoindex.conf /etc/httpd/conf.d/autoindex.conf.disabled
touch /etc/httpd/conf.d/autoindex.conf


# logrotate for httpd
read -d '' output <<- EOF
/var/log/httpd/*/*log {
    missingok
    notifempty
    daily
    sharedscripts
    compress
    delaycompress
    postrotate
        /bin/systemctl reload httpd.service > /dev/null 2>/dev/null || true
    endscript
}
EOF

echo "$output" > /etc/logrotate.d/httpd

# Make a dummy SSL
make-dummy-cert /etc/ssl/certs/$FQDN.crt

systemctl enable httpd.service

# User Skeleton
cd /opt
mkdir skel
mkdir skel/logs
mkdir skel/tmp

# Vhost template
read -d '' output <<- EOF
<VirtualHost *:80>
        ServerAdmin webmaster@DOMAIN
        ServerName USER.$FQDN
        DocumentRoot /var/www/USER/DOMAIN

        <Directory /var/www/USER/DOMAIN/>
                Options -Indexes +FollowSymLinks -MultiViews
                AllowOverride all
                Order allow,deny
                Allow from all
        </Directory>

        DirectoryIndex index.html index.php

        ServerSignature On
        ErrorLog logs/USER/error.log
        CustomLog logs/USER/access.log combined

        <Proxy "unix:/var/www/USER/tmp/php.sock|fcgi://USER">
                ProxySet disablereuse=off
        </Proxy>

        <FilesMatch \.php$>
                SetHandler proxy:fcgi://USER
        </FilesMatch>
</VirtualHost>

<VirtualHost *:80>
        ServerAdmin webmaster@DOMAIN
        ServerName DOMAIN
        ServerAlias www.DOMAIN
        DocumentRoot /var/www/USER/DOMAIN

        <Directory /var/www/USER/DOMAIN/>
                Options -Indexes +FollowSymLinks -MultiViews
                AllowOverride all
                Order allow,deny
                Allow from all
        </Directory>

        DirectoryIndex index.html index.php

        ServerSignature On
        ErrorLog logs/USER/error.log
        CustomLog logs/USER/access.log combined

        <Proxy "unix:/var/www/USER/tmp/php.sock|fcgi://USER">
                ProxySet disablereuse=off
        </Proxy>

        <FilesMatch \.php$>
                SetHandler proxy:fcgi://USER
        </FilesMatch>
</VirtualHost>

EOF

echo "$output" > /etc/httpd/conf.d/template

# PHP-FPM Template
read -d '' output <<- EOF
[USER]

listen = /var/www/USER/tmp/php.sock

user = USER
group = USER
listen.owner = USER
listen.group = USER
listen.mode = 0666

pm = ondemand
pm.max_children = 5
pm.status_path = /php-fpm/status
slowlog = /logs/phpslow.log
chroot = /var/www/USER
php_value[session.save_handler] = files
php_value[session.save_path] = /tmp
php_admin_value[doc_root] = /DOMAIN
php_admin_value[cgi.fix_pathinfo] = 0
php_admin_value[sendmail_path] = /bin/sendmail -fwebmaster@DOMAIN -s127.0.0.1 -t 
php_admin_value[error_log] = /logs/php.log
php_admin_flag[log_errors] = on
EOF

echo "$output" > /etc/php-fpm.d/phpfpm.template

# PHP-FPM Setup
mv /etc/php-fpm.d/www.conf /etc/php-fpm.d/www.conf.disabled
touch /etc/php-fpm.d/www.conf
systemctl enable php-fpm.service



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
logpath  = /var/www/*/logs/access.log
maxretry = 6

EOF

echo "$output" > /etc/fail2ban/jail.local

read -d '' output <<- EOF
[Definition]
failregex = ^<HOST> .*POST .*xmlrpc\.php.*
ignoreregex =

EOF

echo "$output" > /etc/fail2ban/filter.d/apache-xmlrpc.conf


systemctl enable fail2ban.service
firewall-cmd --permanent --zone=public --add-port=24/tcp
firewall-cmd --permanent --zone=public --add-port=80/tcp
firewall-cmd --permanent --zone=public --add-port=443/tcp
systemctl start fail2ban.service
systemctl restart firewalld.service
