# LAMP Server

## LAMP Server optimized for security and performance.

This script was created to spin up a new LAMP server on the Techie Network cloud. This script auotmatically installs
- Apache
- MySQL Latest
- PHP 8.1
- Certbot

It will then continue to configure Apache, PHP-FPM in chroot Jails.

## Requirements
This script is designed to be run on Ubuntu 22, minimal install. All required packages will be automatically installed.

## How to use

wget lamp-ubuntu22.sh

chmod 755 lamp-ubuntu22.sh

./lamp-ubuntu22.sh.sh <servername> <server.fqdn> <webmaster email>
  
Once the install is complete, to add a website use the script

createweb username domain.tld passwordforthesite

To install wordpress in the above site,

installwp username domain.tld


