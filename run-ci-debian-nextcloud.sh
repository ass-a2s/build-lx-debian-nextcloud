#!/bin/bash

### LICENSE - (BSD 2-Clause) // ###
#
# Copyright (c) 2018, Daniel Plominski (ASS-Einrichtungssysteme GmbH)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice, this
# list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
### // LICENSE - (BSD 2-Clause) ###

### ### ### ASS // ### ### ###

#// get container ip address
GET_INTERFACE=$(netstat -rn | grep "0.0.0.0 " | grep "UG" | tr ' ' '\n' | tail -n 1)
GET_IPv4=$(ip addr show dev "$GET_INTERFACE" | grep "inet" | head -n 1 | awk '{print $2}')
GET_IPv6=$(ip addr show dev "$GET_INTERFACE" | grep "inet6" | head -n 1 | awk '{print $2}')

#// check sudo
CHECK_SUDO=$(which sudo | grep -c "sudo")
if [ "$CHECK_SUDO" = "1" ]
then
   : # dummy
else
   echo "[ERROR] require sudo!"
   exit 1
fi

#// generate random mariadb password
if [ -e /mariadb_password ]
then
   : # dummy
else
   sudo touch /mariadb_password
fi
if [ ! -s /mariadb_password ]
then
   GEN_PASSWORD=$(date +%s | sha256sum | base64 | head -c 8; echo)
   sudo echo "$GEN_PASSWORD" > mariadb_password
   sudo cp -fv mariadb_password /mariadb_password
fi
MARIADB_PASSWORD=$(cat /mariadb_password)

#// Debian Version
GET_DEBIAN_VERSION=$(grep "VERSION_ID=" /etc/os-release | sed 's/VERSION_ID=//g' | sed 's/"//g')

#// no MariaDB-Server Support on Debian 9 SmartOS LX Zone
LXZONE_MARIADB=$(uname -a | egrep -c "BrandZ virtual linux")
if [ "$LXZONE_MARIADB" = "1" ]
then
   if [ "$GET_DEBIAN_VERSION" = "9" ]
   then
      STAGE="SKIPMARIADB"
      echo "[$(printf "\033[1;33mWARNING\033[0m\n")] no mariadb-server support on debian 9 smartos lx zones"
   fi
fi

#// FUNCTION: spinner (Version 1.0)
spinner() {
   local pid=$1
   local delay=0.01
   local spinstr='|/-\'
   while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
         local temp=${spinstr#?}
         printf " [%c]  " "$spinstr"
         local spinstr=$temp${spinstr%"$temp"}
         sleep $delay
         printf "\b\b\b\b\b\b"
   done
   printf "    \b\b\b\b"
}

#// FUNCTION: run script as root (Version 1.0)
check_root_user() {
if [ "$(id -u)" != "0" ]; then
   echo "[ERROR] This script must be run as root" 1>&2
   exit 1
fi
}

#// FUNCTION: check state (Version 1.0)
check_hard() {
if [ $? -eq 0 ]
then
   echo "[$(printf "\033[1;32m  OK  \033[0m\n")] '"$@"'"
else
   echo "[$(printf "\033[1;31mFAILED\033[0m\n")] '"$@"'"
   sleep 1
   exit 1
fi
}

#// FUNCTION: check state without exit (Version 1.0)
check_soft() {
if [ $? -eq 0 ]
then
   echo "[$(printf "\033[1;32m  OK  \033[0m\n")] '"$@"'"
else
   echo "[$(printf "\033[1;33mWARNING\033[0m\n")] '"$@"'"
   sleep 1
fi
}

#// FUNCTION: check state hidden (Version 1.0)
check_hidden_hard() {
if [ $? -eq 0 ]
then
   return 0
else
   #/return 1
   checkhard "$@"
   return 1
fi
}

#// FUNCTION: check state hidden without exit (Version 1.0)
check_hidden_soft() {
if [ $? -eq 0 ]
then
   return 0
else
   #/return 1
   checksoft "$@"
   return 1
fi
}

#// FUNCTION: set new hosts config (ignore ::1 localhost ip6 lx-zone bind for documentserver)
set_lx_hosts_config() {
LXZONE=$(uname -a | egrep -c "BrandZ virtual linux")
if [ "$LXZONE" = "1" ]
then
cat << "HOSTS" > lx_hosts

127.0.0.1   localhost
::1         ip6-localhost ip6-loopback
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters

# EOF
HOSTS
   sudo cp -fv lx_hosts /etc/hosts
fi
}

#// FUNCTION: package install
install_package() {
   sudo apt-get autoclean
   sudo apt-get clean
   sudo apt-get update
   sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confold" install --yes --force-yes "$@"
}

#// FUNCTION: silent package install for mariadb
install_package_mariadb() {
   sudo apt-get autoclean
   sudo apt-get clean
   sudo apt-get update
   export DEBIAN_FRONTEND=noninteractive
   #// Debian8
   if [ "$GET_DEBIAN_VERSION" = "8" ]
   then
      sudo debconf-set-selections <<< "mariadb-server-10.0 mysql-server/root_password password ASS"
      sudo debconf-set-selections <<< "mariadb-server-10.0 mysql-server/root_password_again password ASS"
   fi
   #// Debian9
   if [ "$GET_DEBIAN_VERSION" = "9" ]
   then
      sudo debconf-set-selections <<< "mariadb-server-10.1 mysql-server/root_password password ASS"
      sudo debconf-set-selections <<< "mariadb-server-10.1 mysql-server/root_password_again password ASS"
   fi
   #// no Support on Debian 9 SmartOS LX Zone
   if [ "$STAGE" = "SKIPMARIADB" ]
   then
      : # dummy / ignore Debian 9 SmartOS LX Zones and continues
   else
      #/sudo apt-get install -qq "$@"
      sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confold" install --yes --force-yes "$@"
   fi
}

#// FUNCTION: set new mariadb root password
set_mariadb_root_password() {
   mysql -uroot -p"ASS" -e "SET PASSWORD = PASSWORD('$MARIADB_PASSWORD');"
}

#// FUNCTION: hardening mariadb
set_secure_mariadb() {
   # mysql_secure_installation
   #// remove anonymous users
   mysql -uroot -p"$MARIADB_PASSWORD" -e "DELETE FROM mysql.user WHERE User='';"
   #// remove remote root
   mysql -uroot -p"$MARIADB_PASSWORD" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
   #// remove test database
   mysql -uroot -p"$MARIADB_PASSWORD" -e "DROP DATABASE IF EXISTS test;"
   mysql -uroot -p"$MARIADB_PASSWORD" -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
   #// reload privilege tables
   mysql -uroot -p"$MARIADB_PASSWORD" -e "FLUSH PRIVILEGES;"
}

#// FUNCTION: removing php5 packages
remove_php5() {
   uninstall="$(dpkg --list | grep php5 | awk '/^ii/{ print $2}')"
   sudo apt-get --purge remove $uninstall
}

#// FUNCTION: install php7 packages
prepare_php7_repository() {
   #// Debian8
   if [ "$GET_DEBIAN_VERSION" = "8" ]
   then
      sudo echo "deb http://packages.dotdeb.org jessie all" > dotdeb_php7.list
      sudo echo "deb-src http://packages.dotdeb.org jessie all" >> dotdeb_php7.list
      sudo cp -fv dotdeb_php7.list /etc/apt/sources.list.d/dotdeb_php7.list
      sudo wget https://www.dotdeb.org/dotdeb.gpg -O /tmp/dotdeb.gpg
      sudo apt-key add /tmp/dotdeb.gpg
      sudo apt-get update
      #/sudo apt-get install -qq "$@"
      sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confold" install --yes --force-yes "$@"
   fi
}

#// FUNCTION: install nextcloud
install_nextcloud() {
   if [ -e /var/www/ass_latest.zip ]
   then
      echo "skip: install nextcloud"
   else
      sudo wget https://download.nextcloud.com/server/releases/latest.zip -O /var/www/ass_latest.zip
      sudo unzip /var/www/ass_latest.zip -d /var/www/ass_nextcloud
      sudo mv /var/www/html /var/www/html_ORI
      sudo mv /var/www/ass_nextcloud/nextcloud /var/www/html
      sudo chown -R www-data:www-data /var/www/html
   fi
}

#// FUNCTION: prepare public mariadb-server nextcloud user
prepare_public_mariadb_user() {
   #// create mariadb nextcloud database
   mysql -uroot -p"$MARIADB_PASSWORD" -e "create database nextcloud;"
   #// create mariadb user
   mysql -uroot -p"$MARIADB_PASSWORD" -e "create user nextcloud@'%' identified by '$MARIADB_PASSWORD';"
   #// set mariadb privileges for the nextcloud user
   mysql -uroot -p"$MARIADB_PASSWORD" -e "grant all privileges on nextcloud.* to nextcloud@'%' identified by '$MARIADB_PASSWORD';"
   #// reload privilege tables
   mysql -uroot -p"$MARIADB_PASSWORD" -e "FLUSH PRIVILEGES;"
}

#// FUNCTION: prepare mariadb-server nextcloud user
prepare_mariadb_user() {
   #// create mariadb nextcloud database
   mysql -uroot -p"$MARIADB_PASSWORD" -e "create database nextcloud;"
   #// create mariadb user
   mysql -uroot -p"$MARIADB_PASSWORD" -e "create user nextcloud@localhost identified by '$MARIADB_PASSWORD';"
   #// set mariadb privileges for the nextcloud user
   mysql -uroot -p"$MARIADB_PASSWORD" -e "grant all privileges on nextcloud.* to nextcloud@localhost identified by '$MARIADB_PASSWORD';"
   #// reload privilege tables
   mysql -uroot -p"$MARIADB_PASSWORD" -e "FLUSH PRIVILEGES;"
}

#// FUNCTION: set new public mariadb-server config
set_public_mariadb_config() {
cat << "PUBLICMARIADBCONFIG" > public_mariadb_my.cnf
### ### ### ASS // ### ### ###

[client]
port            = 3306
socket          = /var/run/mysqld/mysqld.sock

[mysqld_safe]
socket          = /var/run/mysqld/mysqld.sock
nice            = 0

[mysqld]
user            = mysql
pid-file        = /var/run/mysqld/mysqld.pid
socket          = /var/run/mysqld/mysqld.sock
port            = 3306
basedir         = /usr
datadir         = /var/lib/mysql
tmpdir          = /tmp
lc-messages-dir = /usr/share/mysql
skip-external-locking
bind-address            = 0.0.0.0

key_buffer              = 16M
max_allowed_packet      = 16M
thread_stack            = 192K
thread_cache_size       = 8
myisam-recover          = BACKUP
query_cache_limit       = 1M
query_cache_size        = 16M

log_error = /var/log/mysql/error.log

expire_logs_days        = 10
max_binlog_size         = 100M

[mysqldump]
quick
quote-names
max_allowed_packet      = 16M

[mysql]
#no-auto-rehash # faster start of mysql but no tab completition

[isamchk]
key_buffer              = 16M

#
# * IMPORTANT: Additional settings that can override those from this file!
#   The files must end with '.cnf', otherwise they'll be ignored.
#
!includedir /etc/mysql/conf.d/

log-bin = /var/log/mysql/mariadb-bin
log-bin-index = /var/log/mysql/mariadb-bin.index
binlog_format = mixed

### ### ### // ASS ### ### ###
# EOF
PUBLICMARIADBCONFIG
   sudo cp -fv public_mariadb_my.cnf /etc/mysql/my.cnf
   sudo systemctl restart mysqld.service
   sudo systemctl status --no-pager mysqld.service
   sleep 1
}

#// FUNCTION: set new mariadb config
set_mariadb_config() {
cat << "MARIADBCONFIG" > mariadb_my.cnf
### ### ### ASS // ### ### ###

[client]
port            = 3306
socket          = /var/run/mysqld/mysqld.sock

[mysqld_safe]
socket          = /var/run/mysqld/mysqld.sock
nice            = 0

[mysqld]
user            = mysql
pid-file        = /var/run/mysqld/mysqld.pid
socket          = /var/run/mysqld/mysqld.sock
port            = 3306
basedir         = /usr
datadir         = /var/lib/mysql
tmpdir          = /tmp
lc-messages-dir = /usr/share/mysql
skip-external-locking
bind-address            = 127.0.0.1

key_buffer              = 16M
max_allowed_packet      = 16M
thread_stack            = 192K
thread_cache_size       = 8
myisam-recover          = BACKUP
query_cache_limit       = 1M
query_cache_size        = 16M

log_error = /var/log/mysql/error.log

expire_logs_days        = 10
max_binlog_size         = 100M

[mysqldump]
quick
quote-names
max_allowed_packet      = 16M

[mysql]
#no-auto-rehash # faster start of mysql but no tab completition

[isamchk]
key_buffer              = 16M

#
# * IMPORTANT: Additional settings that can override those from this file!
#   The files must end with '.cnf', otherwise they'll be ignored.
#
!includedir /etc/mysql/conf.d/

log-bin = /var/log/mysql/mariadb-bin
log-bin-index = /var/log/mysql/mariadb-bin.index
binlog_format = mixed

### ### ### // ASS ### ### ###
# EOF
MARIADBCONFIG
   sudo cp -fv mariadb_my.cnf /etc/mysql/my.cnf
   sudo systemctl restart mysqld.service
   sudo systemctl status --no-pager mysqld.service
   sleep 1
}

#// FUNCTION: set new nginx config
set_nginx_config() {
cat << "NGINXCONFIG" > nginx_default
### ### ### ASS // ### ### ###

upstream php-handler {
server unix:/run/php/php7.0-fpm.sock;
}

server {
    listen 80;
    server_name cloud.example.com;
    # enforce https
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name cloud.example.com;

    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    # Add headers to serve security related headers
    # Before enabling Strict-Transport-Security headers please read into this
    # topic first.
    # add_header Strict-Transport-Security "max-age=15768000;
    # includeSubDomains; preload;";
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Robots-Tag none;
    add_header X-Download-Options noopen;
    add_header X-Permitted-Cross-Domain-Policies none;

    # Path to the root of your installation
    root /var/www/html/;

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    # The following 2 rules are only needed for the user_webfinger app.
    # Uncomment it if you're planning to use this app.
    #rewrite ^/.well-known/host-meta /public.php?service=host-meta last;
    #rewrite ^/.well-known/host-meta.json /public.php?service=host-meta-json
    # last;

    location = /.well-known/carddav {
      return 301 $scheme://$host/remote.php/dav;
    }
    location = /.well-known/caldav {
      return 301 $scheme://$host/remote.php/dav;
    }

    # set max upload size
    client_max_body_size 512M;
    fastcgi_buffers 64 4K;

    # Disable gzip to avoid the removal of the ETag header
    gzip off;

    # Uncomment if your server is build with the ngx_pagespeed module
    # This module is currently not supported.
    #pagespeed off;

    error_page 403 /core/templates/403.php;
    error_page 404 /core/templates/404.php;

    location / {
        rewrite ^ /index.php$uri;
    }

    location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)/ {
        deny all;
    }
    location ~ ^/(?:\.|autotest|occ|issue|indie|db_|console) {
        deny all;
    }

    location ~ ^/(?:index|remote|public|cron|core/ajax/update|status|ocs/v[12]|updater/.+|ocs-provider/.+|core/templates/40[34])\.php(?:$|/) {
        include fastcgi_params;
        fastcgi_split_path_info ^(.+\.php)(/.*)$;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_param HTTPS on;
        #Avoid sending the security headers twice
        fastcgi_param modHeadersAvailable true;
        fastcgi_param front_controller_active true;
        fastcgi_pass php-handler;
        fastcgi_intercept_errors on;
        #fastcgi_request_buffering off;
    }

    location ~ ^/(?:updater|ocs-provider)(?:$|/) {
        try_files $uri/ =404;
        index index.php;
    }

    # Adding the cache control header for js and css files
    # Make sure it is BELOW the PHP block
    location ~* \.(?:css|js|woff|svg|gif)$ {
        try_files $uri /index.php$uri$is_args$args;
        add_header Cache-Control "public, max-age=7200";
        # Add headers to serve security related headers (It is intended to
        # have those duplicated to the ones above)
        # Before enabling Strict-Transport-Security headers please read into
        # this topic first.
        # add_header Strict-Transport-Security "max-age=15768000;
        #  includeSubDomains; preload;";
        add_header X-Content-Type-Options nosniff;
        add_header X-Frame-Options "SAMEORIGIN";
        add_header X-XSS-Protection "1; mode=block";
        add_header X-Robots-Tag none;
        add_header X-Download-Options noopen;
        add_header X-Permitted-Cross-Domain-Policies none;
        # Optional: Don't log access to assets
        access_log off;
    }

    location ~* \.(?:png|html|ttf|ico|jpg|jpeg)$ {
        try_files $uri /index.php$uri$is_args$args;
        # Optional: Don't log access to other assets
        access_log off;
    }
}

### ### ### // ASS ### ### ###
# EOF
NGINXCONFIG
   sudo cp -fv nginx_default /etc/nginx/sites-available/default
   sudo systemctl restart nginx.service
   sudo systemctl status --no-pager nginx.service
   sleep 1
}

#// FUNCTION: set new php 7.x config
set_nginx_php_config() {
cat << "NGINXPHPCLICONFIG" > nginx_php_cli_default
[PHP]
; ### ### ### ASS // ### ### ###

engine = On
short_open_tag = Off
precision = 14
output_buffering = 4096
zlib.output_compression = Off
implicit_flush = Off
unserialize_callback_func =
serialize_precision = 17
disable_functions =
disable_classes =
zend.enable_gc = On
expose_php = On
max_execution_time = 30
max_input_time = 60
memory_limit = -1
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
display_errors = Off
display_startup_errors = Off
log_errors = On
log_errors_max_len = 1024
ignore_repeated_errors = Off
ignore_repeated_source = Off
report_memleaks = On
track_errors = Off
html_errors = On
variables_order = "GPCS"
request_order = "GP"
register_argc_argv = Off
auto_globals_jit = On
post_max_size = 8M
auto_prepend_file =
auto_append_file =
default_mimetype = "text/html"
default_charset = "UTF-8"
doc_root =
user_dir =
enable_dl = Off
file_uploads = On
upload_max_filesize = 2M
max_file_uploads = 20
allow_url_fopen = On
allow_url_include = Off
default_socket_timeout = 60

[CLI Server]
cli_server.color = On

[Date]

[filter]

[iconv]

[intl]

[sqlite3]

[Pcre]

[Pdo]

[Pdo_mysql]
pdo_mysql.cache_size = 2000
pdo_mysql.default_socket=

[Phar]

[mail function]
SMTP = localhost
smtp_port = 25
mail.add_x_header = On

[SQL]
sql.safe_mode = Off

[ODBC]
odbc.allow_persistent = On
odbc.check_persistent = On
odbc.max_persistent = -1
odbc.max_links = -1
odbc.defaultlrl = 4096
odbc.defaultbinmode = 1

[Interbase]
ibase.allow_persistent = 1
ibase.max_persistent = -1
ibase.max_links = -1
ibase.timestampformat = "%Y-%m-%d %H:%M:%S"
ibase.dateformat = "%Y-%m-%d"
ibase.timeformat = "%H:%M:%S"

[MySQLi]
mysqli.max_persistent = -1
mysqli.allow_persistent = On
mysqli.max_links = -1
mysqli.cache_size = 2000
mysqli.default_port = 3306
mysqli.default_socket =
mysqli.default_host =
mysqli.default_user =
mysqli.default_pw =
mysqli.reconnect = Off

[mysqlnd]
mysqlnd.collect_statistics = On
mysqlnd.collect_memory_statistics = Off

[OCI8]

[PostgreSQL]
pgsql.allow_persistent = On
pgsql.auto_reset_persistent = Off
pgsql.max_persistent = -1
pgsql.max_links = -1
pgsql.ignore_notice = 0
pgsql.log_notice = 0

[bcmath]
bcmath.scale = 0

[browscap]

[Session]
session.save_handler = files
session.use_strict_mode = 0
session.use_cookies = 1
session.use_only_cookies = 1
session.name = PHPSESSID
session.auto_start = 0
session.cookie_lifetime = 0
session.cookie_path = /
session.cookie_domain =
session.cookie_httponly =
session.serialize_handler = php
session.gc_probability = 0
session.gc_divisor = 1000
session.gc_maxlifetime = 1440
session.referer_check =
session.cache_limiter = nocache
session.cache_expire = 180
session.use_trans_sid = 0
session.hash_function = 0
session.hash_bits_per_character = 5
url_rewriter.tags = "a=href,area=href,frame=src,input=src,form=fakeentry"

[Assertion]
zend.assertions = -1

[COM]

[mbstring]

[gd]

[exif]

[Tidy]
tidy.clean_output = Off

[soap]
soap.wsdl_cache_enabled=1
soap.wsdl_cache_dir="/tmp"
soap.wsdl_cache_ttl=86400
soap.wsdl_cache_limit = 5

[sysvshm]

[ldap]
ldap.max_links = -1

[mcrypt]

[dba]

[opcache]
opcache.enable=1
opcache.enable_cli=1
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=10000
opcache.memory_consumption=128
opcache.save_comments=1
opcache.revalidate_freq=1

[curl]

[openssl]

; ### ### ### // ASS ### ### ###
; # EOF
NGINXPHPCLICONFIG
   sudo cp -fv nginx_php_cli_default /etc/php/7.0/cli/php.ini
cat << "NGINXPHPFPMCONFIG" > nginx_php_fpm_default
[PHP]
; ### ### ### ASS // ### ### ###

engine = On
short_open_tag = Off
precision = 14
output_buffering = 4096
zlib.output_compression = Off
implicit_flush = Off
unserialize_callback_func =
serialize_precision = 17
disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatu     s,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedw     ait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,
disable_classes =
zend.enable_gc = On
expose_php = Off
max_execution_time = 30
max_input_time = 60
memory_limit = 4096M
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
display_errors = Off
display_startup_errors = Off
log_errors = On
log_errors_max_len = 1024
ignore_repeated_errors = Off
ignore_repeated_source = Off
report_memleaks = On
track_errors = Off
html_errors = On
variables_order = "GPCS"
request_order = "GP"
register_argc_argv = Off
auto_globals_jit = On
post_max_size = 8M
auto_prepend_file =
auto_append_file =
default_mimetype = "text/html"
default_charset = "UTF-8"
doc_root =
user_dir =
enable_dl = Off
file_uploads = On
upload_max_filesize = 2M
max_file_uploads = 20
allow_url_fopen = On
allow_url_include = Off
default_socket_timeout = 60

[CLI Server]
cli_server.color = On

[Date]

[filter]

[iconv]

[intl]

[sqlite3]

[Pcre]

[Pdo]

[Pdo_mysql]
pdo_mysql.cache_size = 2000
pdo_mysql.default_socket=

[Phar]

[mail function]
SMTP = localhost
smtp_port = 25
mail.add_x_header = On

[SQL]
sql.safe_mode = Off

[ODBC]
odbc.allow_persistent = On
odbc.check_persistent = On
odbc.max_persistent = -1
odbc.max_links = -1
odbc.defaultlrl = 4096
odbc.defaultbinmode = 1

[Interbase]
ibase.allow_persistent = 1
ibase.max_persistent = -1
ibase.max_links = -1
ibase.timestampformat = "%Y-%m-%d %H:%M:%S"
ibase.dateformat = "%Y-%m-%d"
ibase.timeformat = "%H:%M:%S"

[MySQLi]
mysqli.max_persistent = -1
mysqli.allow_persistent = On
mysqli.max_links = -1
mysqli.cache_size = 2000
mysqli.default_port = 3306
mysqli.default_socket =
mysqli.default_host =
mysqli.default_user =
mysqli.default_pw =
mysqli.reconnect = Off

[mysqlnd]
mysqlnd.collect_statistics = On
mysqlnd.collect_memory_statistics = Off

[OCI8]

[PostgreSQL]
pgsql.allow_persistent = On
pgsql.auto_reset_persistent = Off
pgsql.max_persistent = -1
pgsql.max_links = -1
pgsql.ignore_notice = 0
pgsql.log_notice = 0

[bcmath]
bcmath.scale = 0

[browscap]

[Session]
session.save_handler = files
session.use_strict_mode = 0
session.use_cookies = 1
session.use_only_cookies = 1
session.name = PHPSESSID
session.auto_start = 0
session.cookie_lifetime = 0
session.cookie_path = /
session.cookie_domain =
session.cookie_httponly =
session.serialize_handler = php
session.gc_probability = 0
session.gc_divisor = 1000
session.gc_maxlifetime = 1440
session.referer_check =
session.cache_limiter = nocache
session.cache_expire = 180
session.use_trans_sid = 0
session.hash_function = 0
session.hash_bits_per_character = 5
url_rewriter.tags = "a=href,area=href,frame=src,input=src,form=fakeentry"

[Assertion]
zend.assertions = -1

[COM]

[mbstring]

[gd]

[exif]

[Tidy]
tidy.clean_output = Off

[soap]
soap.wsdl_cache_enabled=1
soap.wsdl_cache_dir="/tmp"
soap.wsdl_cache_ttl=86400
soap.wsdl_cache_limit = 5

[sysvshm]

[ldap]
ldap.max_links = -1

[mcrypt]

[dba]

[opcache]
opcache.enable=1
opcache.enable_cli=1
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=10000
opcache.memory_consumption=512
opcache.save_comments=1
opcache.revalidate_freq=1

[curl]

[openssl]

; ### ### ### // ASS ### ### ###
; # EOF
NGINXPHPFPMCONFIG
   sudo cp -fv nginx_php_fpm_default /etc/php/7.0/fpm/php.ini
cat << "NGINXPHPFPMWWWCONFIG" > nginx_php_fpm_www_default
; ### ### ### ASS // ### ### ###

[www]

user = www-data
group = www-data

listen = /run/php/php7.0-fpm.sock

listen.owner = www-data
listen.group = www-data

pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3

env[HOSTNAME] = $HOSTNAME
env[PATH] = /usr/local/bin:/usr/bin:/bin
env[TMP] = /tmp
env[TMPDIR] = /tmp
env[TEMP] = /tmp

; ### ### ### // ASS ### ### ###
; # EOF
NGINXPHPFPMWWWCONFIG
   sudo cp -fv nginx_php_fpm_www_default /etc/php/7.0/fpm/pool.d/www.conf
   sudo systemctl restart nginx.service
   sudo systemctl status --no-pager nginx.service
   sleep 1
   sudo systemctl restart php7.0-fpm
   sudo systemctl status --no-pager php7.0-fpm
   sleep 1
}

#// FUNCTION: configure new nextcloud environment
configure_new_nextcloud() {
   #// pre
   sudo systemctl restart php7.0-fpm
   sudo systemctl status --no-pager php7.0-fpm
   sleep 1
   #// run
   sudo chmod 0755 /var/www/html/occ
   echo "... your nextcloud will now be installed silently ... please be patient ..."
   (sudo -u www-data /var/www/html/occ maintenance:install --database "mysql" --database-name "nextcloud"  --database-user "nextcloud" --database-pass "$MARIADB_PASSWORD" --admin-user "root" --admin-pass "$MARIADB_PASSWORD" --data-dir "/var/www/html/data") & spinner $!
   #// post
   sudo systemctl restart php7.0-fpm
   sudo systemctl status --no-pager php7.0-fpm
   sleep 1
}

#// FUNCTION: set nextcloud: trusted_domains
set_nextcloud_trusted_domains() {
   sudo chmod 0755 /var/www/html/occ
   #/sed '/^$/d' config-trusted_domains | sed -e 's/^/--value=/' | cat -n | awk '{print $1, $2}' | while read VAR1 VAR2
   sed '/^$/d' config-trusted_domains | cat -n | awk '{print $1, $2}' | while read VAR1 VAR2
   do
      sudo -u www-data /var/www/html/occ config:system:set trusted_domains "$VAR1" --value="$VAR2"
      check_hard setting up nextcloud trusted domain: "$VAR2"
   done
}

#// FUNCTION: set nextcloud: redis-server
set_nextcloud_redis() {
   #// mod redis-server config
   sudo sed -i "s/port 6379/port 0/" /etc/redis/redis.conf
   sudo sed -i "s/# unixsocket/unixsocket/g" /etc/redis/redis.conf
   sudo sed -i "s/unixsocketperm 700/unixsocketperm 770/" /etc/redis/redis.conf
   sudo sed -i "s/# maxclients 10000/maxclients 512/" /etc/redis/redis.conf
   sudo usermod -a -G redis www-data
   sudo systemctl restart redis-server.service
   sudo systemctl status --no-pager redis-server.service
   sleep 1
   #// mod nextcloud redis-server manage file locking settings
   sudo -u www-data /var/www/html/occ config:system:set redis host --value=/var/run/redis/redis.sock
   sudo -u www-data /var/www/html/occ config:system:set redis port --value=0
   sudo -u www-data /var/www/html/occ config:system:set redis dbindex --value=0
   sudo -u www-data /var/www/html/occ config:system:set redis password --value=$MARIADB_PASSWORD
   sudo -u www-data /var/www/html/occ config:system:set redis timeout --value=1.5
   #// mod nextcloud redis-server manage file locking
   sudo -u www-data /var/www/html/occ config:system:set memcache.local --value='\OC\Memcache\Redis'
   sudo -u www-data /var/www/html/occ config:system:set memcache.locking --value='\OC\Memcache\Redis'
   sudo -u www-data /var/www/html/occ config:system:set filelocking.enabled --value=true
}

#// FUNCTION: set nextcloud: addons
set_nextcloud_addons() {
   #// enable PDF viewer
   sudo -u www-data /var/www/html/occ app:enable files_pdfviewer
   #// enable Active-Directory / LDAP support
   sudo -u www-data /var/www/html/occ app:enable user_ldap
   #// enable External Storage
   sudo -u www-data /var/www/html/occ app:enable files_external
}

#// FUNCTION: set nextcloud: third party addons
set_nextcloud_thirdparty_addons() {
   #// install & enable Polls
   sudo -u www-data /var/www/html/occ app:install polls
   sudo -u www-data /var/www/html/occ app:enable polls
   #// install & enable Talk (spreed)
   sudo -u www-data /var/www/html/occ app:install spreed
   sudo -u www-data /var/www/html/occ app:enable spreed
   #// install & enable OnlyOffice
   sudo -u www-data /var/www/html/occ app:install onlyoffice
   sudo -u www-data /var/www/html/occ app:enable onlyoffice
   #// install & enable Draw.IO
   sudo -u www-data /var/www/html/occ app:install drawio
   sudo -u www-data /var/www/html/occ app:enable drawio
}

#// FUNCTION: set nextcloud addon parameter
set_nextcloud_addon_parameter() {
   if [ -e /nextcloud_addon_parameter ]
   then
      #// for OnlyOffice
      GET_ONLYOFFICE_URL=$(grep "ONLYOFFICE_URL" /nextcloud_addon_parameter | sed 's/ONLYOFFICE_URL=//g' | sed 's/"//g')
      if [ -z "$GET_ONLYOFFICE_URL" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set onlyoffice DocumentServerUrl --value="$GET_ONLYOFFICE_URL"
      fi
      #// for user_ldap: has_memberof_filter_support
      GET_USER_LDAP_HAS_MEMBEROF_FILTER_SUPPORT=$(grep "USER_LDAP_HAS_MEMBEROF_FILTER_SUPPORT" /nextcloud_addon_parameter | sed 's/USER_LDAP_HAS_MEMBEROF_FILTER_SUPPORT=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_HAS_MEMBEROF_FILTER_SUPPORT" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap has_memberof_filter_support --value="$GET_USER_LDAP_HAS_MEMBEROF_FILTER_SUPPORT"
      fi
      #// for user_ldap: ldap_agent_password
      GET_USER_LDAP_AGENT_PASSWORD=$(grep "USER_LDAP_AGENT_PASSWORD" /nextcloud_addon_parameter | sed 's/USER_LDAP_AGENT_PASSWORD=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_AGENT_PASSWORD" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_agent_password --value="$GET_USER_LDAP_AGENT_PASSWORD"
      fi
      #// for user_ldap: ldap_base
      GET_USER_LDAP_BASE=$(grep "USER_LDAP_BASE_0" /nextcloud_addon_parameter | sed 's/USER_LDAP_BASE_0=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_BASE" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_base --value="$GET_USER_LDAP_BASE"
      fi
      #// for user_ldap: ldap_base_groups
      GET_USER_LDAP_BASE_GROUPS=$(grep "USER_LDAP_BASE_GROUPS" /nextcloud_addon_parameter | sed 's/USER_LDAP_BASE_GROUPS=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_BASE_GROUPS" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_base_groups --value="$GET_USER_LDAP_BASE_GROUPS"
      fi
      #// for user_ldap: ldap_base_users
      GET_USER_LDAP_BASE_USERS=$(grep "USER_LDAP_BASE_USERS" /nextcloud_addon_parameter | sed 's/USER_LDAP_BASE_USERS=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_BASE_USERS" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_base_users --value="$GET_USER_LDAP_BASE_USERS"
      fi
      #// for user_ldap: ldap_configuration_active
      GET_USER_LDAP_CONFIGURATION_ACTIVE=$(grep "USER_LDAP_CONFIGURATION_ACTIVE" /nextcloud_addon_parameter | sed 's/USER_LDAP_CONFIGURATION_ACTIVE=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_CONFIGURATION_ACTIVE" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_configuration_active --value="$GET_USER_LDAP_CONFIGURATION_ACTIVE"
      fi
      #// for user_ldap: ldap_dn
      GET_USER_LDAP_DN=$(grep "USER_LDAP_DN" /nextcloud_addon_parameter | sed 's/USER_LDAP_DN=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_DN" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_dn --value="$GET_USER_LDAP_DN"
      fi
      #// for user_ldap: ldap_group_filter
      GET_USER_LDAP_GROUP_FILTER=$(grep "USER_LDAP_GROUP_FILTER" /nextcloud_addon_parameter | sed 's/USER_LDAP_GROUP_FILTER=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_GROUP_FILTER" ]
      then
         ### #// continues even with empty variable
         ### sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_group_filter --value="$GET_USER_LDAP_GROUP_FILTER"
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_group_filter --value="$GET_USER_LDAP_GROUP_FILTER"
      fi
      #// for user_ldap: ldap_host
      GET_USER_LDAP_HOST=$(grep "USER_LDAP_HOST" /nextcloud_addon_parameter | sed 's/USER_LDAP_HOST=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_HOST" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_host --value="$GET_USER_LDAP_HOST"
      fi
      #// for user_ldap: ldap_login_filter
      GET_USER_LDAP_LOGIN_FILTER=$(grep "USER_LDAP_LOGIN_FILTER_0" /nextcloud_addon_parameter | sed 's/USER_LDAP_LOGIN_FILTER_0=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_LOGIN_FILTER" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_login_filter --value="$GET_USER_LDAP_LOGIN_FILTER"
      fi
      #// for user_ldap: ldap_login_filter_mode
      GET_USER_LDAP_LOGIN_FILTER_MODE=$(grep "USER_LDAP_LOGIN_FILTER_MODE" /nextcloud_addon_parameter | sed 's/USER_LDAP_LOGIN_FILTER_MODE=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_LOGIN_FILTER_MODE" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_login_filter_mode --value="$GET_USER_LDAP_LOGIN_FILTER_MODE"
      fi
      #// for user_ldap: ldap_port
      GET_USER_LDAP_PORT=$(grep "USER_LDAP_PORT" /nextcloud_addon_parameter | sed 's/USER_LDAP_PORT=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_PORT" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_port --value="$GET_USER_LDAP_PORT"
      fi
      #// for user_ldap: ldap_tls
      GET_USER_LDAP_TLS=$(grep "USER_LDAP_TLS" /nextcloud_addon_parameter | sed 's/USER_LDAP_TLS=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_TLS" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_tls --value="$GET_USER_LDAP_TLS"
      fi
      #// for user_ldap: ldap_userfilter_objectclass
      GET_USER_LDAP_USERFILTER_OBJECTCLASS=$(grep "USER_LDAP_USERFILTER_OBJECTCLASS" /nextcloud_addon_parameter | sed 's/USER_LDAP_USERFILTER_OBJECTCLASS=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_USERFILTER_OBJECTCLASS" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_userfilter_objectclass --value="$GET_USER_LDAP_USERFILTER_OBJECTCLASS"
      fi
      #// for user_ldap: ldap_userlist_filter
      GET_USER_LDAP_USERLIST_FILTER=$(grep "USER_LDAP_USERLIST_FILTER" /nextcloud_addon_parameter | sed 's/USER_LDAP_USERLIST_FILTER=//g' | sed 's/"//g')
      if [ -z "$GET_USER_LDAP_USERLIST_FILTER" ]
      then
         : # dummy
      else
         sudo -u www-data /var/www/html/occ config:app:set user_ldap ldap_userlist_filter --value="$GET_USER_LDAP_USERLIST_FILTER"
      fi
   #// post
   sudo systemctl restart php7.0-fpm
   sudo systemctl status --no-pager php7.0-fpm
   sleep 1
   fi
}

#// FUNCTION: show nextcloud report
show_nextcloud_report() {
   #// show User Report
   sudo -u www-data /var/www/html/occ user:report
}

#// FUNCTION: vm information
vm_info() {
   echo ""
   echo "### ### ### ### ### ### ### ### ### ### ### ### ### ###"
   echo "#                                                     #"
   echo "  Container IPv4:         '$GET_IPv4'                  "
   echo "  Container IPv6:         '$GET_IPv6'                  "
   echo "  MariaDB User:           'nextcloud'                  "
   echo "  MariaDB Password:       '$MARIADB_PASSWORD'          "
   echo "  Nextcloud Admin User:   'root'                       "
   echo "#                                                     #"
   echo "### ### ### ### ### ### ### ### ### ### ### ### ### ###"
   echo ""
}

### RUN ###

set_lx_hosts_config
check_hard setting: new hosts config inside lx-zone

install_package sudo less wget
check_hard install: sudo less wget

#// public mariadb-server ONLY
if [ -e /MARIADB-SERVER ]
then
   install_package_mariadb mariadb-client mariadb-server
   check_hard install: mariadb-client mariadb-server

   set_mariadb_root_password
   check_soft setting: mariadb root password

   set_secure_mariadb
   check_soft hardening: mariadb

   prepare_public_mariadb_user
   check_hard prepare: public mariadb-server nextcloud user

   set_public_mariadb_config
   check_hard setting: new public mariadb-server config

   vm_info
   exit 0
fi

install_package nginx
check_hard install: nginx

install_package_mariadb mariadb-client mariadb-server
check_hard install: mariadb-client mariadb-server

set_mariadb_root_password
check_soft setting: mariadb root password

set_secure_mariadb
check_soft hardening: mariadb

remove_php5
check_hard remove: php5

prepare_php7_repository
check_hard prepare: php7

install_package php7.0-common php7.0-fpm php7.0-cli php7.0-json php7.0-mysql php7.0-curl php7.0-intl php7.0-mcrypt php-pear php7.0-gd php7.0-zip php7.0-xml php7.0-mbstring php7.0-ldap php7.0-bz2
check_hard install: php7.0-common php7.0-fpm php7.0-cli php7.0-json php7.0-mysql php7.0-curl php7.0-intl php7.0-mcrypt php-pear php7.0-gd php7.0-zip php7.0-xml php7.0-mbstring php7.0-ldap php7.0-bz2

install_package php7.0-opcache
check_hard install: php7.0-opcache

### OPTIONAL #/install_package php-apcu
### OPTIONAL #/check_hard install: php-apcu

install_package imagemagick php-imagick
check_hard install: imagemagick php-imagick

install_package redis-server php-redis
check_hard install: redis-server php-redis

install_package apt-transport-https lsb-release ca-certificates software-properties-common zip unzip screen curl ffmpeg libfile-fcntllock-perl
check_hard install: apt-transport-https lsb-release ca-certificates software-properties-common zip unzip screen curl ffmpeg libfile-fcntllock-perl

install_nextcloud
check_hard install: nextcloud

prepare_mariadb_user
check_soft prepare: mariadb nextcloud user

set_mariadb_config
check_soft setting: new mariadb config

install_package ssl-cert
check_hard install: ssl-cert

set_nginx_config
check_hard setting: new nginx config

set_nginx_php_config
check_hard setting: new nginx php config

install_package smbclient
check_hard install: smbclient

install_package php-smbclient
check_hard install: php-smbclient

vm_info

configure_new_nextcloud
check_soft configure new nextcloud / hint: if this failed, it has already been set up, start the git script again or needs to be set up via web ui!

set_nextcloud_trusted_domains
check_hard setting: nextcloud trusted domains / hint: if this is the first pass, go now to the nextcloud web ui and follow the installation, then run the git script again!

set_nextcloud_redis
check_hard setting: nextcloud redis-server

set_nextcloud_addons
check_hard setting: nextcloud addons

set_nextcloud_thirdparty_addons
check_hard setting: nextcloud third party addons

set_nextcloud_addon_parameter
check_hard setting: nextcloud addon parameter

show_nextcloud_report
check_soft show: nextcloud user report / hint: if something went wrong, reset the ldap password via web ui!

vm_info
### ### ### // ASS ### ### ###
exit 0
# EOF
