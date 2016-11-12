#!/bin/sh

##todo http://serverfault.com/questions/172831/sending-email-from-my-server#comment150117_172834

# set the fastest mirror
sed -i "s/ftp\.debian\.org/httpredir.debian.org/g" /etc/apt/sources.list
sed -i "s/ftp\.\([a-z]\+\)\.debian\.org/httpredir.debian.org/g" /etc/apt/sources.list

apt-get update # has to be here, even if it fails
apt-get install -y debian-keyring 
apt-get install -y debian-archive-keyring
apt-get update
apt-get -y upgrade
apt-get install dialog

PORT_SSH_DEFAULT=$(date -u "+%N" | cut -c 7,8)
PORT_SSH_DEFAULT="220${PORT_SSH_DEFAULT}"
PORT_FTP_DEFAULT=$(date -u "+%N" | cut -c 6,7)
PORT_FTP_DEFAULT="210${PORT_FTP_DEFAULT}"
PORT_MYSQL_DEFAULT=$(date -u "+%N" | cut -c 8,7)
PORT_MYSQL_DEFAULT="330${PORT_MYSQL_DEFAULT}"
FTP_USER="ftp-data"
WWW_ROOT="/var/www"
CERTBOT_PATH="/root/certbot-auto"

if [ ! -e "~/random_string.sh" ]; then
cat > ~/random_string.sh << EOF
#!/bin/sh
if [ \$1="-l" ]; then
        length=\$2
    else
        length="8"
    fi
echo \`cat /dev/urandom | tr -dc "a-zA-Z0-9" | fold -w \$length | head -1\`
EOF
fi

is_installed2() {
    local PKG="$1"
    PKG_OK=$(dpkg-query -W --showformat='${Status}\n' $PKG|grep "install ok installed")
    echo $PKG_OK
    if [ "" = $PKG_OK ]; then
        echo "No somelib. Setting up $PKG."
    fi
}

is_installed() {
    if [ -z "`which "$1" 2>/dev/null`" ]
    then
        return 0
    else
        return 1
    fi
}

do_install() {
    is_installed $1
    RES=$?
    if [ "0" = $RES ]; then
        apt-get install -q -y --no-install-recommends -o Dpkg::Options::="--force-confnew" $1
    fi
}

do_uninstall() {
    if [ "$#" = 2 ]; then
        if [ "1" = "$2" ]; then
            DEL=$1
        else
            DEL=$2
        fi
    fi
    if [ "$#" = 1 ]; then
        DEL="$1*"
    fi
    is_installed $1
    RES=$?
    if [ "1" = $RES ]; then
        invoke-rc.d $1 stop
        apt-get purge -s -y $DEL
    fi
}

report_append()  {
    echo "$1: $2" >> ~/bonjour.txt
}







install() {

    read -p "Install php7.0? Choosing (n) will install php5 [Y/n]: " PHP7_Yn
    if [ "${PHP7_Yn}" = "" ]; then
        PHP7_Yn="Y"
    fi
    if [ "${PHP7_Yn}" = "Y" ] || [ "${PHP7_Yn}" = "y" ]; then
        PHP_VER="7.0"
        # symlink to match the old naming format (see the issue #1)
        ln -s /usr/bin/php-cgi7.0 /usr/bin/php7.0-cgi
    else 
        PHP_VER="5"
    fi

    read -p "Install Letsencrypt Certbot? [Y/n]: " LECertbot_Yn
    if [ "${LECertbot_Yn}" = "" ]; then
        LECertbot_Yn="Y"
    fi


    cat /dev/null > ~/bonjour.txt
    hostname_old=`hostname`
    if [ "${hostname_old}" = "" ] || [ "${hostname_old}" = "vps" ]; then
        read -p "New hostname[+]: " nhostname
        if [ "$nhostname" = "" ]; then
            nhostname="+"
        fi
        if [ "$nhostname" = "+" ]; then
            nhostname=`sh /root/random_string.sh -l 4`
            hostname $nhostname
        fi
        if [ "$nhostname" != "" ]; then
            hostname $nhostname
        fi
    else
        nhostname="${hostname_old}"
    fi
    
    read -p "SSH port (default=${PORT_SSH_DEFAULT}): " PORT_SSH
    if [ "$PORT_SSH" = "" ]; then
        PORT_SSH=$PORT_SSH_DEFAULT
    fi
    report_append "PORT_SSH" $PORT_SSH

    read -p "FTP port ('0' to skip, default=${PORT_FTP_DEFAULT}): " PORT_FTP
    if [ "$PORT_FTP" = "" ]; then
        PORT_FTP=$PORT_FTP_DEFAULT
    fi

    read -p "MySQL port ('0' to skip, default=${PORT_MYSQL_DEFAULT}): " PORT_MYSQL
    if [ "$PORT_MYSQL" = "" ]; then
        PORT_MYSQL=$PORT_MYSQL_DEFAULT
    fi

    if ! [ -d $WWW_ROOT ]; then
        mkdir $WWW_ROOT
    fi

    if [ ! "$PORT_FTP" = "0" ]; then
        wdpasswordg=`sh /root/random_string.sh -l 10`
        read -p "Enter a new password for user '$FTP_USER' [${wdpasswordg}]: " wdpassword
        if [ "$wdpassword" = "" ]; then
            wdpassword="${wdpasswordg}"
        fi
        cppassword=$(perl -e 'print crypt($ARGV[0], "password")' $wdpassword)
        if id -u $FTP_USER >/dev/null 2>&1; then
            pkill -u $FTP_USER
            killall -9 -u $FTP_USER
            usermod --home "$WWW_ROOT" $FTP_USER
            usermod --password=$cppassword $FTP_USER
        else
            #echo -e "/bin/false\n" >> /etc/shells
            useradd -d "$WWW_ROOT" -p $cppassword -g www-data -s /bin/sh -M $FTP_USER
            chown $FTP_USER:www-data $WWW_ROOT
        fi
        report_append "PORT_FTP" $PORT_FTP
        report_append "$FTP_USER" $wdpassword
    else
        echo "**** FTP SKIPPED"
    fi

    if [ ! "$PORT_MYSQL" = "0" ]; then
        MYSQL_ROOT_PASS=`sh /root/random_string.sh -l 8`
        read -p "MySQL remote user name: " MYSQL_REMO_USER
        if [ "$MYSQL_REMO_USER" = "" ]; then
            MYSQL_REMO_USER=`sh /root/random_string.sh -l 8`
        fi
        read -p "MySQL password for user '$MYSQL_REMO_USER': " MYSQL_REMO_PASS
        if [ "$MYSQL_REMO_PASS" = "" ]; then
            MYSQL_REMO_PASS=`sh /root/random_string.sh -l 8`
        fi
        report_append "PORT_MYSQL" $PORT_MYSQL
        report_append "MYSQL_ROOT_PASS" $MYSQL_ROOT_PASS
        report_append "MYSQL_REMO_USER" $MYSQL_REMO_USER
        report_append "MYSQL_REMO_PASS" $MYSQL_REMO_PASS
    else
        echo "**** MySQL SKIPPED"
    fi

#build-essentials = c++

do_uninstall exim4
do_uninstall nginx 1
do_uninstall apache2
do_uninstall proftpd-basic
do_uninstall exim4
do_uninstall postgrey
do_uninstall sendmail
#do_uninstall bind9 "bind9-*"
do_uninstall dovecot
do_uninstall mysql


export DEBIAN_FRONTEND=noninteractive
debian_version=`cat /etc/debian_version | sed -r 's/\..*//'`
case $debian_version in
    "6")
        debian_codename="squeeze"
    ;;
    "7")
        debian_codename="wheezy"
    ;;
    "8")
        debian_codename="jessie"
    ;;
esac
cat /dev/null > /etc/apt/sources.list
echo "deb http://ftp.debian.org/debian ${debian_codename} main contrib non-free" >> /etc/apt/sources.list
echo "deb http://security.debian.org/ ${debian_codename}/updates main contrib non-free" >> /etc/apt/sources.list
echo "deb http://ftp.debian.org/debian/ ${debian_codename}-backports main contrib non-free" >> /etc/apt/sources.list
for k in $(apt-get update 2>&1|grep -o NO_PUBKEY.*|sed 's/NO_PUBKEY //g');do echo "key: $k";gpg --recv-keys $k;gpg --recv-keys $k;gpg --armor --export $k|apt-key add -;done

apt-get update
export DEBIAN_FRONTEND=noninteractive

do_install build-essential
#do_install gcc
#do_install apt-utils
do_install iptables
do_install make
do_install sed
do_install curl
do_install ca-certificates
do_install wget
do_install ntp

do_install tzdata
echo "UTC" > /etc/timezone
dpkg-reconfigure -f noninteractive tzdata

#do_install libpcre3-dev
#do_install zlib1g-dev
do_install nginx
#mkdir /root/nginx && cd /root/nginx && wget http://nginx.org/download/nginx-1.4.0.tar.gz && tar zxf nginx-1.4.0.tar.gz && cd nginx-1.4.0 && ./configure --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=/var/log/nginx/error.log --pid-path=/var/log/nginx/nginx.pid --user=www-data --group=www-data && make && make install && rm -rf /root/nginx && cd ~
if [ ! "$PORT_FTP" = "0" ]; then
    do_install inetutils-ftpd
fi
if [ ! "$PORT_MYSQL" = "0" ]; then
    do_install mysql-server
    invoke-rc.d mysql stop
fi

if [ "${PHP_VER}" = "7.0" ]; then
    echo "deb http://packages.dotdeb.org ${debian_codename} all" >> /etc/apt/sources.list
    wget https://www.dotdeb.org/dotdeb.gpg
    apt-key add dotdeb.gpg
    apt-get update
fi
# installing PHP and it's modules
do_install php${PHP_VER}-common
do_install php${PHP_VER}-cli
do_install php${PHP_VER}-cgi
do_install php${PHP_VER}-mysql
do_install php${PHP_VER}-curl
do_install php${PHP_VER}-gd
do_install php${PHP_VER}-mcrypt
do_install php${PHP_VER}-intl
do_install php${PHP_VER}-json
do_install php${PHP_VER}-bcmath
do_install php${PHP_VER}-imap
do_install php${PHP_VER}-mbstring
do_install php${PHP_VER}-xml
if [ "${PHP_VER}" = "7.0" ]; then
    do_install php${PHP_VER}-opcache
fi
if [ "${PHP_VER}" = "5" ]; then
    do_install php${PHP_VER}-suhosin
fi

#invoke-rc.d nginx stop
#invoke-rc.d php${PHP_VER}-cgi stop


cat > /etc/init.d/php${PHP_VER}-cgi <<END
#!/bin/sh
### BEGIN INIT INFO
# Provides:          php${PHP_VER}-cgi
# Required-Start:    \$local_fs \$remote_fs \$network
# Required-Stop:     \$local_fs \$remote_fs \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: controls php${PHP_VER}-cgi
# Description:       controls php${PHP_VER}-cgi using start-stop-daemon
### END INIT INFO

PHP_CGI="\$(which php${PHP_VER}-cgi)"
PHP_CGI_NAME=\`basename \$PHP_CGI\`

BIND="/var/run/\${PHP_CGI_NAME}/\${PHP_CGI_NAME}.sock"
PIDFILE="/var/run/\${PHP_CGI_NAME}.pid"
USER=www-data

PHP_FCGI_CHILDREN=16
PHP_FCGI_MAX_REQUESTS=4096

PHP_CGI_ARGS="- USER=\$USER PATH=/usr/bin PHP_FCGI_CHILDREN=\$PHP_FCGI_CHILDREN PHP_FCGI_MAX_REQUESTS=\$PHP_FCGI_MAX_REQUESTS \$PHP_CGI -b \$BIND"
RETVAL=0

start() {
    if ! [ -d /var/run/\${PHP_CGI_NAME} ]; then
        mkdir /var/run/\${PHP_CGI_NAME}
    fi
    chown www-data:www-data /var/run/\${PHP_CGI_NAME}
    chmod 0777 /var/run/\${PHP_CGI_NAME}
    echo -n "Starting PHP FastCGI: "
    start-stop-daemon --quiet --start --pidfile \${PIDFILE} --background --chuid "\$USER" --exec /usr/bin/env -- \$PHP_CGI_ARGS
    RETVAL=\$?
    echo "\$PHP_CGI_NAME."
}
stop() {
    echo -n "Stopping PHP FastCGI: "
    #pkill \$PHP_CGI_NAME
    #RETVAL=\$?
    start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile \${PIDFILE} > /dev/null
    RETVAL="\$?"
    [ "\$RETVAL" = 2 ] && return 2
    start-stop-daemon --stop --quiet --oknodo --retry=0/30/KILL/5 --exec /usr/bin/env
    [ "\$?" = 2 ] && return 2
    rm -f \$PIDFILE
    echo "\$PHP_CGI_NAME."
    return "\$RETVAL"
}

case "\$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    *)
        echo "Usage: php-fastcgi {start|stop|restart}"
        exit 1
        ;;
esac
exit \$RETVAL
END

chmod +x /etc/init.d/php${PHP_VER}-cgi
update-rc.d php${PHP_VER}-cgi defaults

if [ -e "/etc/nginx/sites-enabled/default" ];
    then
        rm "/etc/nginx/sites-enabled/default"
    fi

cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes  1;
pid /var/run/nginx.pid;
events {
    worker_connections  1024;
}
http {
    client_max_body_size 32m;
    include mime.types;
    default_type application/octet-stream;
    charset utf-8;
    sendfile on;
    keepalive_timeout 65;
    server {
        server_name _;#default
        return 444;
    }
    server {
        listen 80;
        server_name localhost;
        location / {
            root $WWW_ROOT;
            index index.html index.htm;
        }
    }
    include /etc/nginx/sites-enabled/*;
}
EOF

cat > /etc/nginx/common.conf << EOF
listen 80;
index  index.php index.html index.htm;
fastcgi_index index.php;
location ~ \.php {
    try_files \$uri =404;
    include /etc/nginx/fastcgi_params;
    keepalive_timeout 0;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    fastcgi_pass unix:/var/run/php${PHP_VER}-cgi/php${PHP_VER}-cgi.sock;
}
location = /favicon.ico {
    log_not_found off;
    access_log off;
}
location = /robots.txt {
    allow all;
    log_not_found off;
    access_log off;
}
location ~ /\.ht {
    deny all;
}
location ~ /\.ng {
    deny all;
}
EOF

invoke-rc.d nginx start
invoke-rc.d php${PHP_VER}-cgi start
curl -sS https://getcomposer.org/installer -o "$WWW_ROOT/composer.phar"
php "$WWW_ROOT/composer.phar"

if [ ! "$PORT_MYSQL" = "0" ]; then
    #sed -i 's/#skip-innodb/skip-innodb/g' /etc/mysql/my.cnf
    echo "skip-innodb" >> /etc/mysql/my.cnf
    sed -i "s/\t= 3306/\t= ${PORT_MYSQL}/g" /etc/mysql/my.cnf
    sed -i "s/\t= 127.0.0.1/\t= $(hostname -i)/g" /etc/mysql/my.cnf
    invoke-rc.d mysql start
    mysqladmin -u root password "${MYSQL_ROOT_PASS}"
    mysql -uroot -p${MYSQL_ROOT_PASS} -e "CREATE USER '${MYSQL_REMO_USER}'@'%' IDENTIFIED BY '${MYSQL_REMO_PASS}';"
    mysql -uroot -p${MYSQL_ROOT_PASS} -e "GRANT ALL PRIVILEGES ON *.* TO '${MYSQL_REMO_USER}'@'%' WITH GRANT OPTION;"
fi

cat > /root/add_host.sh << EOF
#!/bin/sh

### Checking for user
if [ "\$(whoami)" != 'root' ]; then
    echo "You have no permission to run \$0 as non-root user. Use sudo !!!"
    exit 1;
fi

### Script params
www_root="$WWW_ROOT"
ftp_user="$FTP_USER"
if ! [ id -u "\$ftp_user" >/dev/null 2>&1 ]; then
    ftp_user="www-data"
fi
nginx_conf_dir="/etc/nginx"
sites_available=\$nginx_conf_dir"/sites-available"
sites_enabled=\$nginx_conf_dir"/sites-enabled"
mysql="\$(which mysql)"
# mysql root password
mysql_password="$MYSQL_ROOT_PASS"
# phpMyAdmin login details:
mysql_admin="$MYSQL_REMO_USER"
mysql_admin_password="$MYSQL_REMO_PASS"

### Functions
restart_nginx() {
    if [ -e /var/run/nginx.pid ];
        then
            command='restart'
        else
            command='start'
        fi
    invoke-rc.d nginx \$command
}
add_alias() {
    aliases=\$aliases" "\$1
    read -p "Enter another alias (leave blank to skip): " newalias
    if [ "\$newalias" != "" ];then
        ### loop
        add_alias \$newalias
    fi
}
add() {
    public_dir_name_default="public_html"
    read -p "Add www.\$1? [Y/n]: " WWW_Yn
    if [ "\${WWW_Yn}" = "" ] || [ "\${WWW_Yn}" = "Y" ] || [ "\${WWW_Yn}" = "y" ]; then
        aliases="www.\$1"
    fi
    database_name_random=\`echo \$1 | sed -e 's/\W//g'\`;
    database_user_random=\`sh /root/random_string.sh -l 8\`
    database_password_waitforit_random=\`sh /root/random_string.sh -l 12\`
    if [ -z \$4 ]; then
        read -p "Enter alias (leave blank to skip): " alias
        if [ "\$alias" != "" ]; then
            add_alias \$alias
        fi
    else
        if [ \$4 != "N" ] && [ \$4 != "n" ]; then
            aliases=\$aliases" "\$4
        fi
    fi
    if [ -z \$2 ]; then
        site_dir_default=\$www_root
        read -p "Specify the top-level ROOT ([ \$site_dir_default ]/\$1): " site_dir
        if [ "\$site_dir" = "" ]; then
            site_dir=\$site_dir_default
        fi
        read -p "Enter site directory NAME (\$site_dir/[ \$1 ]): " site_dir_name
        if [ "\$site_dir_name" = "" ]; then
            site_dir_name=\$1
        fi
    else
        site_dir=\$www_root
        site_dir_name=\$2
    fi

    site_dir=\$site_dir"/"\$site_dir_name
    #read -p "Create \"public_html\" subdir (i.e. "\$site_dir"/"\$public_dir_name_default")? [y/N]: " create_public_dir
    create_public_dir="N"

    if [ -z \$3 ]; then
    read -p "Create MySQL database? [Y/n]: " create_database
    if [ "\$create_database" != "n" ] && [ "\$create_database"!="N" ]
        then
            read -p "Enter MySQL database name [\$database_name_random]: " database_name
            if [ "\$database_name" = "" ]
                then
                    database_name=\$database_name_random
                fi
            read -p "Enter MySQL user [\$database_user_random]: " database_user
            if [ "\$database_user" = "" ]
                then
                    database_user=\$database_user_random
                fi
            read -p "Enter MySQL password [\$database_password_waitforit_random]: " database_password
            if [ "\$database_password" = "" ]
                then
                    database_password=\$database_password_waitforit_random
                fi
        fi
    else
        if [ \$3 = "N" ] || [ \$3 = "n" ]; then
            create_database="n"
        else
            create_database="y"
            database_name=\$database_name_random
            database_user=\$database_user_random
            database_password=\$database_password_waitforit_random
        fi
    fi

    read -p "Create a separate FTP/UNIX user? [Y/n]: " create_user
    if [ "\${create_user}" != "n" ] && [ "\${create_user}"!="N" ]; then
        secondlvldomain=\`echo \$1 | cut -d "." -f 1\`
        website_user_default="www-usr-\${secondlvldomain}"
        read -p "FTP/UNIX user [\${website_user_default}]: " website_user
        if [ "u\${website_user}" = "u" ]; then
            website_user=\${website_user_default}
        fi
        wdpasswordg=\`sh /root/random_string.sh -l 10\`
        read -p "Enter a new password for user '\${website_user}' [\${wdpasswordg}]: " wdpassword
        if [ "\$wdpassword" = "" ]; then
            wdpassword="\${wdpasswordg}"
        fi
        cppassword=\$(perl -e 'print crypt(\$ARGV[0], "password")' \$wdpassword)
        if id -u \${website_user} >/dev/null 2>&1; then
            pkill -u \${website_user}
            killall -9 -u \${website_user}
            usermod --password=\${cppassword} --home="\${site_dir}" \${website_user}
        else
            useradd -d "\${site_dir}" -p \${cppassword} -g www-data -s /bin/sh -M \${website_user}
        fi
        ftp_user="\${website_user}"
    fi

    echo ""
    echo "ADDING VIRTUALHOST \$1"
    echo -n "Web root... "
    if ! [ -d \$site_dir ];
        then
            mkdir \$site_dir
            chown \$ftp_user:www-data \$site_dir
        fi
    if ! [ -d \$site_dir ]
        then
            echo "ERROR: "\$site_dir" could not be created."
        else
            echo \$site_dir" is fine."
            if [ "\$create_public_dir" = "y" ] || [ "\$create_public_dir" = "Y" ]
                then
                    public_dir=\$site_dir"/"\$public_dir_name_default
                    mkdir \$public_dir
                    chown \$ftp_user:www-data \$public_dir
                else
                    public_dir=\$site_dir
            fi
        fi
    ngaccess_file=\$site_dir"/.ngaccess"
    echo -n "Nginx config... "
    config=\$sites_enabled"/"\$1
    if ! [ -e \$common_conf_file ] || ! touch \$config
        then
            echo "ERROR: "\$config" could not be created."
        else
            echo \$config" created."
        fi
    echo -n "Writing config... "
    if ! echo "server {
server_name \$1 \$aliases;
access_log /var/log/nginx/\$1.access.log;
error_log /var/log/nginx/\$1.error.log;
root \$public_dir; # config_path \$site_dir
include "\$ngaccess_file";
location ~ /\.ng {
    return 404;
}
include "/etc/nginx/common.conf";
}" > \$config
        then
            echo "ERROR"
        else
            echo "done."
        fi
    echo "# FTP :${PORT_FTP} u:\${website_user} p:\${wdpassword}" >> \${config}
    echo -n ".ngaccess file... "
    if ! [ -f \$ngaccess_file ]
        then
            if ! touch \$ngaccess_file
                then
                    echo "ERROR (creating)."
                else
                    if ! echo "#this is the part of the main nginx config
if (!-f \\\$request_filename) {
    # put your rewrite rules here
    #rewrite  ^(.*)\\$ /index.php break;
}" > \$ngaccess_file
                        then
                            echo "ERROR (writing)."
                        else
                            echo "done."
                        fi
                fi
        else
            echo "exists."
        fi
    echo "# FTP :${PORT_FTP} u:\${website_user} p:\${wdpassword}" >> \${ngaccess_file}
    chown -R \${website_user}:www-data \${site_dir}
    ### MySQL
    if [ "\$create_database" != "n" ] && [ "\$create_database"!="N" ]
        then
            \$mysql -uroot -p\$mysql_password -e "CREATE DATABASE \\\`\$database_name\\\`;"
            \$mysql -uroot -p\$mysql_password -e "GRANT SELECT,INSERT,UPDATE,DELETE ON \$database_name.* TO \$database_user@localhost IDENTIFIED BY '\$database_password';"
            \$mysql -uroot -p\$mysql_password -e "GRANT ALL ON \$database_name.* TO \$mysql_admin@localhost IDENTIFIED BY '\$mysql_admin_password';"
            echo -e "Database:\n-name: \$database_name\n-user: \$database_user\n-pass: \$database_password"
            echo -n "Config file... "
            config_file=\$site_dir"/config.php"
            if ! touch \$config_file
                then
                    echo "ERROR (creating)."
                else
                    if ! echo -e "<?php\\n\\\$mysql=array();\\n\\\$mysql['host']='localhost';\\n\\\$mysql['name']='\$database_name';\\n\\\$mysql['user']='\$database_user';\\n\\\$mysql['pass']='\$database_password';\\n?>" > \$config_file
                        then
                            echo "ERROR (writing)."
                        else
                            echo "done."
                        fi
                fi
        fi
}
remove() {
    config_nginx=\$sites_enabled"/"\$1
    if [ -f \$config_nginx ]
        then
            echo ""
            echo "CLEANING THE DATABASE"
            site_dir=\`cat \$config_nginx | grep config_path | sed -e "s/root \(.*\); # config_path \(.*\)/\2/g"\`
            echo \$site_dir
            config_php=\$site_dir"/config.php"
            if [ -f \$config_php ]
                then
                    database_name=\`cat \$config_php | grep name | sed -e "s/.*='\(.*\)';/\1/g"\`
                    database_user=\`cat \$config_php | grep user | sed -e "s/.*='\(.*\)';/\1/g"\`
                else
                    echo "Can't find the config.php file!"
                    read -p "Remove the database manually? [Y/n]:" remove_database
                    if [ "\$remove_database" != "n" ] && [ "\$remove_database"!="N" ]
                        then
                            read -p "MySQL database name: " database_name
                            read -p "MySQL database user: " database_user
                        fi
                fi
            if [ "\$database_name" != "" ] && [ "\$database_user" != "" ]
                then
                    \$mysql -uroot -p\$mysql_password -e "DROP DATABASE \$database_name;"
                    \$mysql -uroot -p\$mysql_password -e "DROP USER '\$database_user'@localhost;"
                fi
            echo ""
            echo "REMOVING \$1 VIRTUALHOST"
            echo -n "Nginx config... "
            if ! rm \$config_nginx
                then
                    echo "ERROR: "\$config_nginx" could not be removed."
                else
                    echo \$config_nginx" removed."
                fi
            read -p "Remove \$site_dir? [y/N]: " remove_dir
            echo -n "Web root... "
            if [ "\$remove_dir" != "y" ] && [ "\$remove_dir" != "Y" ]
                then
                    echo "untouched."
                else
                    if ! rm -r \$site_dir
                        then
                            echo "ERROR."
                        else
                            echo "removed."
                        fi
                fi
        else
            echo "Can't find the config file \$config_nginx"
        fi
}

if [ -z \$# ] && [ \$# -gt 0 ]; then
    for i; do
        key=\`echo \$i | cut -d = -f 1 | cut -c 3-\`
        val=\`echo \$i | cut -d = -f 2\`
        case \$key in
            "action" | "act")
                case \$val in
                    "add" | "a")
                        action="add"
                    ;;
                    "remove" | "r")
                        action="remove"
                    ;;
                esac
                ;;
            "hostname" | "host")
                hostname=\$val
                ;;
            "alias")
                alias=\$val
                ;;
            "dir")
                dirname=\$val
                ;;
            "db")
                database=\$val
                ;;
        esac
    done
fi

if [ -z \$action ]; then
    if [ -z \$2 ]; then
        action="add"
        hostname="\$1"
    else
        case \$1 in
            "add" | "a" | "-a")
                action="add"
                ;;
            "remove" | "r" | "-r")
                action="remove"
                ;;
        esac
        hostname="\$2"
    fi
fi;

echo "ACTION: \${action}"
### What to do?
case "\$action" in
    "remove")
        remove \$hostname
        ;;
    "add")
        add \$hostname \$dirname \$database \$alias
        ;;
esac

restart_nginx

EOF

chmod +x ~/add_host.sh
echo "alias addhost='sh /root/add_host.sh'" >> /etc/bash.bashrc

if [ ! "$PORT_FTP" = "0" ]; then
    sed -i "s/\t21\/tcp/\t$PORT_FTP\/tcp/g" /etc/services
    #useradd ftpd
cat > /etc/init.d/inetutils-ftpd << EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          inetutils-ftpd
# Required-Start:    \$local_fs \$remote_fs \$network \$syslog
# Required-Stop:     \$local_fs \$remote_fs \$network \$syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: controls ftpd
# Description:       controls inetutils-ftpd using start-stop-daemon
### END INIT INFO
USER="root"
NAME="ftpd"
DAEMON="\$(which \$NAME)"
DAEMON_ARGS="--no-version --daemon --auth=default"
RETVAL=0
start() {
    echo -n "Starting \$NAME: "
    start-stop-daemon --quiet --start --background --chuid "\$USER" --exec /usr/bin/env --exec \$DAEMON -- \$DAEMON_ARGS
    RETVAL=\$?
    echo "\$DAEMON."
}
stop() {
    echo -n "Stopping \$NAME: "
    killall \$NAME
    RETVAL=\$?
    echo "\$NAME."
}
case "\$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    *)
        echo "Usage: \$NAME {start|stop|restart}"
        exit 1
        ;;
esac
exit \$RETVAL
EOF
chmod +x /etc/init.d/inetutils-ftpd
invoke-rc.d inetutils-ftpd start
update-rc.d inetutils-ftpd defaults
fi

if [ "${LECertbot_Yn}" = "Y" ] || [ "${LECertbot_Yn}" = "y" ]; then
    # install certbot for letsencrypt
    # https://certbot.eff.org/all-instructions/#web-hosting-service-nginx
    wget -O ${CERTBOT_PATH} https://dl.eff.org/certbot-auto
    chmod a+x ${CERTBOT_PATH}
    ${CERTBOT_PATH}
fi

sed -i "s/Port 22/Port $PORT_SSH/g" /etc/ssh/sshd_config
#/usr/bin/ssh-keygen -A

#iptables -A INPUT -s 8.8.1.1/16 -p tcp --dport ${PORT_SSH} -j ACCEPT
#iptables -A OUTPUT -d 8.8.1.1/16 -p tcp --sport ${PORT_SSH} -j ACCEPT
#iptables -A INPUT -p tcp --dport ${PORT_SSH} -j DROP
#iptables -A OUTPUT -p tcp --sport ${PORT_SSH} -j DROP
if [ ! "${PORT_SSH}" = "22" ]; then
    iptables -A INPUT -p tcp --dport 22 -j DROP
    iptables -A OUTPUT -p tcp --sport 22 -j DROP
fi;
iptables -A INPUT -p tcp --dport 9000 -j DROP
iptables -A OUTPUT -p tcp --sport 9000 -j DROP
iptables-save > /etc/iptables.conf
cat > /etc/network/if-up.d/iptables << EOF
#!/bin/sh
iptables-restore < /etc/iptables.conf
EOF
chmod +x /etc/network/if-up.d/iptables 

apt-get -y autoremove
echo "**** Once again, the new SSH port is: ${PORT_SSH}"

# https://www.veeam.com/kb2061
echo "KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1" >> /etc/ssh/sshd_config
echo "Ciphers 3des-cbc,blowfish-cbc,aes128-cbc,aes128-ctr,aes256-ctr" >> /etc/ssh/sshd_config
ssh-keygen -A

sleep 4
invoke-rc.d ssh restart
reboot
}

case "$1" in
    install)
        install
        ;;
    *)
        read -p "Run the instserv script? [Y/n]: " inststart
        if [ "${inststart}" != "N" ] && [ "${inststart}" != "n" ]; then
            install
        else
            echo "Aborted."
        fi
        ;;
esac