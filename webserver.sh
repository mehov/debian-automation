#!/bin/sh

##todo http://serverfault.com/questions/172831/sending-email-from-my-server#comment150117_172834


PORT_SSH_DEFAULT=$(date -u "+%N" | cut -c 7,8)
PORT_SSH_DEFAULT="220${PORT_SSH_DEFAULT}"
PORT_FTP_DEFAULT=$(date -u "+%N" | cut -c 6,7)
PORT_FTP_DEFAULT="210${PORT_FTP_DEFAULT}"
PORT_MYSQL_DEFAULT=$(date -u "+%N" | cut -c 8,7)
PORT_MYSQL_DEFAULT="330${PORT_MYSQL_DEFAULT}"
SSH_USER_DEFAULT="admin"
FTP_USER="ftp-data"
WWW_ROOT="/var/www"
CERTBOT_PATH="/root/certbot-auto"
HOSTMANAGER_PATH="/root/spanel.sh"
SSH_CLIENT_IP=$(who -m --ips | awk '{print $5}')

# reusable functions
random_string() {
    if [ $1="-l" ]; then
            length=$2
        else
            length="8"
        fi
    echo `cat /dev/urandom | tr -dc "a-zA-Z0-9" | fold -w $length | head -1`
}
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
        DEBIAN_FRONTEND=noninteractive apt-get install -q -y --no-install-recommends -o Dpkg::Options::="--force-confnew" $1
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
        service $1 stop
        apt-get purge -s -y $DEL
    fi
}

report_append()  {
    echo "$1: $2" >> ~/bonjour.txt
}







install() {
    read -p "Install Nginx? [Y/n]: " NGINX_Yn
    if [ "${NGINX_Yn}" = "" ] ||  [ "${NGINX_Yn}" = "Y" ] || [ "${NGINX_Yn}" = "y" ]; then
        PORT_HTTP="80"
    else 
        PORT_HTTP="0"
    fi
    read -p "Install PHP? [Y/n]: " PHP_Yn
    if [ "${PHP_Yn}" = "" ] ||  [ "${PHP_Yn}" = "Y" ] || [ "${PHP_Yn}" = "y" ]; then
        PHP_VER="7"
    else 
        PHP_VER="0"
    fi

    LECertbot_Yn="n"
    if [ ! "$PORT_HTTP" = "0" ]; then
        read -p "Install the Let's Encrypt Certbot? [Y/n]: " LECertbot_Yn
    fi

    cat /dev/null > ~/bonjour.txt
    hostname_old=`hostname`
    if [ "${hostname_old}" = "" ] || [ "${hostname_old}" = "vps" ]; then
        read -p "New hostname[+]: " nhostname
        if [ "$nhostname" = "" ]; then
            nhostname="+"
        fi
        if [ "$nhostname" = "+" ]; then
            nhostname=`random_string -l 4`
            hostname $nhostname
        fi
        if [ "$nhostname" != "" ]; then
            hostname $nhostname
        fi
    else
        nhostname="${hostname_old}"
    fi

    printf "\n\n\n\n"
    echo "Some commonly hacked ports (e.g. SSH, FTP) shouldn't be public."
    echo "You can whitelist your trusted IP addresses, and block everyone else."
    echo ""
    echo "!! If you lose access to the IPs you whitelisted, you will get locked out."
    echo ""
    printf "So use multiple trusted IPs (e.g. a backup VPN), or buy a "
    printf "static IP from your ISP, or make sure your VPS provider has "
    printf "an emergency console or is able to step in; otherwise choose 'n' below.\n"
    echo ""
    read -p "Secure commonly hacked ports by whitelisting your IP addresses? [Y/n]: " WHTLST_Yn
    if [ "${WHTLST_Yn}" = "" ] || [ "${WHTLST_Yn}" = "Y" ] || [ "${WHTLST_Yn}" = "y" ]; then
        read -p "Whitelisted IP addresses, space-separated [${SSH_CLIENT_IP}]: " WHTLST_IPS
        if [ -z "${WHTLST_IPS}" ]; then
            WHTLST_IPS="${SSH_CLIENT_IP}"
        fi
    else
        WHTLST_IPS=""
    fi

    read -p "Use your public SSH key instead of password-based authentication? You'll need to paste your SSH key at the end of this setup so that the server lets you in next time you connect. [Y/n]: " nopass_Yn
    if [ "${nopass_Yn}" = "" ] || [ "${nopass_Yn}" = "Y" ]; then
        nopass_Yn="y"
    fi

    read -p "Disable direct root login? Using a non-root account and switching to root only when needed is more secure. Choosing 'n' will keep the direct root login [Y/n]: " noroot_Yn
    if  [ "${noroot_Yn}" = "Y" ] || [ "${noroot_Yn}" = "" ]; then
        noroot_Yn="y"
    fi
    if [ "${noroot_Yn}" = "y" ]; then
        read -p "SSH non-root user [${SSH_USER_DEFAULT}]: " SSH_USER
        if [ "$SSH_USER" = "" ]; then
            SSH_USER=$SSH_USER_DEFAULT
        fi
        report_append "SSH_USER" $SSH_USER
    fi

    read -p "SSH port [default=${PORT_SSH_DEFAULT}]: " PORT_SSH
    if [ "$PORT_SSH" = "" ]; then
        PORT_SSH=$PORT_SSH_DEFAULT
    fi
    report_append "PORT_SSH" $PORT_SSH

    read -p "FTP port, or '0' to skip [${PORT_FTP_DEFAULT}]: " PORT_FTP
    if [ "$PORT_FTP" = "" ]; then
        PORT_FTP=$PORT_FTP_DEFAULT
    fi

    if [ ! "$PORT_HTTP" = "0" ] && [ ! -d $WWW_ROOT ]; then
        mkdir $WWW_ROOT
    fi

    if [ ! "$PORT_FTP" = "0" ]; then
        wdpasswordg=`random_string -l 16`
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

    read -p "MySQL port, or '0' to skip [${PORT_MYSQL_DEFAULT}]: " PORT_MYSQL
    if [ "$PORT_MYSQL" = "" ]; then
        PORT_MYSQL=$PORT_MYSQL_DEFAULT
    fi

    if [ ! "$PORT_MYSQL" = "0" ]; then
        MYSQL_ROOT_PASS=`random_string -l 16`
        MYSQL_REMO_USER_RAND=`random_string -l 16`
        MYSQL_REMO_PASS_RAND=`random_string -l 16`
        read -p "MySQL remote access user name [${MYSQL_REMO_USER_RAND}]: " MYSQL_REMO_USER
        if [ "$MYSQL_REMO_USER" = "" ]; then
            MYSQL_REMO_USER=${MYSQL_REMO_USER_RAND}
        fi
        read -p "MySQL password for that user [${MYSQL_REMO_PASS_RAND}]: " MYSQL_REMO_PASS
        if [ "$MYSQL_REMO_PASS" = "" ]; then
            MYSQL_REMO_PASS=${MYSQL_REMO_PASS_RAND}
        fi
        report_append "PORT_MYSQL" $PORT_MYSQL
        report_append "MYSQL_ROOT_PASS" $MYSQL_ROOT_PASS
        report_append "MYSQL_REMO_USER" $MYSQL_REMO_USER
        report_append "MYSQL_REMO_PASS" $MYSQL_REMO_PASS
    else
        echo "**** MySQL SKIPPED"
    fi

    echo "**** All set. No further user input required."

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

    do_install ca-certificates
    do_install wget

    debian_version=`cat /etc/debian_version | sed -r 's/\..*//'`
    debian_codename=$(lsb_release -sc)
    cat /dev/null > /etc/apt/sources.list
    echo "deb http://httpredir.debian.org/debian ${debian_codename} main contrib non-free" >> /etc/apt/sources.list
    echo "deb http://httpredir.debian.org/debian ${debian_codename}-backports main contrib non-free" >> /etc/apt/sources.list
    echo "deb http://security.debian.org/ ${debian_codename}/updates main contrib non-free" >> /etc/apt/sources.list
    if [ ! "$PORT_HTTP" = "0" ]; then
        echo "deb http://nginx.org/packages/debian/ ${debian_codename} nginx" >> /etc/apt/sources.list
        echo "deb-src http://nginx.org/packages/debian/ ${debian_codename} nginx" >> /etc/apt/sources.list
        wget https://nginx.org/keys/nginx_signing.key -O - | apt-key add -
    fi
    for k in $(apt-get update 2>&1|grep -o NO_PUBKEY.*|sed 's/NO_PUBKEY //g');do echo "key: $k";gpg --recv-keys $k;gpg --recv-keys $k;gpg --armor --export $k|apt-key add -;done

    cat >> /root/.bash_profile << EOF
alias grep="grep --color=auto"
# http://superuser.com/a/664061/111289
export HISTFILESIZE=
export HISTSIZE=
export HISTTIMEFORMAT="[%F %T] "
export HISTFILE=~/.bash_eternal_history
PROMPT_COMMAND="history -a; $PROMPT_COMMAND"
EOF

    apt-get update # has to be here, even if it fails
    apt-get install -y debian-keyring 
    apt-get install -y debian-archive-keyring
    apt-get update
    apt-get install -y dialog
    apt-get -y upgrade


    do_install build-essential
    #do_install gcc
    do_install coreutils
    do_install apt-utils
    do_install iptables
    do_install make
    do_install sed
    do_install cron
    do_install systemd
    do_install curl
    do_install easy-rsa
    do_install logrotate
    do_install ntp
    do_install tzdata
    echo "UTC" > /etc/timezone
    dpkg-reconfigure -f noninteractive tzdata
    do_install unattended-upgrades
    dpkg-reconfigure -f noninteractive unattended-upgrades
    do_install fail2ban

    #do_install libpcre3-dev
    #do_install zlib1g-dev
    do_install git
    if [ ! "$PORT_HTTP" = "0" ]; then
        do_install nginx
    fi
    if [ ! "$PORT_FTP" = "0" ]; then
        do_install inetutils-ftpd
    fi
    if [ ! "$PORT_MYSQL" = "0" ]; then
        do_install mariadb-server
        systemctl enable mariadb
        service mysql stop
    fi

    if [ ! "${PHP_VER}" = "0" ]; then
        # installing PHP and it's modules
        do_install php${PHP_VER}*-common
        do_install php${PHP_VER}*-cli
        do_install php${PHP_VER}*-fpm
        do_install php${PHP_VER}*-mysql
        do_install php${PHP_VER}*-curl
        do_install php${PHP_VER}*-gd
        do_install php${PHP_VER}*-mcrypt
        do_install php${PHP_VER}*-intl
        do_install php${PHP_VER}*-json
        do_install php${PHP_VER}*-bcmath
        do_install php${PHP_VER}*-imap
        do_install php${PHP_VER}*-mbstring
        do_install php${PHP_VER}*-xml
        do_install php${PHP_VER}*-opcache
    fi

# initial fail2ban jail configuration
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
findtime = 1w
bantime = 1w
banaction = iptables-multiport
banaction_allports = iptables-allports
ignoreip = ${WHTLST_IPS}
EOF

# nginx configuration
CPU_CORES_CNT=`nproc --all`
ULIMIT=`ulimit -n`
if [ ! "$PORT_HTTP" = "0" ]; then
    if [ ! -d "/etc/nginx/sites-enabled" ]; then
        mkdir "/etc/nginx/sites-enabled"
    fi
    if [ ! -d "/etc/nginx/sites-available" ]; then
        mkdir "/etc/nginx/sites-available"
    fi
    if [ ! -d "/etc/nginx/snippets" ]; then
        mkdir "/etc/nginx/snippets"
    fi
    if [ -e "/etc/nginx/sites-enabled/default" ]; then
        rm "/etc/nginx/sites-enabled/default"
    fi
    if [ -e "/etc/nginx/conf.d/default.conf" ]; then
        rm "/etc/nginx/conf.d/default.conf"
    fi

    cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes ${CPU_CORES_CNT};
pid /var/run/nginx.pid;
events {
    worker_connections ${ULIMIT};
    use epoll;
    multi_accept on;
}
http {
    limit_req_zone \$binary_remote_addr zone=byip:64m rate=4r/s;
    server_names_hash_bucket_size 128;
    client_max_body_size 32m;
    include mime.types;
    default_type application/octet-stream;
    charset utf-8;
    sendfile on;
    keepalive_timeout 65;
    server_tokens off;
    server {
        server_name _;
        listen 80 default_server;
        #todo: add https support
        #listen 443 default_server;
        #ssl_certificate /etc/nginx/00-default.crt;
        #ssl_certificate_key /etc/nginx/00-default.key;
        return 444;
    }
    gzip on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_min_length 256;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript application/x-javascript application/vnd.ms-fontobject application/x-font-ttf font/opentype image/svg+xml image/x-icon application/x-font-opentype application/x-font-truetype font/eot font/otf image/vnd.microsoft.icon;
    include snippets/suspicious.conf;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    if [ ! -e "/etc/nginx/snippets/fastcgi-php.conf" ]; then
        cat > /etc/nginx/snippets/fastcgi-php.conf << EOF
# regex to split \$uri to \$fastcgi_script_name and \$fastcgi_path
fastcgi_split_path_info ^(.+\.php)(/.+)\$;

# Check that the PHP script exists before passing it
try_files \$fastcgi_script_name =404;

# Bypass the fact that try_files resets \$fastcgi_path_info
# see: http://trac.nginx.org/nginx/ticket/321
set \$path_info \$fastcgi_path_info;
fastcgi_param PATH_INFO \$path_info;

fastcgi_index index.php;
include fastcgi_params;
EOF
    fi

    PHP_SOCK_PATH=$(grep -iR "\.sock" /etc/php | awk -F "= " '{print $2}')
    cat > /etc/nginx/snippets/common.conf << EOF
index index.php index.html index.htm;
location ~ \.php {
    if (\$suspicious = 1) {
        access_log /var/log/nginx/suspicious.log suslog;
        return 500;
    }
    limit_req zone=byip burst=4;
    include snippets/fastcgi-php.conf;
    keepalive_timeout 0;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    fastcgi_pass unix:${PHP_SOCK_PATH};
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
location ~* \.(ini)\$ {
    return 404;
}
location ~ /\.well-known { 
    allow all;
}
location ~ /\. {
    deny all;
}
EOF

    cat > /etc/nginx/snippets/suspicious.conf << 'EOF'
# poor man's WAF
map "$request_uri $http_referer $http_user_agent $http_cookie" $suspicious {
    default 0;
    "~127\.0\.0\.1" 1;
    "~(\.\./)+" 1;
    "~*(<|%3c)\?" 1;
    "~*\?(>|%3e)" 1;
    "~_(SERVER|GET|POST|FILES|REQUEST|SESSION|ENV|COOKIE)\[" 1;
    "~*(\\x|%)(3c|3e|5c|22|27)+" 1;
    "~*(un)?hex\(" 1;
    "~*base64_(en|de)code" 1;
    "~*file_(put|get)_contents" 1;
    "~*call_user_func_array" 1;
    "~*(mb_)?ereg_replace" 1;
    "~*char(.*)?(\(|%28)" 1;
    "~*concat(.*)?(\(|%28)" 1;
    "~*eval(.*)?(\(|%28)" 1;
    "~*(union(.*))?select(.*)from" 1;
    "~*union(.*)select((.*)from)?" 1;
}
log_format suslog '$remote_addr - $remote_user $host [$time_local] '
    '"$request" $status $body_bytes_sent '
    '"$http_referer" "$http_user_agent"';
EOF

    # configure fail2ban for poor man's nginx waf
    NW_PREF="nginx-custom-waf"
    cat > "/etc/fail2ban/filter.d/${NW_PREF}.conf" << 'EOF'
[Definition]

failregex = ^<HOST> (.*)?$

ignoreregex =
EOF
    cat > "/etc/fail2ban/action.d/${NW_PREF}-log.conf" << 'EOF'
[Definition]

actionban = grep -iR "<ip>" /var/log/nginx > "/var/log/nginx-attacks/<ip>.log"

ignoreregex =
EOF
    cat >> /etc/fail2ban/jail.local << EOF
[${NW_PREF}]
enabled = true
filter = ${NW_PREF}
action = iptables-allports
         ${NW_PREF}-log
maxretry = 4
logpath = /var/log/nginx/suspicious.log
EOF
    mkdir /var/log/nginx-attacks

service nginx start
fi

if [ ! "${PHP_VER}" = "0" ]; then
    curl -sS https://getcomposer.org/installer -o "$WWW_ROOT/composer.phar"
    php "$WWW_ROOT/composer.phar"
fi

if [ ! "$PORT_MYSQL" = "0" ]; then
    sed -i "s/^#port/port/g" /etc/mysql/mariadb.conf.d/50-server.cnf
    sed -i "s/= 3306/= ${PORT_MYSQL}/g" /etc/mysql/mariadb.conf.d/50-server.cnf
    sed -i "s/= 127.0.0.1/= $(hostname -i)/g" /etc/mysql/mariadb.conf.d/50-server.cnf
    service mysql start
    mysqladmin -u root password "${MYSQL_ROOT_PASS}"
    mysql -uroot -p${MYSQL_ROOT_PASS} -e "CREATE USER '${MYSQL_REMO_USER}'@'%' IDENTIFIED BY '${MYSQL_REMO_PASS}';"
    mysql -uroot -p${MYSQL_ROOT_PASS} -e "GRANT ALL PRIVILEGES ON *.* TO '${MYSQL_REMO_USER}'@'%' WITH GRANT OPTION;"
fi

if [ ! "$PORT_HTTP" = "0" ]; then
    cat > ${HOSTMANAGER_PATH} << GAHEOF
#!/bin/sh

### Checking for user
if [ "\$(whoami)" != 'root' ]; then
    echo "You have no permission to run \$0 as a non-root user."
    exit 1;
fi

### Script params
www_root="$WWW_ROOT"
ftp_user="$FTP_USER"
if ! [ id -u "\$ftp_user" >/dev/null 2>&1 ]; then
    ftp_user="www-data"
fi
nginx_conf_dir="/etc/nginx"
sites_available="\${nginx_conf_dir}/sites-available"
sites_enabled="\${nginx_conf_dir}/sites-enabled"
mysql="\$(which mysql)"
# mysql root password
mysql_password="$MYSQL_ROOT_PASS"
mysql_admin="$MYSQL_REMO_USER"
mysql_admin_password="$MYSQL_REMO_PASS"

### Functions
random_string() {
    if [ \$1="-l" ]; then
            length=\$2
        else
            length="8"
        fi
    echo \`cat /dev/urandom | tr -dc "a-zA-Z0-9" | fold -w \$length | head -1\`
}
restart_nginx() {
    if [ -e /var/run/nginx.pid ];
        then
            command='restart'
        else
            command='start'
        fi
    service nginx \$command
}
add_alias() {
    aliases=\$aliases" "\$1
    read -p "Enter another alias (leave blank to skip): " newalias
    if [ "\$newalias" != "" ]; then
        ### loop
        add_alias \$newalias
    fi
}

nginx_vhost_conf_name() {
    echo "vhost-\${1}.conf"
}
create_nginx_host() {
    # \$1=hostname; \$2=aliases; \$3=public_dir; \$4=config_dir; \$5=certbot_path_opt
    conf_file_name=\`nginx_vhost_conf_name \${1}\`
    if [ ! -z "\${2}" ]; then
    cat >> "\${sites_available}/\${conf_file_name}" << EOF
    server {
        listen 80;
        server_name \$2;
        return 301 http://\$1\\\$request_uri;
    }
EOF
    fi
    cat >> "\${sites_available}/\${conf_file_name}" << EOF
    server {
        listen 80;
        server_name \$1;
        access_log /var/log/nginx/\$1.access.log;
        error_log /var/log/nginx/\$1.error.log;
        root \$3; # config_path \$4
        include "snippets/common.conf";
        include "\$4/.ngaccess";
    }
EOF
    if ! [ -f "\${sites_enabled}/\${conf_file_name}" ]; then
        ln -s "\${sites_available}/\${conf_file_name}" "\${sites_enabled}/\${conf_file_name}"
    fi
    if [ ! "\$5" = "" ] && [ -f "\$5" ]; then
        restart_nginx # restart so the host goes live and is verifiable
        domains="\$1"
        for alias in \$2; do
            domains="\${domains},\${alias}"
        done
        letsencrypt_email="webmaster@\$1"
        printf "Requesting a certificate from Let's Encrypt:\n"
        printf " - email:   \${letsencrypt_email}\n"
        printf " - webroot: \$3\n"
        printf " - domains: \${domains}\n"
        \$5 certonly --non-interactive --agree-tos --email "\${letsencrypt_email}" --webroot -w "\$3" -d "\${domains}"
        openssl dhparam -out /etc/letsencrypt/live/\$1/dhparam.pem 2048
        # cut -2 lines from the end of file (.ngaccess inclusion and closing bracket)
        # so that we can later append further configuration to this directive
        head -n -2 "\${sites_available}/\${conf_file_name}" > "\${sites_available}/\${conf_file_name}.tmp"
        mv "\${sites_available}/\${conf_file_name}.tmp" "\${sites_available}/\${conf_file_name}"
        cat >> "\${sites_available}/\${conf_file_name}" << EOF
        location / {
            return 301 https://\\\$server_name\\\$request_uri;
        }
        location /.well-known/acme-challenge/ {}
    }
EOF
if [ ! -z "\${2}" ]; then
    cat >> "\${sites_available}/\${conf_file_name}" << EOF
    server {
        listen 443 ssl;
        server_name \$2;
        ssl on;
        ssl_certificate /etc/letsencrypt/live/\$1/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/\$1/privkey.pem;
        ssl_dhparam /etc/letsencrypt/live/\$1/dhparam.pem;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:50m;
        ssl_stapling on;
        ssl_stapling_verify on;
        add_header Strict-Transport-Security max-age=15768000;
        return 301 https://\$1\\\$request_uri;
    }
EOF
fi
cat >> "\${sites_available}/\${conf_file_name}" << EOF
    server {
        listen 443 ssl;
        server_name \$1;
        access_log /var/log/nginx/\$1.access.log;
        error_log /var/log/nginx/\$1.error.log;
        root \$3;
        include "\$4/.ngaccess";
        include "snippets/common.conf";
        ssl on;
        ssl_certificate /etc/letsencrypt/live/\$1/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/\$1/privkey.pem;
        ssl_dhparam /etc/letsencrypt/live/\$1/dhparam.pem;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:50m;
        ssl_stapling on;
        ssl_stapling_verify on;
        add_header Strict-Transport-Security max-age=15768000;
        location /.well-known/acme-challenge/ {
            return 301 http://\\\$server_name\\\$request_uri;
        }
    }
EOF
        restart_nginx 
    fi
}
add() {
    read -p "Add www.\$1? [Y/n]: " WWW_Yn
    if [ "\${WWW_Yn}" = "" ] || [ "\${WWW_Yn}" = "Y" ] || [ "\${WWW_Yn}" = "y" ]; then
        aliases="www.\$1"
    fi
    read -p "Install LetsEncrypt SSL? [Y/n]: " SSL_Yn
    CERTBOT_PATH_OPT=""
    if [ "\${SSL_Yn}" = "" ] || [ "\${SSL_Yn}" = "Y" ] || [ "\${SSL_Yn}" = "y" ]; then
        CERTBOT_PATH_OPT="${CERTBOT_PATH}"
    fi
    public_dir_name_default="public_html"
    database_name_random=\`echo \$1 | sed -e 's/\W//g'\`;
    database_user_random=\`random_string -l 16\`
    database_password_waitforit_random=\`random_string -l 16\`
    if [ -z \$4 ]; then
        read -p "Enter alias (leave blank to skip): " alias
        if [ "\$alias" != "" ] && [ "\$alias" != "n" ] && [ "\$alias" != "N" ]; then
            add_alias \$alias
        fi
    else
        if [ \$4 != "N" ] && [ \$4 != "n" ]; then
            aliases=\$aliases" "\$4
        fi
    fi
    if [ -z \$2 ]; then
        site_dir=\$www_root
        read -p "Enter site directory NAME (\$site_dir/[> \$1 <]): " site_dir_name
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
        wdpasswordg=\`random_string -l 16\`
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
            echo \$site_dir" OK"
            if [ "\$create_public_dir" = "y" ] || [ "\$create_public_dir" = "Y" ]
                then
                    public_dir=\$site_dir"/"\$public_dir_name_default
                    mkdir \$public_dir
                    chown \$ftp_user:www-data \$public_dir
                else
                    public_dir=\$site_dir
            fi
        fi
    ngaccess_file="\${site_dir}/.ngaccess"
    echo -n ".ngaccess file... "
    if ! [ -f \$ngaccess_file ]
        then
            if ! touch \$ngaccess_file
                then
                    echo "ERROR (creating)."
                else
                    if ! echo "#this is the part of the main nginx config
location / {
    try_files \\\$uri \\\$uri/ /index.php?\\\$args;
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
    echo "# FTP p:${PORT_FTP} u:\${website_user} p:\${wdpassword}" >> \${ngaccess_file}
    chown -R \${website_user}:www-data \${site_dir}
    create_nginx_host "\$1" "\${aliases}" "\${public_dir}" "\${site_dir}" "\${CERTBOT_PATH_OPT}"
    #for alias in \$aliases; do
    #    create_nginx_host \$alias \${public_dir} \${site_dir} \${CERTBOT_PATH_OPT}
    #done

    ### MySQL
    if [ "\$create_database" != "n" ] && [ "\$create_database"!="N" ]
        then
            \$mysql -uroot -p\$mysql_password -e "CREATE DATABASE \\\`\$database_name\\\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
            \$mysql -uroot -p\$mysql_password -e "GRANT CREATE,SELECT,INSERT,UPDATE,DELETE ON \$database_name.* TO \$database_user@localhost IDENTIFIED BY '\$database_password';"
            \$mysql -uroot -p\$mysql_password -e "GRANT ALL ON \$database_name.* TO \$mysql_admin@localhost IDENTIFIED BY '\$mysql_admin_password';"
            printf "Database:\n-name: \$database_name\n-user: \$database_user\n-pass: \$database_password\n"
            echo -n "Config file... "
            config_file=\$site_dir"/config_spanel.php"
            if ! touch \$config_file
                then
                    echo "ERROR (creating)."
                else
                    if ! printf "<?php\\n\\\$mysql=array();\\n\\\$mysql['host']='localhost';\\n\\\$mysql['name']='\$database_name';\\n\\\$mysql['user']='\$database_user';\\n\\\$mysql['pass']='\$database_password';\\n" > \$config_file
                        then
                            echo "ERROR (writing)."
                        else
                            echo "done."
                        fi
                fi
        fi
}
remove_nginx_host() {
    # \$1=hostname;
    conf_file_name=\`nginx_vhost_conf_name \${1}\`
    if [ -f "\${sites_enabled}/\${conf_file_name}" ]; then
        rm "\${sites_enabled}/\${conf_file_name}"
    fi
    if [ -f "\${sites_available}/\${conf_file_name}" ]; then
        rm "\${sites_available}/\${conf_file_name}"
    fi
    if [ -d "/etc/letsencrypt/live/\${1}" ]; then
        rm -rf "/etc/letsencrypt/live/\${1}"
    fi
    if [ -d "/etc/letsencrypt/archive/\${1}" ]; then
        rm -rf "/etc/letsencrypt/archive/\${1}"
    fi
}

remove() {
    conf_file_name=\`nginx_vhost_conf_name \${1}\`
    config_nginx="\${sites_available}/\${conf_file_name}"
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
            remove_nginx_host \$1
        else
            echo "Can't find the config file \$config_nginx"
        fi
}

certbot_update_all() {
    ${CERTBOT_PATH} renew
    (sleep 3600 && service nginx restart)&
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
    case \$1 in
        "add" | "a" | "-a")
            action="add"
            ;;
        "remove" | "r" | "-r")
            action="remove"
            ;;
        *)
            action="\$1"
            ;;
    esac
    hostname="\$2"
fi;

echo "ACTION: \${action}"
### What to do?
case "\$action" in
    "remove")
        if [ "\$hostname" = "" ]; then
            echo "Please specify the primary hostname"
            exit 1;
        fi
        remove \$hostname
        restart_nginx
        ;;
    "add")
        if [ "\$hostname" = "" ]; then
            echo "Please specify the primary hostname"
            exit 1;
        fi
        add \$hostname \$dirname \$database \$alias
        restart_nginx
        ;;
    "certupdate")
        certbot_update_all
        ;;
    *)
        echo "**** USAGE:"
        echo "spanel [add|remove] example.com"
        exit 1;
        ;;
esac

GAHEOF
chmod +x ${HOSTMANAGER_PATH}
echo "alias spanel='sh ${HOSTMANAGER_PATH}'" >> /etc/bash.bashrc
fi

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
service inetutils-ftpd start
update-rc.d inetutils-ftpd defaults
fi

if [ "${LECertbot_Yn}" = "" ] ||  [ "${LECertbot_Yn}" = "Y" ] || [ "${LECertbot_Yn}" = "y" ]; then
    # install certbot for letsencrypt
    # https://certbot.eff.org/all-instructions/#web-hosting-service-nginx
    wget -O ${CERTBOT_PATH} https://dl.eff.org/certbot-auto
    chmod a+x ${CERTBOT_PATH}
    ${CERTBOT_PATH} --non-interactive
    echo "0 4 1,15 * * root ${HOSTMANAGER_PATH} certupdate >> /var/log/certupdate.log 2>&1" > /etc/cron.d/certupdate
fi

echo "Updating SSH configuration"
# Update the SSH port
sed -i "s/#Port/Port/g" /etc/ssh/sshd_config
sed -i "s/Port 22/Port $PORT_SSH/g" /etc/ssh/sshd_config
# Log More Information - help.ubuntu.com/community/SSH/OpenSSH/Configuring
sed -i "s/LogLevel INFO/LogLevel VERBOSE/g" /etc/ssh/sshd_config
# Disable empty passwords
sed -i "s/#PermitEmptyPasswords/PermitEmptyPasswords/g" /etc/ssh/sshd_config
sed -i "s/PermitEmptyPasswords yes/PermitEmptyPasswords no/g" /etc/ssh/sshd_config
# Disable X11Forwarding
sed -i "s/#X11Forwarding/X11Forwarding/g" /etc/ssh/sshd_config
sed -i "s/X11Forwarding yes/X11Forwarding no/g" /etc/ssh/sshd_config
# Set MaxAuthTries to 4 (https://superuser.com/a/1180018)
sed -i 's/^ *# *MaxAuthTries *[^ ]*/MaxAuthTries 4/' /etc/ssh/sshd_config
if [ "${noroot_Yn}" = "y" ]; then
    DIR_HOME="/home/${SSH_USER}"
    # Disable root login
    sed -i "s/#PermitRootLogin/PermitRootLogin/g" /etc/ssh/sshd_config
    sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
    # Whitelist the non-SSH user
    echo "AllowUsers ${SSH_USER}" >> /etc/ssh/sshd_config
    useradd -md "${DIR_HOME}" -g sudo $SSH_USER
    usermod -a -G www-data ${SSH_USER}
    if [ -d "${WWW_ROOT}" ]; then
        chown -R ${SSH_USER}:www-data "${WWW_ROOT}"
    fi
else
    DIR_HOME="/root"
fi
if [ "${nopass_Yn}" = "y" ]; then
    # Disable password authentication
    sed -i "s/#PasswordAuthentication/PasswordAuthentication/g" /etc/ssh/sshd_config
    sed -i "s/PasswordAuthentication yes/PasswordAuthentication no/g" /etc/ssh/sshd_config
    # Enable key-based authentication
    sed -i "s/#PubkeyAuthentication/PubkeyAuthentication/g" /etc/ssh/sshd_config
    sed -i "s/PubkeyAuthentication no/PubkeyAuthentication yes/g" /etc/ssh/sshd_config
    mkdir -p "${DIR_HOME}/.ssh"
    read -p "Please paste your public key here: " SSH_USER_PUBKEY
    echo ${SSH_USER_PUBKEY} > "${DIR_HOME}"/.ssh/authorized_keys
fi
# https://infosec-handbook.eu/blog/wss1-basic-hardening/#s3
echo "" >> /etc/ssh/sshd_config
sed -i '/^KexAlgorithms /d' /etc/ssh/sshd_config
sed -i '/^Ciphers /d' /etc/ssh/sshd_config
sed -i '/^MACs /d' /etc/ssh/sshd_config
sed -i '/^HostKeyAlgorithms /d' /etc/ssh/sshd_config
cat << EOF >> /etc/ssh/sshd_config
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-256,rsa-sha2-512,ssh-rsa-cert-v01@openssh.com
EOF
ssh-keygen -A

# configure fail2ban for sshd
SSH_MAXRETRY=4
if [ "${nopass_Yn}" = "y" ]; then
    # lower the tolerance for failed attempts if no password is used
    SSH_MAXRETRY=2
fi
cat >> /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
mode = aggressive
port = ${PORT_SSH}
filter = sshd
maxretry = ${SSH_MAXRETRY}
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF

iptables -F

# if SSH uses port other than 22, add a honeypot
if [ ! "${PORT_SSH}" = "22" ]; then
    HP_PREF="sshd-honeypot"
    iptables -A INPUT -p tcp  --dport 22 -j LOG --log-prefix="${HP_PREF} "
    cat > "/etc/rsyslog.d/00-${HP_PREF}.conf" << EOF
:msg,contains,"${HP_PREF} " -/var/log/${HP_PREF}.log
& ~
EOF
    cat > "/etc/fail2ban/filter.d/${HP_PREF}.conf" << EOF
[Definition]

failregex = ${HP_PREF} .* SRC=<HOST>

ignoreregex =
EOF
    cat >> /etc/fail2ban/jail.local << EOF
[${HP_PREF}]
enabled = true
filter = ${HP_PREF}
maxretry = 1
logpath = /var/log/${HP_PREF}.log
EOF
    service rsyslog restart
fi;

# configure iptables with whitelisted IP addresses, if any
if [ -n "${WHTLST_IPS}" ]; then
    WHTLST_PORTS="${PORT_SSH} ${PORT_FTP} ${PORT_MYSQL}"
    for WL_PORT in ${WHTLST_PORTS}; do
        for WL_IP in ${WHTLST_IPS}; do
            iptables -A INPUT -p tcp --dport ${WL_PORT} -s ${WL_IP} -j ACCEPT
            iptables -A OUTPUT -p tcp --sport ${WL_PORT} -d ${WL_IP} -j ACCEPT
        done
        iptables -A INPUT -p tcp --dport ${WL_PORT} -j DROP
        iptables -A OUTPUT -p tcp --sport ${WL_PORT} -j DROP
    done
fi
iptables-save > /etc/iptables.conf
cat > /etc/network/if-up.d/iptables << EOF
#!/bin/sh
iptables-restore < /etc/iptables.conf
EOF
chmod +x /etc/network/if-up.d/iptables 

apt-get -y autoremove
rm $0

echo "**** All done."
echo "**** Reminder: the new SSH port is: ${PORT_SSH}"
echo "     (make sure to allow it with your AWS/GCP/etc. firewall)"
echo "**** The server will reboot."

reboot
}

case "$1" in
    install)
        install
        ;;
    *)
        read -p "Using this is your own risk and responsibility. [Y/n]: " inststart
        if [ "${inststart}" != "N" ] && [ "${inststart}" != "n" ]; then
            install
        else
            echo "Aborted."
        fi
        ;;
esac
