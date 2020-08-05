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
CERTBOT_PATH="/usr/local/bin/certbot-auto"
HOSTMANAGER_PATH="/root/spanel.sh"
SSH_CLIENT_IP=$(who -m --ips | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}')

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
        header "Installing ${1}"
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
        header "Purging ${1}"
        service $1 stop
        apt-get purge -s -y $DEL
    fi
}

report_append()  {
    echo "$1=$2" >> ~/.bonjour.ini
}

HEADERS=0
header() {
    printf "\n\n"
    echo "**** ${SESSION_ID}/${HEADERS} [$(date +%T.%N%z)] ${1}"
    HEADERS=$((HEADERS+1))
}




install() {
    SESSION_ID=$(random_string -l 4)
    # start the config
    report_append "WWW_ROOT" $WWW_ROOT
    report_append "CERTBOT_PATH" $CERTBOT_PATH

    echo ""
    echo "Receive security notifications and alerts (SSH, fail2ban)?"
    read -p "Enter an e-mail address, or leave empty to skip: " ALERTEMAIL

    read -p "Install Nginx? [Y/n]: " NGINX_Yn
    if [ "${NGINX_Yn}" = "" ] ||  [ "${NGINX_Yn}" = "Y" ] || [ "${NGINX_Yn}" = "y" ]; then
        PORT_HTTP="80"
    else 
        PORT_HTTP="0"
    fi
    read -p "Install PHP? [Y/n]: " PHP_Yn
    if [ "${PHP_Yn}" = "" ] ||  [ "${PHP_Yn}" = "Y" ] || [ "${PHP_Yn}" = "y" ]; then
        PHP_VER="7"
        read -p "Expected size of a single PHP process, in MB [64]: " PHP_PSZ
        if [ -z "${PHP_PSZ}" ]; then
            PHP_PSZ="64"
        fi
    else 
        PHP_VER="0"
    fi

    LECertbot_Yn="n"
    if [ ! "$PORT_HTTP" = "0" ]; then
        read -p "Install the Let's Encrypt Certbot? [Y/n]: " LECertbot_Yn
    fi

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
    report_append "SSH_PORT" $PORT_SSH

    read -p "FTP port, or '0' to skip [${PORT_FTP_DEFAULT}]: " PORT_FTP
    if [ "$PORT_FTP" = "" ]; then
        PORT_FTP=$PORT_FTP_DEFAULT
    fi

    if [ ! "$PORT_HTTP" = "0" ] && [ ! -d $WWW_ROOT ]; then
        mkdir $WWW_ROOT
    fi
    if [ -d "${WWW_ROOT}" ]; then
        chgrp -R www-data "${WWW_ROOT}"
        chmod g+s "${WWW_ROOT}"
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
            chown $FTP_USER $WWW_ROOT
        fi
        report_append "FTP_PORT" $PORT_FTP
        report_append "FTP_USER" $FTP_USER
        report_append "FTP_PASS" $wdpassword
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
        report_append "MYSQL_PORT" $PORT_MYSQL
        report_append "MYSQL_ROOT_PASS" $MYSQL_ROOT_PASS
        report_append "MYSQL_REMO_USER" $MYSQL_REMO_USER
        report_append "MYSQL_REMO_PASS" $MYSQL_REMO_PASS
    else
        echo "**** MySQL SKIPPED"
    fi

    header "Starting."

    #build-essentials = c++

    header "Deleting pre-installed packages"
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

    header "Installing requirements"
    do_install apt-transport-https
    do_install ca-certificates
    do_install wget
    do_install gnupg
    do_install gnupg2
    do_install lsb-release
    do_install dialog

    header "Updating sources.list"
    debian_codename=$(lsb_release -sc)
    if [ -z "${debian_codename}" ]; then
        echo "Failed to get the Debian version codename using lsb_release"
        exit 1
    fi
    cat /dev/null > /etc/apt/sources.list
    echo "deb http://httpredir.debian.org/debian ${debian_codename} main contrib non-free" >> /etc/apt/sources.list
    echo "deb http://httpredir.debian.org/debian ${debian_codename}-backports main contrib non-free" >> /etc/apt/sources.list
    echo "deb http://security.debian.org/ ${debian_codename}/updates main contrib non-free" >> /etc/apt/sources.list
    if [ ! "$PORT_HTTP" = "0" ]; then
        header "Adding Nginx repository to sources.list"
        echo "deb http://nginx.org/packages/debian/ ${debian_codename} nginx" >> /etc/apt/sources.list
        echo "deb-src http://nginx.org/packages/debian/ ${debian_codename} nginx" >> /etc/apt/sources.list
        wget https://nginx.org/keys/nginx_signing.key -O - | apt-key add -
    fi
    debian_release=$(printf "%.0f\n" $(lsb_release -sr)) # truncate to major ver
    if [ "${debian_release}" = "8" ]; then
        wget -q https://packages.sury.org/php/apt.gpg -O- | apt-key add -
        echo "deb https://packages.sury.org/php/ ${debian_codename} main" >> /etc/apt/sources.list
    fi
    header "Adding pubkeys"
    for k in $(apt-get update 2>&1|grep -o NO_PUBKEY.*|sed 's/NO_PUBKEY //g');do echo "key: $k";gpg --recv-keys $k;gpg --recv-keys $k;gpg --armor --export $k|apt-key add -;done

    cat >> /root/.bash_profile << 'EOF'
alias grep="grep --color=auto"
# https://superuser.com/questions/137438/664061#664061
export HISTFILESIZE=
export HISTSIZE=
export HISTTIMEFORMAT="[%F %T] "
export HISTFILE=~/.bash_eternal_history
PROMPT_COMMAND="history -a; $PROMPT_COMMAND"
EOF

    header "Installing keyrings"
    apt-get update # has to be here, even if it fails
    do_install debian-archive-keyring
    apt-get update

    header "Upgrading"
    apt-get -y upgrade

    header "Installing core software"
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
    do_install vim
    do_install unzip
    do_install bc
    do_install cfget
    do_install easy-rsa
    do_install logrotate
    do_install ntp
    do_install tzdata
    do_install python3-gi # fix "Unable to monitor PrepareForShutdown() signal"
    do_install git
    do_install fail2ban
    do_install dnsutils
    do_install whois
    if [ -n "${ALERTEMAIL}" ]; then
        do_install nullmailer
    fi
    do_install rush
    do_install rsync
    header "Installing and configuring unattended-upgrades"
    do_install unattended-upgrades
    dpkg-reconfigure -f noninteractive unattended-upgrades

    #do_install libpcre3-dev
    #do_install zlib1g-dev
    if [ ! "$PORT_HTTP" = "0" ]; then
        header "Installing Nginx"
        do_install nginx
    fi
    if [ ! "$PORT_FTP" = "0" ]; then
        header "Installing FTP (inetutils)"
        do_install inetutils-ftpd
    fi
    if [ ! "$PORT_MYSQL" = "0" ]; then
        header "Installing MariaDB"
        do_install mariadb-server
        systemctl enable mariadb
        service mysql stop
    fi

    if [ ! "${PHP_VER}" = "0" ]; then
        header "Installing PHP and it's modules"
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
        do_install php${PHP_VER}*-zip
    fi
    header "Configuring the software"
    # set the timezone
    timedatectl set-timezone UTC
    # disable the mouse input in vim visual mode
    DEFAULTSVIM=$(find /usr -path "*/vim/*" -type f -name "defaults.vim")
    sed -i "s/^\"* *set mouse[^$]*/set mouse-=a/" "${DEFAULTSVIM}"

    # configure rush to only allow rsync restricted to WWW_ROOT
    cat > /etc/rush.rc << EORUSHRC
debug 1
rule allow-rsync
  command ^rsync --server [^/]* ${WWW_ROOT}\$
  set[0] /usr/bin/rsync
  transform[\$] s|[\\\.]{2,}||g
  transform[\$] s|[%]+||g
  chdir ${WWW_ROOT}
rule trap
  command ^.*
  # keep the trailing space below
  exit 
EORUSHRC

    # initial fail2ban jail configuration
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
findtime = 1w
bantime = 1w
banaction = iptables-multiport
banaction_allports = iptables-allports
ignoreip = ${WHTLST_IPS}
EOF

if [ -n "${ALERTEMAIL}" ]; then
    header "Setting up alerts"
    report_append "ALERT_EMAIL" $ALERTEMAIL
    # below is a way to avoid installing sendmail, exim, postfix, etc.
    # nullmailer is lightweight, but relay only; lets relay right to target MX
    # parse out recipient's email hostname
    ALERTEMAILHOST=$(echo "${ALERTEMAIL}" | awk -F "@" '{print $2}')
    # read it's MX address record
    ALERTEMAILMX=$(dig +short "${ALERTEMAILHOST}" mx | sort -n | nawk '{print $2; exit}' | sed -e 's/\.$//')
    # save the MX record to nullmailer's config
    printf "${ALERTEMAILMX}" > /etc/nullmailer/remotes
    # configure the SSH login notifications
    ALERTSCRIPT="/home/login-notification.sh"
    ALERTBIN=$(which sendmail)
    cat > "${ALERTSCRIPT}" << EOFALERTSCRIPT
#!/bin/sh

if [ "\${PAM_TYPE}" != "close_session" ]; then
    ALERT_DATE=\$(LC_ALL=C date +"%a, %d %h %Y %T %z")
    ALERT_SUBJECT="SSH Login Alert: \${PAM_USER}@\${PAM_RHOST} to \$(hostname)"
    printf %b "Subject: \${ALERT_SUBJECT}\n\$(env)\n\${ALERT_DATE}" | ${ALERTBIN} "${ALERTEMAIL}"
fi
EOFALERTSCRIPT
    chmod -w+x "${ALERTSCRIPT}"
    echo "session optional pam_exec.so seteuid $ALERTSCRIPT" >> /etc/pam.d/sshd
    sed -i "s/^#* *UsePAM *[^ ]*/UsePAM yes/" /etc/ssh/sshd_config
    # enable fail2ban email notifications
    echo "action = %(action_mwl)s" >> /etc/fail2ban/jail.local
    # configure fail2ban to notify the provided e-mail
    sed -i "s/^#* *destemail *= *[^$]*/destemail = ${ALERTEMAIL}/" /etc/fail2ban/jail.conf
fi

# nginx configuration
CPU_CORES_CNT=`nproc --all`
ULIMIT=`ulimit -n`
if [ ! "$PORT_HTTP" = "0" ]; then
    header "Configuring Nginx"
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

    cat > /etc/nginx/snippets/vhost-common.conf << 'EOF'
index index.php index.html index.htm;
location = /favicon.ico {
    log_not_found off;
    access_log off;
}
location = /robots.txt {
    allow all;
    log_not_found off;
    access_log off;
}
location ~* \.(ini)$ {
    return 404;
}
location ~ /\.well-known { 
    allow all;
}
location ~ /\. {
    deny all;
}
EOF
    if [ ! "${PHP_VER}" = "0" ]; then
        header "Configuring Nginx: PHP"
        PHP_SOCK_PATH=$(grep -iR "\.sock" /etc/php | awk -F "= " '{print $2}')
        cat >> /etc/nginx/snippets/vhost-common.conf << EOF
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
EOF
    fi

    # perform all letsencrypt validations in a separate directory
    header "Configuring Nginx: Lets Encrypt"
    LETSENCRYPT_ROOT="/usr/share/nginx/letsencrypt"
    report_append "LETSENCRYPT_ROOT" ${LETSENCRYPT_ROOT}
    mkdir -p "${LETSENCRYPT_ROOT}"
    cat > /etc/nginx/snippets/vhost-letsencrypt.conf << EOF
location ^~ /.well-known/acme-challenge/ {
    allow all;
    access_log /var/log/nginx/letsencrypt.access.log;
    error_log /var/log/nginx/letsencrypt.error.log;
    root ${LETSENCRYPT_ROOT};
}
EOF
    # generate the diffie-hellman parameters
    openssl dhparam -out /etc/nginx/dhparam.pem 4096

    header "Configuring Nginx: WAF"
    cat > /etc/nginx/snippets/suspicious.conf << 'EOF'
# poor man's WAF
map "$request_uri $http_referer $http_user_agent $http_cookie" $suspicious {
    default 0;
    "~(?<susmatch>127\.0\.0\.1)" 1;
    "~(?<susmatch>(\.\./)+)" 1;
    "~*(?<susmatch>(<|%3c)\?)" 1;
    "~*(?<susmatch>\?(>|%3e))" 1;
    "~(?<susmatch>_(SERVER|GET|POST|FILES|REQUEST|SESSION|ENV|COOKIE)\[)" 1;
    "~*(?<susmatch>(\\x|%)(3c|3e|5c|27)+)" 1;
    "~*(?<susmatch>base64_(en|de)code)" 1;
    "~*(?<susmatch>file_(put|get)_contents)" 1;
    "~*(?<susmatch>call_user_func_array)" 1;
    "~*(?<susmatch>(mb_)?ereg_replace)" 1;
    "~*(?<susmatch>(un)?hex([%0-9a-f|\W]*)(\(|%28))" 1;
    "~*(?<susmatch>(char|concat|eval)([%0-9a-f|\W]*)(\(|%28))" 1;
    "~*(?<susmatch>(union([%0-9a-f|\W]*))?select([%0-9a-f|\W]*)from)" 1;
    "~*(?<susmatch>union([%0-9a-f|\W]*)select(([%0-9a-f|\W]*)from)?)" 1;
}
log_format suslog '$remote_addr /$susmatch/ - $remote_user $host [$time_local] '
    '"$request" $status $body_bytes_sent '
    '"$http_referer" "$http_user_agent" "$http_cookie"';
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
    touch /var/log/nginx/suspicious.log
    chown www-data:www-data /var/log/nginx/suspicious.log
    mkdir /var/log/nginx-attacks

service nginx start
fi

if [ ! "${PHP_VER}" = "0" ]; then
    header "Configuring PHP"
    curl -sS https://getcomposer.org/installer -o "$WWW_ROOT/composer.phar"
    chmod +x "$WWW_ROOT/composer.phar"
    php "$WWW_ROOT/composer.phar"
    # CONFIGURING PHP-FPM
    # find php.ini path, regardless of php-fpm version
    PHP_FPM_INI=$(find /etc/php  -path "*/fpm/*" -type f -name "php.ini")
    # make sure opcache is enabled
    sed -i "s/^;* *opcache\.enable *= *[^$]*/opcache.enable=1/" ${PHP_FPM_INI}
    # force checking file readability on each access to cached file
    sed -i "s/^;* *opcache\.validate_permission *= *[^$]*/opcache.validate_permission=1/" ${PHP_FPM_INI}
    # validate root path of the file, prevent access in chrooted environments
    sed -i "s/^;* *opcache\.validate_root *= *[^$]*/opcache.validate_root=1/" ${PHP_FPM_INI}
    # Use opcache.restrict_api to disable OPcache API access for all PHP scripts
    sed -i "s/^;* *opcache\.restrict_api *= *[^$]*/opcache.restrict_api=1/" ${PHP_FPM_INI}
    # find www pool config path, regardless of php-fpm version
    PHP_WPCNF=$(find /etc/php  -path "*/fpm/pool.d/*" -type f -name "www.conf")
    # switch to static 
    # (haydenjames.io/php-fpm-tuning-using-pm-static-max-performance/)
    sed -i "s/^;* *pm *= *[^ ]*/pm = static/" ${PHP_WPCNF}
    # set max requests until respawn
    sed -i "s/^;* *pm\.max_requests *= *[^ ]*/pm.max_requests = 512/" ${PHP_WPCNF}
    # calculate max_children based on server RAM and estimated process size
    PHP_PSZ_kB=$(echo "${PHP_PSZ}*1024" | bc) # convert from MB to kB
    if [ ! "$PORT_MYSQL" = "0" ]; then
        PHP_PSHR=0.5 # decrease if this server also hosts MySQL
    else
        PHP_PSHR=0.8 # increase if no MySQL runs on this server
    fi
    SRV_RAM_TOTAL=$(awk '/MemTotal/ {print $2}' /proc/meminfo) # total RAM
    SRV_RAM_SHARE=$(echo "${SRV_RAM_TOTAL}*${PHP_PSHR}" | bc) # calculated share
    PHP_CHLDN=$(echo "${SRV_RAM_SHARE}/${PHP_PSZ_kB}" | bc) # how many children
    echo "Total RAM: ${SRV_RAM_TOTAL} kB. Allocated to PHP: ${SRV_RAM_SHARE} kB"
    echo "Setting pm.max_children to ${PHP_CHLDN}"
    # set max_children
    sed -i "s/^;* *pm\.max_children *= *[^ ]*/pm.max_children = ${PHP_CHLDN}/" ${PHP_WPCNF}
    # error handling
    sed -i "s/^;* *php_flag\[display_errors\] *= *[^ ]*/php_flag[display_errors] = off/" ${PHP_WPCNF}
    sed -i "s/^;* *php_admin_flag\[log_errors\] *= *[^ ]*/php_admin_flag[log_errors] = on/" ${PHP_WPCNF}
    sed -i "s@^;* *php_admin_value\[error_log\] *= *[^ ]*@php_admin_value[error_log] = /var/log/php-fpm.log@" ${PHP_WPCNF}
fi

if [ ! "$PORT_MYSQL" = "0" ]; then
    header "Configuring MySQL"
    sed -i "s/^#port/port/g" /etc/mysql/mariadb.conf.d/50-server.cnf
    sed -i "s/= 3306/= ${PORT_MYSQL}/g" /etc/mysql/mariadb.conf.d/50-server.cnf
    sed -i "s/= 127.0.0.1/= $(hostname -i)/g" /etc/mysql/mariadb.conf.d/50-server.cnf
    service mysql start
    mysqladmin -u root password "${MYSQL_ROOT_PASS}"
    mysql -uroot -p${MYSQL_ROOT_PASS} -e "CREATE USER '${MYSQL_REMO_USER}'@'%' IDENTIFIED BY '${MYSQL_REMO_PASS}';"
    mysql -uroot -p${MYSQL_ROOT_PASS} -e "GRANT ALL PRIVILEGES ON *.* TO '${MYSQL_REMO_USER}'@'%' WITH GRANT OPTION;"
fi

header "Downloading the host manager script (spanel)"
wget -O ${HOSTMANAGER_PATH} https://raw.githubusercontent.com/mehov/debian-automation/master/spanel/spanel.sh
chmod +x ${HOSTMANAGER_PATH}
echo "alias spanel='bash ${HOSTMANAGER_PATH}'" >> /etc/bash.bashrc

if [ ! "$PORT_FTP" = "0" ]; then
    header "Configuring FTP"
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
    header "Installing the Lets Encrypt certbot"
    # install certbot for letsencrypt
    # https://certbot.eff.org/all-instructions/#web-hosting-service-nginx
    wget -O ${CERTBOT_PATH} https://dl.eff.org/certbot-auto
    chown root "${CERTBOT_PATH}"
    chmod 0755 "${CERTBOT_PATH}"
    ${CERTBOT_PATH} --non-interactive
    echo "0 4 1,15 * * root ${HOSTMANAGER_PATH} certupdate >> /var/log/certupdate.log 2>&1" > /etc/cron.d/certupdate
fi

header "Configuring SSH"
# stop accepting client environment variables
sed -i "s/^AcceptEnv/#AcceptEnv/g" /etc/ssh/sshd_config
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
    useradd -s /bin/bash -md "${DIR_HOME}" -g sudo $SSH_USER
    usermod -a -G www-data ${SSH_USER}
    if [ -d "${WWW_ROOT}" ]; then
        chown -R ${SSH_USER} "${WWW_ROOT}"
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
chown -R ${SSH_USER}:sudo "${DIR_HOME}"
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
header "Configuring SSH fail2ban jail"
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
    header "Configuring SSH fail2ban honeypot"
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
    # and if at least one port is configured
    if [ -n "${PORT_SSH}" ] || [ -n "${PORT_FTP}" ] || [ -n "${PORT_MYSQL}" ]; then
        header "Trusting whitelisted IP addresses"
        # trust the provided IPs
        sh ${HOSTMANAGER_PATH} trust "${WHTLST_IPS}"
        # block everyone else
        WHTLST_PORTS="${PORT_SSH} ${PORT_FTP} ${PORT_MYSQL}"
        for PORT in ${WHTLST_PORTS}; do
            # only if the port number is not empty and greater than zero
            if [ -n "${PORT}" ] && [ "${PORT}" -gt 0 ]; then
                echo "Blocking port ${PORT} for everyone else"
                # use -A to make these least specific rules apply last
                iptables -A INPUT -p tcp --dport ${PORT} -j DROP
                iptables -A OUTPUT -p tcp --sport ${PORT} -j DROP
            else
                echo "Skipping '${PORT}' as it isn't a valid port number"
            fi
        done
    fi
    iptables-save > /etc/iptables.conf
fi
header "Finishing up the iptables configuration"
# set the iptables rules to be restored on boot
cat > /etc/network/if-up.d/iptables << EOF
#!/bin/sh
iptables-restore < /etc/iptables.conf
EOF
chmod +x /etc/network/if-up.d/iptables 

header "Clean up"
apt-get -y autoremove
header "Self-destruct"
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
