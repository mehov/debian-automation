#!/bin/bash

##todo http://serverfault.com/questions/172831/sending-email-from-my-server#comment150117_172834


PORT_SSH_DEFAULT=$(date -u "+%N" | cut -c 7,8)
PORT_SSH_DEFAULT="220${PORT_SSH_DEFAULT}"
PORT_FTP_DEFAULT=$(date -u "+%N" | cut -c 6,7)
PORT_FTP_DEFAULT="210${PORT_FTP_DEFAULT}"
PORT_MYSQL_DEFAULT=$(date -u "+%N" | cut -c 8,7)
PORT_MYSQL_DEFAULT="330${PORT_MYSQL_DEFAULT}"
WWW_ROOT="/var/www"
CERTBOT_PATH=""
HOSTMANAGER_PATH="/root/spanel.sh"
SSH_CLIENT_IP=$(who -m --ips | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}')

# reusable functions
ARGS="$@"
input() { # try taking required variable from flags/arguments, else prompt
    NAME="${1}" # shorthand to the name of requested variable
    PROMPT="${2}" # shorthand to the prompt text
    DEFAULT="${3}" # shorthand to the default value
    if ${_noninteractive}; then
        VALUE="${DEFAULT}"
        PROMPT=""
    fi
    IS_YN=false # determine whether prompt expects a yes or no answer
    if [ "${DEFAULT}" = true ] || [ "${DEFAULT}" = false ]; then
        IS_YN=true
    fi
    ARG="" # clean up
    KEY="" # clean up
    KEY_LENGTH="" # clean up
    VALUE="" # clean up
    for ARG in ${ARGS}; do # loop through flags/arguments passed to the script
        KEY=$(echo ${ARG} | cut -f1 -d=) # parse --KEY out of --KEY=VALUE
        if [ "${KEY}" != "--${NAME}" ]; then # skip keys that don't match
            continue
        fi
        KEY_LENGTH=${#KEY}
        VALUE="${ARG:$KEY_LENGTH+1}" # parse VALUE out of --KEY=VALUE
        if [ -z "${VALUE}" ]; then # this flag has been provided with no value
            header "Received ${KEY}: ${VALUE}"
            if "${IS_YN}"; then
                VALUE=true # for booleans, consider no value as a yes
            else
                VALUE="${DEFAULT}" # otherwise, use whatever is the default
                PROMPT="" # emptying prompt makes sure it's not shown
            fi
        fi
    done
    if [ -n "${PROMPT}" ] && [ -z "${VALUE}" ]; then # if variable was not found in arguments, prompt
        PROMPT_DEFAULT="${DEFAULT}" # displayed default value
        if "${IS_YN}"; then # if expecting boolean, format the prompt as Y/N
            if "${DEFAULT}"; then
                PROMPT_DEFAULT="Y/n"
            else
                PROMPT_DEFAULT="y/N"
            fi
        fi
        if [ ! -z "${PROMPT_DEFAULT}" ]; then
            PROMPT_DEFAULT=" [${PROMPT_DEFAULT}]"
        fi
        read -p "${PROMPT}${PROMPT_DEFAULT}: " "VALUE" # finally, prompt
    fi
    if [ -z "${VALUE}" ]; then # if still empty after prompt, revert to default
        VALUE="${DEFAULT}"
    fi
    if "${IS_YN}"; then # if expecting boolean, convert the value we have
        if [ "${VALUE}" = "Y" ] || [ "${VALUE}" = "y" ]; then
            VALUE=true
        fi
        if [ "${VALUE}" = "N" ] || [ "${VALUE}" = "n" ]; then
            VALUE=false
        fi
    fi
    printf -v "_${NAME}" "%s" "${VALUE}" # stackoverflow.com/a/55331060
}
random_string() {
    if [ $1="-l" ]; then
            length=$2
        else
            length="8"
        fi
    echo `cat /dev/urandom | tr -dc "a-zA-Z0-9" | fold -w $length | head -1`
}
do_install() {
    header "Installing ${1}"
    DEBIAN_FRONTEND=noninteractive apt-get install -q -y --no-install-recommends -o Dpkg::Options::="--force-confnew" $1
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
    header "Purging ${DEL}"
    apt-get purge -y $DEL
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

prompt_server_ip() {
    RESOLVED_IP=$(dig +short myip.opendns.com @resolver1.opendns.com)
    input "server_ip" "The IP address of this server" "${RESOLVED_IP}"
    if [ "_${_server_ip}" = "_" ]; then
        echo "Please provide a valid IP address."
        prompt_server_ip
    fi
    ping -c 1 "${_server_ip}"
    if [ "$?" -gt "0" ]; then
        echo "${_server_ip} is not connectable."
        prompt_server_ip
    fi
}



install() {
    SESSION_ID=$(random_string -l 4)
    # start the config
    report_append "WWW_ROOT" $WWW_ROOT
    input "noninteractive" "" false # never prompt; false by default, true if passed
    # make sure we know the IP address of this server
    do_install dnsutils
    prompt_server_ip
    grep -qF "${_server_ip}" /etc/hosts || echo "${_server_ip} $(hostname)" >> /etc/hosts

    echo ""
    echo "Receive security notifications and alerts (SSH, fail2ban)?"
    input "email" "Enter an e-mail address, or leave empty to skip" ""

    input "nginx" "Install Nginx?" false
    if ${_nginx}; then
        input "certbot" "Install the Let's Encrypt Certbot?" true
        input "dhparam_numbits" "" 4096 # accept via argument, do not prompt
    fi

    input "php" "Install PHP?" false
    if ${_php}; then
        input "php_psz" "Expected size of a single PHP process, in MB" 64
    fi
    hostname_old=`hostname`
    if [ "${hostname_old}" = "" ] || [ "${hostname_old}" = "vps" ]; then
        input "hostname" "New hostname" "+"
        if [ "${_hostname}" = "+" ]; then
            _hostname=`random_string -l 4`
        fi
        if [ "${_hostname}" != "" ]; then
            hostname "${_hostname}"
        fi
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
    input "whitelist_ips" "Secure commonly hacked ports by whitelisting your IP addresses?" true
    if $_whitelist_ips; then
        input "whitelisted_ips" "Whitelisted IP addresses, space-separated" "${SSH_CLIENT_IP}"
    else
        _whitelisted_ips=""
    fi

    input "nopass" "Use your public SSH key instead of password-based authentication? You'll need to paste your SSH key at the end of this setup so that the server lets you in next time you connect" true

    input "noroot" "Disable direct root login? Using a non-root account and switching to root only when needed is more secure. Choosing 'n' will keep the direct root login" true
    if ${_noroot}; then
        input "ssh_user" "SSH non-root user" "admin"
        report_append "SSH_USER" ${_ssh_user}
    fi

    input "ssh_port" "SSH port" ${PORT_SSH_DEFAULT}
    report_append "SSH_PORT" ${_ssh_port}

    if ${_nginx} && [ ! -d $WWW_ROOT ]; then
        mkdir $WWW_ROOT
    fi
    if [ -d "${WWW_ROOT}" ]; then
        chgrp -R www-data "${WWW_ROOT}"
        chmod g+s "${WWW_ROOT}"
    fi

    input "ftp" "Install FTP?" false
    if ${_ftp}; then
        input "ftp_port" "FTP port" ${PORT_FTP_DEFAULT}
        input "ftp_user" "FTP user" "ftp-data"
        input "ftp_password" "FTP password for '${_ftp_user}'" `random_string -l 16`
        cppassword=$(perl -e 'print crypt($ARGV[0], "password")' ${_ftp_password})
        if id -u ${_ftp_user} >/dev/null 2>&1; then
            pkill -u ${_ftp_user}
            killall -9 -u ${_ftp_user}
            usermod --home "$WWW_ROOT" ${_ftp_user}
            usermod --password=$cppassword ${_ftp_user}
        else
            #echo -e "/bin/false\n" >> /etc/shells
            useradd -d "$WWW_ROOT" -p $cppassword -g www-data -s /bin/sh -M ${_ftp_user}
            chown ${_ftp_user} $WWW_ROOT
        fi
        report_append "FTP_PORT" ${_ftp_port}
        report_append "FTP_USER" ${_ftp_user}
        report_append "FTP_PASS" ${_ftp_password}
    else
        echo "**** FTP SKIPPED"
    fi

    input "mysql" "Install MySQL?" false
    if ${_mysql}; then
        input "mysql_port" "MySQL port" ${PORT_MYSQL_DEFAULT}
        report_append "MYSQL_PORT" ${_mysql_port}
        MYSQL_ROOT_PASS=`random_string -l 16`
        report_append "MYSQL_ROOT_PASS" "${MYSQL_ROOT_PASS}"
        input "mysql_remo_user" "MySQL remote access user" `random_string -l 16`
        report_append "MYSQL_REMO_USER" "${_mysql_remo_user}"
        input "mysql_remo_pass" "MySQL password for '${_mysql_remo_user}'" `random_string -l 16`
        report_append "MYSQL_REMO_PASS" "${_mysql_remo_pass}"
    else
        echo "**** MySQL SKIPPED"
    fi

    header "Starting."

    #build-essentials = c++

    header "Deleting pre-installed packages"
    do_uninstall man-db
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
    debian_release=$(printf "%.0f\n" $(lsb_release -sr)) # truncate to major ver
    debian_codename=$(lsb_release -sc)
    if [ -z "${debian_codename}" ]; then
        echo "Failed to get the Debian version codename using lsb_release"
        exit 1
    fi
    cat /dev/null > /etc/apt/sources.list
    echo "deb http://httpredir.debian.org/debian ${debian_codename} main contrib non-free" >> /etc/apt/sources.list
    echo "deb http://httpredir.debian.org/debian ${debian_codename}-backports main contrib non-free" >> /etc/apt/sources.list
    echo "deb http://security.debian.org/ ${debian_codename}/updates main contrib non-free" >> /etc/apt/sources.list
    if ${_nginx}; then
        header "Adding Nginx repository to sources.list"
        echo "deb http://nginx.org/packages/debian/ ${debian_codename} nginx" >> /etc/apt/sources.list
        echo "deb-src http://nginx.org/packages/debian/ ${debian_codename} nginx" >> /etc/apt/sources.list
        wget https://nginx.org/keys/nginx_signing.key -O - | apt-key add -
    fi
    if ${_php}; then
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
    do_install sudo
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
    do_install crudini
    do_install easy-rsa
    do_install logrotate
    do_install ntp
    do_install tzdata
    do_install python3-gi # fix "Unable to monitor PrepareForShutdown() signal"
    do_install git
    do_install fail2ban
    do_install whois
    do_install idn
    do_install net-tools
    if [ -n "${_email}" ]; then
        do_install nullmailer
    fi
    do_install rush
    do_install rsync
    header "Installing and configuring unattended-upgrades"
    do_install unattended-upgrades
    dpkg-reconfigure -f noninteractive unattended-upgrades

    #do_install libpcre3-dev
    #do_install zlib1g-dev
    if ${_nginx}; then
        header "Installing Nginx"
        do_install nginx
    fi
    if ${_ftp}; then
        header "Installing FTP (inetutils)"
        do_install inetutils-ftpd
    fi
    if ${_mysql}; then
        header "Installing MariaDB"
        do_install mariadb-server
        systemctl enable mariadb
        service mysql stop
    fi
    if ${_php}; then
        header "Installing PHP and it's modules"
        for PHP_MOD in common cli fpm mysql curl gd mcrypt intl json bcmath imap mbstring xml opcache zip sqlite3; do
            do_install php-${PHP_MOD}
        done
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
ignoreip = ${_whitelisted_ips}
EOF

if [ -n "${_email}" ]; then
    header "Setting up alerts"
    report_append "ALERT_EMAIL" ${_email}
    # configure the SSH login notifications
    ALERTSCRIPT="/home/login-notification.sh"
    cat > "${ALERTSCRIPT}" << 'EOFALERTSCRIPT'
#!/bin/sh

if [ "${PAM_TYPE}" != "close_session" ]; then
    ALERT_SUBJECT="SSH Login Alert: ${PAM_USER}@${PAM_RHOST} to $(hostname)"
    ALERT_TEXT="Connecting IP: ${PAM_RHOST}\n\n$(env)\n\n$(whois ${PAM_RHOST})"
    spanel alert "${ALERT_SUBJECT}" "${ALERT_TEXT}"
fi
EOFALERTSCRIPT
    chmod -w+x "${ALERTSCRIPT}"
    # https://tuximail.github.io/pam.html
    echo "session optional pam_exec.so seteuid $ALERTSCRIPT" >> /etc/pam.d/sshd
    sed -i "s/^#* *UsePAM *[^ ]*/UsePAM yes/" /etc/ssh/sshd_config
    # enable fail2ban email notifications
    echo "action = %(action_mwl)s" >> /etc/fail2ban/jail.local
    # configure fail2ban to notify the provided e-mail
    sed -i "s/^#* *destemail *= *[^$]*/destemail = ${_email}/" /etc/fail2ban/jail.conf
fi

# nginx configuration
CPU_CORES_CNT=`nproc --all`
ULIMIT=`ulimit -n`
if ${_nginx}; then
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
        listen 443 ssl default_server;
        ssl_certificate /etc/nginx/default_server.crt;
        ssl_certificate_key /etc/nginx/default_server.key;
        include snippets/vhost-letsencrypt.conf;
        location / {
            return 444;
        }
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
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
        openssl req -x509 -nodes -days 36524 -newkey rsa:4096 -keyout /etc/nginx/default_server.key -out /etc/nginx/default_server.crt -subj "/C=FR/ST=/L=Paris/O=/CN=*"
        cat > /etc/nginx/conf.d/trusted_ip.conf << 'EOF'
map $remote_addr $trusted_ip {
    default 0;
    #192.0.2.4 1;
}
EOF

        cat > /etc/nginx/conf.d/limit_req.conf << 'EOF'
map $trusted_ip $limit_req_key {
    default $binary_remote_addr;
    1 "";
}
limit_req_zone $limit_req_key zone=per_ip:64m rate=10r/s;
limit_req_zone $limit_req_key zone=per_ip_slow:64m rate=30r/m;
EOF

        cat > /etc/nginx/conf.d/webp.conf << 'EOF'
# https://serverfault.com/questions/630212/conditionally-serving-high-resolution-and-webp-images-with-nginx
# https://alexey.detr.us/en/posts/2018/2018-08-20-webp-nginx-with-fallback/
map $http_accept $ext_webp {
    default "";
    "~image\/webp" ".webp";
}
EOF

        cat > /etc/nginx/snippets/vhost-ssl.conf << 'EOF'
ssl_dhparam /etc/nginx/dhparam.pem;
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security max-age=15768000;
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
location ~* \.(jpe?g)$ {
    try_files $uri$ext_webp $uri =404;
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
    if ${_php}; then
        header "Configuring Nginx: PHP"
        PHP_SOCK_PATH=$(grep -iR "\.sock" /etc/php | awk -F "= " '{print $2}')
        cat >> /etc/nginx/snippets/vhost-common.conf << EOF
location ~ \.php {
    if (\$suspicious = 1) {
        access_log /var/log/nginx/suspicious.log suslog;
        return 500;
    }
    limit_req zone=per_ip burst=4;
    include snippets/fastcgi-php.conf;
    keepalive_timeout 0;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    fastcgi_pass unix:${PHP_SOCK_PATH};
}
EOF
    fi

    # configure nginx for certbot validation
    header "Configuring Nginx: Lets Encrypt"
    cat > /etc/nginx/snippets/vhost-letsencrypt.conf << EOF
location ^~ /.well-known/acme-challenge/ {
    auth_basic off;
    allow all;
    access_log /var/log/nginx/letsencrypt.access.log;
    error_log /var/log/nginx/letsencrypt.error.log;
    proxy_pass http://localhost:8008/.well-known/acme-challenge/;
}
EOF
    # generate the diffie-hellman parameters
    openssl dhparam -out /etc/nginx/dhparam.pem ${_dhparam_numbits}

    header "Configuring Nginx: WAF"
    cat > /etc/nginx/conf.d/suspicious.conf << 'EOF'
# poor man's WAF
map "$request_uri $http_referer $http_user_agent $http_cookie" $suspicious {
    default 0;
    "~(?<susmatch>127\.0\.0\.1)" 1;
    "~(?<susmatch>(\.\./)+)" 1;
    "~(?<susmatch>(\/\*)(.*?)(\*\/))" 1;#bugs.mysql.com/bug.php?id=28779
    "~(?<susmatch>--(\+|%[0-9a-f]{2}| |$)+)" 1;#dev.mysql.com/doc/refman/5.6/en/ansi-diff-comments.html
    "~*(?<susmatch>(<|%3c)\?)" 1;
    "~*(?<susmatch>\?(>|%3e))" 1;
    "~(?<susmatch>_(SERVER|GET|POST|FILES|REQUEST|SESSION|ENV|COOKIE)\[)" 1;
    "~*(?<susmatch>(\\x|%)(3c|3e|5c|27)+)" 1;
    "~*(?<susmatch>base64_(en|de)code)" 1;
    "~*(?<susmatch>file_(put|get)_contents)" 1;
    "~*(?<susmatch>call_user_func_array)" 1;
    "~*(?<susmatch>(mb_)?ereg_replace)" 1;
    "~*(?<susmatch>(benchmark|chr|char|concat|eval|extractvalue|hex|md5|now|receive_message|select|sleep|sysdate)(%[0-9a-f]{2}|\W)*(\(|%28))" 1;
    "~*(?<susmatch>select( |%[a-f0-9]{2}|\()+(.*)( |%[a-f0-9]{2}|\))+from)" 1;
    "~*(?<susmatch>union(%[0-9a-f]{2}|\W)+select((%[0-9a-f]{2}|\W)+from)?)" 1;
}
log_format suslog '$remote_addr  $susmatch  - $remote_user $host [$time_local] '
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

if ${_php}; then
    header "Configuring PHP"
    curl -sS https://getcomposer.org/installer -o "$WWW_ROOT/composer.phar"
    chmod +x "$WWW_ROOT/composer.phar"
    php "$WWW_ROOT/composer.phar"
    ln -s "$WWW_ROOT/composer.phar" "/usr/bin/composer"
    # CONFIGURING PHP-FPM
    # find php-fpm.conf path, regardless of php-fpm version
    PHP_FPM_CONF=$(find /etc/php -path "*/fpm/*" -type f -name "php-fpm.conf")
    # change the log level to warning
    sed -i "s/^;* *log_level *= *[^ ]*\$/log_level = warning/" ${PHP_FPM_CONF}
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
    PHP_PSZ_kB=$(echo "${_php_psz}*1024" | bc) # convert from MB to kB
    if ${_mysql}; then
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

if ${_mysql}; then
    header "Configuring MySQL"
    crudini --set "/etc/mysql/mariadb.conf.d/50-server.cnf" mysqld port ${_mysql_port}
    crudini --set "/etc/mysql/mariadb.conf.d/50-server.cnf" mysqld bind-address "${_server_ip}"
    service mysql start
    mysqladmin -u root password "${MYSQL_ROOT_PASS}"
    mysql -uroot -p${MYSQL_ROOT_PASS} -e "CREATE USER '${MYSQL_REMO_USER}'@'%' IDENTIFIED BY '${MYSQL_REMO_PASS}';"
    mysql -uroot -p${MYSQL_ROOT_PASS} -e "GRANT ALL PRIVILEGES ON *.* TO '${MYSQL_REMO_USER}'@'%' WITH GRANT OPTION;"
fi

header "Downloading the host manager script (spanel)"
wget -O ${HOSTMANAGER_PATH} https://raw.githubusercontent.com/mehov/debian-automation/master/spanel/spanel.sh
chmod +x ${HOSTMANAGER_PATH}
ln -s "${HOSTMANAGER_PATH}" "/usr/bin/spanel"
chmod +x "/usr/bin/spanel"

if ${_ftp}; then
    header "Configuring FTP"
    sed -i "s/\t21\/tcp/\t${_ftp_port}\/tcp/g" /etc/services
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

if ${_certbot}; then
    header "Installing the Lets Encrypt certbot"
    # install certbot for letsencrypt
    do_install certbot
    CERTBOT_PATH=$(which certbot)
    report_append "CERTBOT_PATH" $CERTBOT_PATH
    echo "0 4 1,15 * * root ${HOSTMANAGER_PATH} certupdate >> /var/log/certupdate.log 2>&1" > /etc/cron.d/certupdate
fi

header "Configuring SSH"
# create root SSH key if needed
if [ ! -d "$HOME/.ssh" ]; then
    mkdir -p "$HOME/.ssh"
fi
if [ ! -f "$HOME/.ssh/id_rsa" ]; then
    ssh-keygen -b 8192 -t rsa -q -f "$HOME/.ssh/id_rsa" -N ""
fi
# stop accepting client environment variables
sed -i "s/^AcceptEnv/#AcceptEnv/g" /etc/ssh/sshd_config
# Update the SSH port
sed -i "s/#Port/Port/g" /etc/ssh/sshd_config
sed -i "s/Port 22/Port ${_ssh_port}/g" /etc/ssh/sshd_config
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
if ${_noroot}; then
    DIR_HOME="/home/${_ssh_user}"
    # Disable root login
    sed -i "s/#PermitRootLogin/PermitRootLogin/g" /etc/ssh/sshd_config
    sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
    # Whitelist the non-SSH user
    echo "AllowUsers ${_ssh_user}" >> /etc/ssh/sshd_config
    # Create the SSH user inside the group "sudo"
    useradd -s /bin/bash -md "${DIR_HOME}" -g sudo ${_ssh_user}
    # Also add to the group "www-data"
    usermod -a -G www-data ${_ssh_user}
    # Create SSH keys for ${_ssh_user}
    if [ ! -d "${DIR_HOME}/.ssh" ]; then
        mkdir -p "${DIR_HOME}/.ssh"
    fi
    if [ ! -f "${DIR_HOME}/.ssh/id_rsa" ]; then
        ssh-keygen -b 8192 -t rsa -q -f "${DIR_HOME}/.ssh/id_rsa" -N "" -C "${_ssh_user}"
    fi
    # Finally, make this user a sudoer too
    echo "${_ssh_user} ALL=(ALL) NOPASSWD: ALL" | (su -c "EDITOR='tee' visudo -f /etc/sudoers.d/${_ssh_user}")
    if [ -d "${WWW_ROOT}" ]; then
        chown -R ${_ssh_user} "${WWW_ROOT}"
    fi
    cat >> ${DIR_HOME}/.profile << '    EOF'
alias grep="grep --color=auto"
# https://superuser.com/questions/137438/664061#664061
export HISTFILESIZE=
export HISTSIZE=
export HISTTIMEFORMAT="[%F %T] "
export HISTFILE=~/.bash_eternal_history
PROMPT_COMMAND="history -a; $PROMPT_COMMAND"
    EOF
else
    DIR_HOME="/root"
fi
if ${_nopass}; then
    # Disable password authentication
    sed -i "s/#PasswordAuthentication/PasswordAuthentication/g" /etc/ssh/sshd_config
    sed -i "s/PasswordAuthentication yes/PasswordAuthentication no/g" /etc/ssh/sshd_config
    # Enable key-based authentication
    sed -i "s/#PubkeyAuthentication/PubkeyAuthentication/g" /etc/ssh/sshd_config
    sed -i "s/PubkeyAuthentication no/PubkeyAuthentication yes/g" /etc/ssh/sshd_config
    mkdir -p "${DIR_HOME}/.ssh"
    prompt_pubkey() {
        read -p "Please paste your public key here: " SSH_USER_PUBKEY
        echo "${SSH_USER_PUBKEY}" | ssh-keygen -l -f - 2>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "The public key you provided is not valid.\n"
            prompt_pubkey
        fi
    }
    prompt_pubkey
    echo "${SSH_USER_PUBKEY} ${_ssh_user}" >> "${DIR_HOME}"/.ssh/authorized_keys
else
    # Enable password authentication
    sed -i 's/^\s*#\?\s*PasswordAuthentication\s\+\w\+/PasswordAuthentication yes/' /etc/ssh/sshd_config
    # Prompt and set the password for the user
    input "ssh_password" "Password for ${_ssh_user}" "$(random_string -l 16)"
    echo "${_ssh_user}:${_ssh_password}" | sudo chpasswd
fi
chown -R ${_ssh_user}:sudo "${DIR_HOME}"
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
if ${_nopass}; then
    # lower the tolerance for failed attempts if no password is used
    SSH_MAXRETRY=2
fi
cat >> /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
mode = aggressive
port = ${_ssh_port}
filter = sshd
maxretry = ${SSH_MAXRETRY}
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF

iptables -F

# allow only localhost to the certbot standalone port
iptables -A INPUT -p tcp -i lo --dport 8008 -j ACCEPT
iptables -A INPUT -p tcp --dport 8008 -j DROP

# if SSH uses port other than 22, add a honeypot
if [ ! "${_ssh_port}" = "22" ]; then
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
if [ -n "${_whitelisted_ips}" ]; then
    # and if at least one port is configured
    if [ -n "${_ssh_port}" ] || [ -n "${_ftp_port}" ] || [ -n "${_mysql_port}" ]; then
        header "Trusting whitelisted IP addresses"
        # trust the provided IPs
        bash ${HOSTMANAGER_PATH} trust "${_whitelisted_ips}"
        # block everyone else
        WHTLST_PORTS="${_ssh_port} ${_ftp_port} ${_mysql_port}"
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
echo "**** Reminder: the new SSH port is: ${_ssh_port}"
echo "     (make sure to allow it with your AWS/GCP/etc. firewall)"
echo "**** The server will reboot."

reboot
}

case "$1" in
    install)
        install ${@}
        ;;
    *)
        input "start" "Using this is your own risk and responsibility" true
        if ${_start}; then
            do_install screen
            BIN_SCREEN=$(which screen)
            if [ -z "${BIN_SCREEN}" ]; then
                echo "Screen is required but not installed"
                exit
            fi
            "${BIN_SCREEN}" -S "spanel" bash "${0}" install ${@}
            header "Configuration summary"
            cat /root/.bonjour.ini
        else
            echo "Aborted."
        fi
        ;;
esac
