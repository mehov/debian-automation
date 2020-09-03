#!/bin/bash

### Checking for user
if [ "$(whoami)" != 'root' ]; then
    echo "You have no permission to run $0 as a non-root user."
    exit 1;
fi

### Script params
CERTBOT_PATH=$(cfget -qC ~/.bonjour.ini "CERTBOT_PATH")
LETSENCRYPT_ROOT=$(cfget -qC ~/.bonjour.ini "LETSENCRYPT_ROOT")
www_root=$(cfget -qC ~/.bonjour.ini "WWW_ROOT")
ftp_user=$(cfget -qC ~/.bonjour.ini "FTP_USER")
FTP_PORT=$(cfget -qC ~/.bonjour.ini "FTP_PORT")
if ! [ id -u "$ftp_user" >/dev/null 2>&1 ]; then
    ftp_user="www-data"
fi
nginx_conf_dir="/etc/nginx"
sites_available="${nginx_conf_dir}/sites-available"
sites_enabled="${nginx_conf_dir}/sites-enabled"
mysql="$(which mysql)"
# mysql root password
mysql_password="$(cfget -qC ~/.bonjour.ini "MYSQL_ROOT_PASS")"
mysql_admin="$(cfget -qC ~/.bonjour.ini "MYSQL_REMO_USER")"
mysql_admin_password="$(cfget -qC ~/.bonjour.ini "MYSQL_REMO_PASS")"

### Functions
random_string() {
    if [ $1="-l" ]; then
            length=$2
        else
            length="8"
        fi
    echo `cat /dev/urandom | tr -dc "a-zA-Z0-9" | fold -w $length | head -1`
}
restart_nginx() {
    if [ -e /var/run/nginx.pid ]; then
        command='restart'
    else
        command='start'
    fi
    service nginx $command
}
add_alias() {
    aliases=$aliases" "$1
    read -p "Enter another alias (leave blank to skip): " newalias
    if [ "$newalias" != "" ]; then
        ### loop
        add_alias $newalias
    fi
}

nginx_vhost_conf_name() {
    echo "vhost-${1}.conf"
}
create_nginx_host() {
    # $1=hostname; $2=aliases; $3=public_dir; $4=config_dir; $5=certbot_path_opt
    conf_file_name=`nginx_vhost_conf_name ${1}`
    if [ ! -z "${2}" ]; then
cat >> "${sites_available}/${conf_file_name}" << EOF
server {
listen 80;
server_name $2;
access_log /var/log/nginx/$1-aliases.access.log;
error_log /var/log/nginx/$1-aliases.error.log;
include snippets/vhost-letsencrypt.conf;
location / {
    return 301 http://$1\$request_uri;
}
}
EOF
fi
cat >> "${sites_available}/${conf_file_name}" << EOF
    server {
        listen 80;
        server_name $1;
        access_log /var/log/nginx/$1.access.log;
        error_log /var/log/nginx/$1.error.log;
        root $3; # config_path $4
        include snippets/vhost-letsencrypt.conf;
        include snippets/vhost-common.conf;
        include "$4/.ngaccess";
    }
EOF
    if ! [ -f "${sites_enabled}/${conf_file_name}" ]; then
        ln -s "${sites_available}/${conf_file_name}" "${sites_enabled}/${conf_file_name}"
    fi
    if [ ! "$5" = "" ] && [ -f "$5" ]; then
        restart_nginx # restart so the host goes live and is verifiable
        domains="$1"
        for alias in $2; do
            domains="${domains},${alias}"
        done
        letsencrypt_email="webmaster@$1"
        printf "Requesting a certificate from Let's Encrypt:\n"
        printf " - email:   ${letsencrypt_email}\n"
        printf " - webroot: ${LETSENCRYPT_ROOT}\n"
        printf " - domains: ${domains}\n"
        $5 certonly --non-interactive --agree-tos --email "${letsencrypt_email}" --webroot -w "${LETSENCRYPT_ROOT}" -d "${domains}"
        if [ ! -r "/etc/letsencrypt/live/$1/fullchain.pem" ]; then
            echo "Can't find the certificate file. Aborting."
            exit 1
        fi
        # cut -3 lines from the end of file (.ngaccess, vhost-common.conf, bracket)
        # that way we can later append further configuration to this directive
        head -n -3 "${sites_available}/${conf_file_name}" > "${sites_available}/${conf_file_name}.tmp"
        mv "${sites_available}/${conf_file_name}.tmp" "${sites_available}/${conf_file_name}"
        cat >> "${sites_available}/${conf_file_name}" << EOF
        location / {
            return 301 https://\$server_name\$request_uri;
        }
    }
EOF
if [ ! -z "${2}" ]; then
    cat >> "${sites_available}/${conf_file_name}" << EOF
    server {
        listen 443 ssl http2;
        server_name $2;
        ssl_certificate /etc/letsencrypt/live/$1/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/$1/privkey.pem;
        ssl_dhparam /etc/nginx/dhparam.pem;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:50m;
        ssl_stapling on;
        ssl_stapling_verify on;
        add_header Strict-Transport-Security max-age=15768000;
        location / {
            return 301 https://$1\$request_uri;
        }
    }
EOF
fi
cat >> "${sites_available}/${conf_file_name}" << EOF
    server {
        listen 443 ssl http2;
        server_name $1;
        access_log /var/log/nginx/$1.access.log;
        error_log /var/log/nginx/$1.error.log;
        root $3;
        include "$4/.ngaccess";
        include snippets/vhost-common.conf;
        ssl_certificate /etc/letsencrypt/live/$1/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/$1/privkey.pem;
        ssl_dhparam /etc/nginx/dhparam.pem;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:50m;
        ssl_stapling on;
        ssl_stapling_verify on;
        add_header Strict-Transport-Security max-age=15768000;
    }
EOF
        restart_nginx 
    fi
}
add() {
    # if this is a www. domain, suggest adding a root domain
    if [ "www." = $(echo "$1" | cut -c -4) ]; then
        ROOT_DOMAIN=$(echo "$1" | cut -c 5-)
        read -p "Add ${ROOT_DOMAIN}? [Y/n]: " RTD_Yn
        if [ "${RTD_Yn}" = "" ] || [ "${RTD_Yn}" = "Y" ] || [ "${RTD_Yn}" = "y" ]; then
            aliases="${ROOT_DOMAIN}"
        fi
    # otherwise suggest adding a www.
    else
        read -p "Add www.$1? [Y/n]: " WWW_Yn
        if [ "${WWW_Yn}" = "" ] || [ "${WWW_Yn}" = "Y" ] || [ "${WWW_Yn}" = "y" ]; then
            aliases="www.$1"
        fi
    fi
    echo ""
    printf "You can get a free SSL/TLS certificate from Let's Encrypt. "
    printf "Warning: your domain will be listed in public "
    printf "certificate transparency logs, such as: \n"
    echo "- https://transparencyreport.google.com/https/certificates"
    echo "- https://crt.sh"
    echo ""
    read -p "Use Let's Encrypt? [Y/n]: " SSL_Yn
    CERTBOT_PATH_OPT=""
    if [ "${SSL_Yn}" = "" ] || [ "${SSL_Yn}" = "Y" ] || [ "${SSL_Yn}" = "y" ]; then
        CERTBOT_PATH_OPT="${CERTBOT_PATH}"
    fi
    public_dir_name_default="public_html"
    database_name_random=`echo $1 | sed -e 's/\W//g'`;
    database_user_random=`random_string -l 16`
    database_password_waitforit_random=`random_string -l 16`
    if [ -z $4 ]; then
        read -p "Enter alias (leave blank to skip): " alias
        if [ "$alias" != "" ] && [ "$alias" != "n" ] && [ "$alias" != "N" ]; then
            add_alias $alias
        fi
    else
        if [ $4 != "N" ] && [ $4 != "n" ]; then
            aliases=$aliases" "$4
        fi
    fi
    if [ -z $2 ]; then
        site_dir=$www_root
        read -p "Enter site directory NAME ($site_dir/[> $1 <]): " site_dir_name
        if [ "$site_dir_name" = "" ]; then
            site_dir_name=$1
        fi
    else
        site_dir=$www_root
        site_dir_name=$2
    fi

    site_dir=$site_dir"/"$site_dir_name
    #read -p "Create \"public_html\" subdir (i.e. "$site_dir"/"$public_dir_name_default")? [y/N]: " create_public_dir
    create_public_dir="N"

    MYSQL_PORT=$(cfget -qC ~/.bonjour.ini "MYSQL_PORT")
    if [ -z "${MYSQL_PORT}" ]; then
        create_database="n"
    elif [ -z $3 ]; then
        read -p "Create MySQL database? [Y/n]: " create_database
        if [ "$create_database" != "n" ] && [ "$create_database"!="N" ]; then
        read -p "Enter MySQL database name [$database_name_random]: " database_name
            if [ "$database_name" = "" ]; then
                database_name=$database_name_random
            fi
            read -p "Enter MySQL user [$database_user_random]: " database_user
            if [ "$database_user" = "" ]; then
                database_user=$database_user_random
            fi
            read -p "Enter MySQL password [$database_password_waitforit_random]: " database_password
            if [ "$database_password" = "" ]; then
                database_password=$database_password_waitforit_random
            fi
        fi
    else
        if [ $3 = "N" ] || [ $3 = "n" ]; then
            create_database="n"
        else
            create_database="y"
            database_name=$database_name_random
            database_user=$database_user_random
            database_password=$database_password_waitforit_random
        fi
    fi

    FTP_PORT=$(cfget -qC ~/.bonjour.ini "FTP_PORT")
    if [ -n "${FTP_PORT}" ]; then
        read -p "Create a separate FTP/UNIX user? [Y/n]: " create_user
    else
        create_user="n"
    fi
    if [ "${create_user}" != "n" ] && [ "${create_user}"!="N" ]; then
        secondlvldomain=`echo $1 | cut -d "." -f 1`
        website_user_default="www-usr-${secondlvldomain}"
        read -p "FTP/UNIX user [${website_user_default}]: " website_user
        if [ "u${website_user}" = "u" ]; then
            website_user=${website_user_default}
        fi
        wdpasswordg=`random_string -l 16`
        read -p "Enter a new password for user '${website_user}' [${wdpasswordg}]: " wdpassword
        if [ "$wdpassword" = "" ]; then
            wdpassword="${wdpasswordg}"
        fi
        cppassword=$(perl -e 'print crypt($ARGV[0], "password")' $wdpassword)
        if id -u ${website_user} >/dev/null 2>&1; then
            pkill -u ${website_user}
            killall -9 -u ${website_user}
            usermod --password=${cppassword} --home="${site_dir}" ${website_user}
        else
            useradd -d "${site_dir}" -p ${cppassword} -g www-data -s /bin/sh -M ${website_user}
        fi
        ftp_user="${website_user}"
    fi

    echo ""
    echo "ADDING VIRTUALHOST $1"
    echo -n "Web root... "
    if ! [ -d $site_dir ]; then
        mkdir $site_dir
    fi
    if ! [ -d $site_dir ]; then
        echo "ERROR: "$site_dir" could not be created."
    else
        echo $site_dir" OK"
        if [ "$create_public_dir" = "y" ] || [ "$create_public_dir" = "Y" ];then
            public_dir=$site_dir"/"$public_dir_name_default
            mkdir $public_dir
        else
            public_dir=$site_dir
        fi
    fi
    ngaccess_file="${site_dir}/.ngaccess"
    echo -n ".ngaccess file... "
    if ! [ -f $ngaccess_file ]; then
        if ! touch $ngaccess_file; then
            echo "ERROR (creating)."
        else
            if ! echo "#this is the part of the main nginx config
location / {
try_files \$uri \$uri/ /index.php?\$args;
}" > $ngaccess_file; then
                echo "ERROR (writing)."
            else
                echo "done."
            fi
        fi
    else
        echo "exists."
    fi
    if [ -n "${FTP_PORT}" ]; then
        echo "# FTP p:${FTP_PORT} u:${website_user} p:${wdpassword}" >> ${ngaccess_file}
    fi
    create_nginx_host "$1" "${aliases}" "${public_dir}" "${site_dir}" "${CERTBOT_PATH_OPT}"
    #for alias in $aliases; do
    #    create_nginx_host $alias ${public_dir} ${site_dir} ${CERTBOT_PATH_OPT}
    #done

    ### MySQL
    if [ "$create_database" != "n" ] && [ "$create_database"!="N" ]; then
        $mysql -uroot -p$mysql_password -e "CREATE DATABASE \`$database_name\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        $mysql -uroot -p$mysql_password -e "GRANT CREATE,SELECT,INSERT,UPDATE,DELETE ON $database_name.* TO $database_user@localhost IDENTIFIED BY '$database_password';"
        $mysql -uroot -p$mysql_password -e "GRANT ALL ON $database_name.* TO $mysql_admin@localhost IDENTIFIED BY '$mysql_admin_password';"
        printf "Database:\n-name: $database_name\n-user: $database_user\n-pass: $database_password\n"
        echo -n "Config file... "
        config_file=$site_dir"/config_spanel.php"
        if ! touch $config_file; then
            echo "ERROR (creating)."
        else
            if ! printf "<?php\n\$mysql=array();\n\$mysql['host']='localhost';\n\$mysql['name']='$database_name';\n\$mysql['user']='$database_user';\n\$mysql['pass']='$database_password';\n" > $config_file; then
                echo "ERROR (writing)."
            else
                echo "done."
            fi
        fi
    fi
}
remove_nginx_host() {
    # $1=hostname;
    conf_file_name=`nginx_vhost_conf_name ${1}`
    if [ -f "${sites_enabled}/${conf_file_name}" ]; then
        rm "${sites_enabled}/${conf_file_name}"
    fi
    if [ -f "${sites_available}/${conf_file_name}" ]; then
        rm "${sites_available}/${conf_file_name}"
    fi
    ${CERTBOT_PATH} delete --cert-name "${1}"
}

remove() {
    conf_file_name=`nginx_vhost_conf_name ${1}`
    config_nginx="${sites_available}/${conf_file_name}"
    if [ -f $config_nginx ]; then
        echo ""
        echo "CLEANING THE DATABASE"
        site_dir=`cat $config_nginx | grep config_path | sed -e "s/root \(.*\); # config_path \(.*\)/\2/g"`
        echo $site_dir
        config_php=$site_dir"/config.php"
        if [ -f $config_php ]; then
            database_name=`cat $config_php | grep name | sed -e "s/.*='\(.*\)';/\1/g"`
            database_user=`cat $config_php | grep user | sed -e "s/.*='\(.*\)';/\1/g"`
        else
            echo "Can't find the config.php file!"
            read -p "Remove the database manually? [Y/n]:" remove_database
            if [ "$remove_database" != "n" ] && [ "$remove_database"!="N" ]; then
                read -p "MySQL database name: " database_name
                read -p "MySQL database user: " database_user
            fi
        fi
        if [ "$database_name" != "" ] && [ "$database_user" != "" ]; then
            $mysql -uroot -p$mysql_password -e "DROP DATABASE $database_name;"
            $mysql -uroot -p$mysql_password -e "DROP USER '$database_user'@localhost;"
        fi
        echo ""
        echo "REMOVING $1 VIRTUALHOST"
        read -p "Remove $site_dir? [y/N]: " remove_dir
        echo -n "Web root... "
        if [ "$remove_dir" != "y" ] && [ "$remove_dir" != "Y" ]; then
            echo "untouched."
        else
            if [ ! rm -r $site_dir ]; then
                echo "ERROR."
            else
                echo "removed."
            fi
        fi
        remove_nginx_host $1
    else
        echo "Can't find the config file $config_nginx"
    fi
}

certbot_update_all() {
    ${CERTBOT_PATH} renew --webroot -w "${LETSENCRYPT_ROOT}" --post-hook "service nginx reload"
}

# Receive a path as an argument, make it writable to the web server
# Optionally block HTTP access to that item and block PHP execution
permit_writing() {
    # remove the trailing slash, if any
    ROOT=${www_root%/}
    ITEMPATH=${1%/}
    # validate the item is inside the web root
    case ${ITEMPATH} in
        "${ROOT}"*)
            ;;
        *)
            echo "A writable file or folder has to be inside the web root"
            exit 1
            ;;
    esac
    # Confirm the path
    echo "Setting ${ITEMPATH} to be writable by the web server."
    # Collect input
    read -p "Clear the contents? [Y/n]: " RM_Yn
    if [ "${RM_Yn}" = "" ] || [ "${RM_Yn}" = "Y" ]; then
        RM_Yn="y"
    fi
    read -p "Block HTTP access? (Recommended.) [Y/n]: " BH_Yn
    if [ "${BH_Yn}" = "" ] || [ "${BH_Yn}" = "Y" ]; then
        BH_Yn="y"
    fi
    if [ -d "${ITEMPATH}" ] && [ "y" != "${BH_Yn}" ]; then
        echo "Leaving a folder both writable and accessible may let attackers upload, access and execute malicious scripts inside it."
        read -p "Block PHP execution? (Highly recommended.) [Y/n]: " BP_Yn
        if [ "${BP_Yn}" = "" ] || [ "${BP_Yn}" = "Y" ]; then
            BP_Yn="y"
        fi
    fi
    # clean up, if requested
    if [ "y" = "${RM_Yn}" ]; then
        if [ -d "${ITEMPATH}" ]; then
            rm -rf "${ITEMPATH}"/*
        elif [ -f "${ITEMPATH}" ]; then
            echo "" > "${ITEMPATH}"
        fi
    fi
    # set the writing permisions
    chgrp -R www-data "${ITEMPATH}"
    chmod g+ws "${ITEMPATH}" # chmod the folder and newly created items
    if [ -d "${ITEMPATH}" ] && [ "y" != "${RM_Yn}" ]; then
        # find and chmod the subfolders, if any
        find "${ITEMPATH}" -type d -exec chmod g+ws {} \;
    fi
    # abort if no HTTP or PHP blocking is requested
    if [ "y" != "${BH_Yn}" ] && [ "y" != "${BP_Yn}" ]; then
        exit 0
    fi
    # traverse the tree looking for .ngaccess
    TRY_PATH="${ITEMPATH}" # start with the given path
    # until we hit the web root
    NGACCESS=""
    while [ "${TRY_PATH}" != "${ROOT}" ]; do
        if [ -e "$TRY_PATH/.ngaccess" ]; then
            NGACCESS="$TRY_PATH/.ngaccess"
            break
        else
            # go one level deeper
            TRY_PATH=$(dirname $TRY_PATH)
        fi
    done
    # if the file was found
    if [ -e "${NGACCESS}" ]; then
        ITEMPATH_WEB=$(echo "${ITEMPATH}" | sed -e "s@${TRY_PATH}@@g")
        if [ "y" = "${BH_Yn}" ]; then
cat >> "${NGACCESS}" << BHEOF
location ~ ${ITEMPATH_WEB} {
    return 404;
}
BHEOF
        fi
        if [ "y" = "${BP_Yn}" ]; then
cat >> "${NGACCESS}" << BHEOF
location ~* ${ITEMPATH_WEB}/.*\.php {
    return 404;
}
BHEOF
        fi
        service nginx reload
    else
        echo "Could not find a .ngaccess file. Stopped at ${TRY_PATH}"
    fi

}

# this whitelists/removes the passed (space-separated) IPs with iptables
manage_trusted_ips() {
    if [ -z "${1}" ]; then
        echo "The list of IPs is empty. Please provide them space-separated."
        exit 1;
    fi
    WHTLST_IPS="${1}"
    # collect the ports from the after-install config
    CONF_PATH="/root/.bonjour.ini"
    SSH_PORT=$(cfget -qC "${CONF_PATH}" "SSH_PORT")
    FTP_PORT=$(cfget -qC "${CONF_PATH}" "FTP_PORT")
    MYSQL_PORT=$(cfget -qC "${CONF_PATH}" "MYSQL_PORT")
    if [ -z "${SSH_PORT}" ] && [ -z "${FTP_PORT}" ] && [ -z "${MYSQL_PORT}" ]; then
        echo "No ports to secure found in ${CONF_PATH}."
        exit 1;
    fi
    # make a space-separated list of ports to loop through
    WHTLST_PORTS="${SSH_PORT} ${FTP_PORT} ${MYSQL_PORT}"
    # pick variables depending on the requested action
    case "${2}" in
        "add")
            MSG_VERB="Trusting"
            CMD="I" # use -I to make these rules apply first in the chain
            ;;
        "remove")
            MSG_VERB="Distrusting"
            CMD="D"
            ;;
    esac
    # output a confirmation message
    echo "${MSG_VERB} '${WHTLST_IPS}' with port(s) '${WHTLST_PORTS}'"
    # configure iptables
    for PORT in ${WHTLST_PORTS}; do
        for IP in ${WHTLST_IPS}; do
            iptables -${CMD} INPUT -p tcp --dport ${PORT} -s ${IP} -j ACCEPT
            iptables -${CMD} OUTPUT -p tcp --sport ${PORT} -d ${IP} -j ACCEPT
        done
    done
    # back up iptables (minus the fail2ban rules)
    iptables-save|grep -vP '^(?:(-A f2b-|:f2b-)|-A INPUT\b.* -j f2b-)'>/etc/iptables.conf
    # configure fail2ban's 'ignoreip'
    F2BCONF="/etc/fail2ban/jail.local" # fail2ban configuration file path
    # get currently ignored IPs
    F2B_IPS=$(grep 'ignoreip' ${F2BCONF} | cut -d '=' -f 2)
    # if we're adding more ignored IPs
    if [ "add" = "${2}" ]; then
        # simply concat for now; will remove duplicates (if any) below
        F2B_IPS_NEW="${F2B_IPS} ${WHTLST_IPS}"
    # otherwise, if we're removing currently ignored IPs
    elif [ "remove" = "${2}" ]; then
        F2B_IPS_NEW=""
        # loop through each currently ignored IP
        for F2B_IP in ${F2B_IPS}; do
            # match it against the list of IPs to be removed from ignored
            case "${WHTLST_IPS}" in
                *${F2B_IP}*)
                    # if there's a match, do not include into the updated list
                    ;;
                *)
                    # otherwise, include into the updated list
                    F2B_IPS_NEW="${F2B_IPS_NEW} ${F2B_IP}"
                    ;;
            esac
        done
    fi
    # remove duplicate entries; remove extra spaces
    F2B_IPS_NEW=$(echo "${F2B_IPS_NEW}" | tr ' ' '\n' | sort -u | xargs)
    # update fail2ban configuration
    sed -i "s/^#* *ignoreip *= *[^$]*/ignoreip = ${F2B_IPS_NEW}/" ${F2BCONF}
    echo "Fail2Ban set to ignore '${F2B_IPS_NEW}'"
}

backup_user_add() {
    # generate the backup user account name
    BACKUSER_DEFAULT="backup$(date -u "+%N" | cut -c 1,2,4,8)"
    # prompt for the backup user account name
    read -p "Backup user account name [${BACKUSER_DEFAULT}]: " BACKUSER
    if [ -z "${BACKUSER}" ]; then
        BACKUSER=${BACKUSER_DEFAULT}
    fi
    # store their home folder in a variable
    BACKHOME="/home/${BACKUSER}"
    # get the gnu rush path
    PATHRUSH=$(which rush)
    # add the backup user
    echo "Creating user ${BACKUSER}"
    useradd -md "${BACKHOME}" -g www-data -s ${PATHRUSH} ${BACKUSER}
    # allow the user with ssh - but only if AllowUsers is actually being used
    sed -i "s/^ *AllowUsers [^$]*/& ${BACKUSER}/" /etc/ssh/sshd_config
    # create their .ssh folder
    mkdir -p "${BACKHOME}/.ssh"
    # prompt for the authorized key
    read -p "A public key from the backup server: " BACKKEY
    # save the authorized key
    echo ${BACKKEY} > "${BACKHOME}/.ssh/authorized_keys"
    # restart sshd
    service sshd restart
    # trust backup server IP address
    read -p "Backup server IP address: " BACKADDR
    manage_trusted_ips "${BACKADDR}" "add"
}

# always make sure this script is executable (for e.g. cron)
if [ ! -x "${0}" ]; then
    chmod +x "${0}"
fi

manage_http_basic_auth() {
    # prepare the variables
    WEBROOT=$(pwd)
    WEBCONF=$(grep -FliR -m 1 --color=never "root ${WEBROOT};" ${sites_available})
    HTTP_HTPA="${WEBCONF}.htpasswd"
    HTTP_USER="${1}"
    # if we're setting a password for the user
    if [ "${2}" = "on" ]; then
        # can't continue if the username is empty
        if [ -z "${1}" ]; then
            echo "Please provide a username"
            exit 1;
        fi
        # read the password, or use the randomly generated one
        HTTP_PASS_RAND=$(random_string -l 24)
        read -p "HTTP Password for ${HTTP_USER} [${HTTP_PASS_RAND}]: " HTTP_PASS
        if [ "_${HTTP_PASS}" = "_" ]; then
            HTTP_PASS=${HTTP_PASS_RAND}
        fi
        # add the user entry if it doesn't exist yet
        touch "${HTTP_HTPA}"
        if ! grep -q "${HTTP_USER}:" "${HTTP_HTPA}"; then
            printf "${HTTP_USER}:\n" >> ${HTTP_HTPA}
        fi
        # update the password
        HTTP_HASH=$(openssl passwd -apr1 ${HTTP_PASS})
        sed -i "s|${HTTP_USER}:[^ ]*|${HTTP_USER}:${HTTP_HASH}|" ${HTTP_HTPA}
        # add auth_basic to nginx configuration, if not already present
        if ! grep -q "auth_basic" "${WEBCONF}"; then
            HTTP_AUTH="auth_basic \"Auth\";\nauth_basic_user_file ${HTTP_HTPA};"
            sed -i "/^ *server {$/ a ${HTTP_AUTH}" ${WEBCONF}
        fi
    else
        # if a specific user is requested, delete it from the passwords file
        if [ "_${HTTP_USER}" != "_off" ]; then
            echo "Deleting ${HTTP_USER} from ${HTTP_HTPA}."
            sed -i "/^${HTTP_USER}:/d" ${HTTP_HTPA}
        fi
        # if the passwords file is now empty, or if disabling auth requested
        if [ ! -s ${HTTP_HTPA} ] || [ "_${HTTP_USER}" = "_off" ]; then
            # delete the passwords file if it exists
            if [ -f "${HTTP_HTPA}" ]; then
                echo "Deleting ${HTTP_HTPA}"
                rm "${HTTP_HTPA}"
            fi
            # remove the auth_basic directives from the nginx config
            echo "Deleting the auth_basic directives"
            sed -i '/^auth_basic/d' ${WEBCONF}
        fi
    fi
    service nginx restart
}

echo "ACTION: ${1}"
### What to do?
case "${1}" in
    "remove")
        if [ "${2}" = "" ]; then
            echo "Please specify the primary hostname"
            exit 1;
        fi
        remove "${2}"
        restart_nginx
        ;;
    "add")
        if [ "${2}" = "" ]; then
            echo "Please specify the primary hostname"
            exit 1;
        fi
        add "${2}"
        restart_nginx
        ;;
    "certupdate")
        certbot_update_all
        ;;
    "writable")
        permit_writing "${2}"
        ;;
    "trust")
        manage_trusted_ips "${2}" "add"
        ;;
    "distrust")
        manage_trusted_ips "${2}" "remove"
        ;;
    "backup")
        backup_user_${2}
        ;;
    "update")
        VAR_JSON="/tmp/spanel.json"
        wget -nv -O "${VAR_JSON}" https://api.github.com/repos/mehov/debian-automation/contents/spanel/spanel.sh
        VAR_DL=$(grep --color=never -Po '"download_url":.*?[^\\]",' "${VAR_JSON}" | cut -d '"' -f4)
        VAR_TMP="${0}.tmp"
        wget -nv -O "${VAR_TMP}" "${VAR_DL}"
        VAR_LSHA=$(cat "${VAR_TMP}" | git hash-object --stdin)
        VAR_RSHA=$(grep --color=never -Po '"sha":.*?[^\\]",' "${VAR_JSON}" | cut -d '"' -f4)
        if [ "_${VAR_LSHA}" = "_${VAR_RSHA}" ]; then
            cat "${VAR_TMP}" > "${0}"
        else
            printf "Checksum mismatch:\n"
            printf "  ${VAR_LSHA} ${VAR_TMP}\n"
            printf "  ${VAR_RSHA} ${VAR_DL}\n"
        fi
        # clean up
        rm "${VAR_TMP}" "${VAR_JSON}"
        ;;
    "password")
        # make sure a website to work with is selected
        WEBROOT=$(pwd)
        WEBCONF=$(grep -FliR -m 1 --color=never "root ${WEBROOT};" ${sites_available})
        if [ -z "${WEBCONF}" ]; then
            echo "Please cd to a folder that contains a Nginx-hosted website."
            exit 1;
        fi
        # disabling auth if requested, regardless of the user account
        if [ "_${2}" = "_off" ]; then
            echo "Disabling HTTP Basic Auth for this website."
            manage_http_basic_auth "${2}" "off"
            exit 0;
        fi
        HTTP_HTPA="${WEBCONF}.htpasswd"
        # if the passwords file exists
        if [ -f "${HTTP_HTPA}" ]; then
            # and if the requested user is already listed in the passwords file
            if grep -q "${2}:" "${HTTP_HTPA}"; then
                # ask whether to delete the user or update password
                read -p "User ${HTTP_USER} exists. Update or delete? [U/d]:" HTTP_ACT
                if [ "_${HTTP_ACT}" = "_d" ] || [ "_${HTTP_ACT}" = "_D" ]; then
                    echo "Disabling HTTP Basic Auth for ${2}."
                    manage_http_basic_auth "${2}" "off"
                    exit 0;
                fi
            fi
        fi
        # otherwise, set password for the user (regardless of whether it exists already)
        echo "Configuring HTTP Basic Auth for ${2}."
        manage_http_basic_auth "${2}" "on"
        ;;
    *)
        echo "**** USAGE:"
        echo "spanel [add|remove] example.com"
        exit 1;
        ;;
esac
