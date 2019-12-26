#!/bin/sh

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
    read -p "Add www.$1? [Y/n]: " WWW_Yn
    if [ "${WWW_Yn}" = "" ] || [ "${WWW_Yn}" = "Y" ] || [ "${WWW_Yn}" = "y" ]; then
        aliases="www.$1"
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

    if [ -z $3 ]; then
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

    read -p "Create a separate FTP/UNIX user? [Y/n]: " create_user
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
        chown $ftp_user:www-data $site_dir
    fi
    if ! [ -d $site_dir ]; then
        echo "ERROR: "$site_dir" could not be created."
    else
        echo $site_dir" OK"
        if [ "$create_public_dir" = "y" ] || [ "$create_public_dir" = "Y" ];then
            public_dir=$site_dir"/"$public_dir_name_default
            mkdir $public_dir
            chown $ftp_user:www-data $public_dir
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
    echo "# FTP p:${FTP_PORT} u:${website_user} p:${wdpassword}" >> ${ngaccess_file}
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
    chown -R ${website_user}:www-data ${site_dir}
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

# Receive a folder path as an argument, make it writable to the web server
# Optionally block HTTP access to that folder, or block PHP execution
permit_folder_writing() {
    # remove the trailing slash, if any
    ROOT=${www_root%/}
    DIR=${1%/}
    # validate the folder is inside web root
    case $DIR in
        "${ROOT}"*)
            ;;
        *)
            echo "A writable directory has to be inside the web root"
            exit 1
            ;;
    esac
    # Confirm the folder path
    echo "Setting ${DIR} to be writable by the web server."
    # Collect input
    read -p "Empty the folder? [Y/n]: " RM_Yn
    if [ "${RM_Yn}" = "" ] || [ "${RM_Yn}" = "Y" ]; then
        RM_Yn="y"
    fi
    read -p "Block HTTP access? (Recommended.) [Y/n]: " BH_Yn
    if [ "${BH_Yn}" = "" ] || [ "${BH_Yn}" = "Y" ]; then
        BH_Yn="y"
    fi
    if [ "y" != "${BH_Yn}" ]; then
        echo "Leaving folder both writable and accessible may let attackers upload, access and execute malicious scripts."
        read -p "Block PHP execution? (Highly recommended.) [Y/n]: " BP_Yn
        if [ "${BP_Yn}" = "" ] || [ "${BP_Yn}" = "Y" ]; then
            BP_Yn="y"
        fi
    fi
    # clean up, if requested
    if [ "y" = "${RM_Yn}" ]; then
        rm -rf "${DIR}"/*
    fi
    # set the writing permisions
    chgrp -R www-data "${DIR}"
    chmod g+ws "${DIR}"
    # abort if no HTTP or PHP blocking is requested
    if [ "y" != "${BH_Yn}" ] && [ "y" != "${BP_Yn}" ]; then
        exit 0
    fi
    # traverse the tree looking for .ngaccess
    TRY_PATH="${DIR}" # start with the given path
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
        DIR_WEB=$(echo "${DIR}" | sed -e "s@${TRY_PATH}@@g")
        if [ "y" = "${BH_Yn}" ]; then
cat >> "${NGACCESS}" << BHEOF
location ~ ${DIR_WEB} {
    return 404;
}
BHEOF
        fi
        if [ "y" = "${BP_Yn}" ]; then
cat >> "${NGACCESS}" << BHEOF
location ~* ${DIR_WEB}/.*\.php {
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
        permit_folder_writing "${2}"
        ;;
    "trust")
        manage_trusted_ips "${2}" "add"
        ;;
    "distrust")
        manage_trusted_ips "${2}" "remove"
        ;;
    *)
        echo "**** USAGE:"
        echo "spanel [add|remove] example.com"
        exit 1;
        ;;
esac