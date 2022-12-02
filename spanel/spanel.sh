#!/bin/bash

### Checking for user
if [ "$(whoami)" != 'root' ]; then
    echo "You have no permission to run $0 as a non-root user."
    exit 1;
fi

header() {
    printf "\n\n"
    echo "**** [$(date +%T.%N%z)] ${1}"
}
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
input "noninteractive" "" false # never prompt; false by default, true if passed

ini_get() {
    PATH_INI="/root/.bonjour.ini"
    if ! grep -q "^${1}=" "${PATH_INI}"; then
        return 0
    fi
    BIN_CRUDINI=$(which crudini)
    if [ -n "${BIN_CRUDINI}" ]; then
        echo $(${BIN_CRUDINI} --get ${PATH_INI} "" "${1}")
        return 0
    fi
    BIN_CFGET=$(which cfget)
    if [ -n "${BIN_CFGET}" ]; then
        echo $(${BIN_CFGET} -qC ${PATH_INI} "${1}")
        return 0
    fi
}

### Script params
CERTBOT_PATH=$(ini_get "CERTBOT_PATH")
www_root=$(ini_get "WWW_ROOT")
ftp_user=$(ini_get "FTP_USER")
FTP_PORT=$(ini_get "FTP_PORT")
if ! [ id -u "$ftp_user" >/dev/null 2>&1 ]; then
    ftp_user="www-data"
fi
nginx_conf_dir="/etc/nginx"
sites_available="${nginx_conf_dir}/sites-available"
sites_enabled="${nginx_conf_dir}/sites-enabled"
mysql="$(which mysql)"
# mysql root password
mysql_password=$(ini_get "MYSQL_ROOT_PASS")
mysql_admin=$(ini_get "MYSQL_REMO_USER")
mysql_admin_password=$(ini_get "MYSQL_REMO_PASS")

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
        command='reload'
    else
        command='start'
    fi
    service nginx $command
}
add_alias() {
    if [ -n "$1" ]; then
        _aliases=${_aliases}" "$1
    fi
    read -p "Enter another alias (leave blank to skip): " newalias
    if [ "$newalias" != "" ]; then
        ### loop
        add_alias $newalias
    fi
}

nginx_vhost_conf_name() {
    echo "vhost-${1}.conf"
}
add() {
    HOST=$1
    conf_file_name=`nginx_vhost_conf_name ${HOST}`
    if [ -f "${sites_available}/${conf_file_name}" ]; then
        input "force" "Host ${HOST} exists on this system. Continue?" false
        if ! ${_force}; then
            header "Host ${HOST} exists on this system. Aborting"
            return 0
        fi
    fi
    # Aliases
    input "aliases" "Enter alias (leave blank to skip)"
    if ! ${_noninteractive} && [ -n "${_aliases}" ]; then
        add_alias
    fi
    # Letsencrypt
    LE_PROMPT="\n"
    LE_PROMPT=${LE_PROMPT}"You can get a free SSL/TLS certificate from Let's Encrypt.\n"
    LE_PROMPT=${LE_PROMPT}"Warning: your domain will be listed in public "
    LE_PROMPT=${LE_PROMPT}"certificate transparency logs, such as:\n\n"
    LE_PROMPT=${LE_PROMPT}"- https://transparencyreport.google.com/https/certificates\n"
    LE_PROMPT=${LE_PROMPT}"- https://crt.sh\n\n"
    LE_PROMPT=${LE_PROMPT}"Use Let's Encrypt?"
    input "letsencrypt" "$(echo -e $LE_PROMPT)" true
    # Site path
    input "dir" "Enter site directory path" "$(ini_get WWW_ROOT)/$HOST"
    input "dir_public" "" "${_dir}"
    # MySQL
    database_name_random=`echo $1 | sed -e 's/\W//g'`;
    database_user_random=`random_string -l 16`
    database_password_waitforit_random=`random_string -l 16`
    if [ -n "$(ini_get MYSQL_PORT)" ]; then
        input "database" "Create MySQL database?" true
        if ${_database}; then
            input "database_name" "Enter MySQL database name" $database_name_random
            input "database_user" "Enter MySQL user" $database_user_random
            input "database_password" "Enter MySQL password for '${_database_user}'" $database_password_waitforit_random
        fi
    fi
    # FTP
    if [ -n "$(ini_get FTP_PORT)" ]; then
        input "user" "Create a separate FTP/UNIX user?" false
        if ${_user}; then
            secondlvldomain=`echo $HOST | cut -d "." -f 1`
            input "user_name" "FTP/UNIX user" "www-usr-${secondlvldomain}"
            input "user_password" "Password for '${_user_name}'" `random_string -l 16`
            cppassword=$(perl -e 'print crypt($ARGV[0], "password")' ${_user_password})
            if id -u ${_user_name} >/dev/null 2>&1; then
                pkill -u ${_user_name}
                killall -9 -u ${_user_name}
                usermod --password=${cppassword} --home="${_dir}" ${_user_name}
            else
                useradd -d "${_dir}" -p ${cppassword} -g www-data -s /bin/sh -M ${_user_name}
            fi
        fi
    fi
    # Adding
    echo ""
    echo "ADDING VIRTUALHOST $1"
    echo -n "Web root... "
    if ! [ -d ${_dir} ]; then
        mkdir ${_dir}
    fi
    if [ -d ${_dir} ]; then
        echo ${_dir}" OK"
    else
        echo "ERROR: "${_dir}" could not be created."
        exit
    fi
    if [ -n "${_dir_public}" ] && ! [ -d ${_dir_public} ]; then
        mkdir -p "${_dir_public}"
    fi
    ngaccess_file="${_dir}/.ngaccess"
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
    if [ -n "$(ini_get FTP_PORT)" ] && ${_user}; then
        echo "# FTP $(ini_get FTP_PORT) ${_user_name}:${_user_password}" >> ${ngaccess_file}
    fi
    if [ -f "${sites_available}/${conf_file_name}" ]; then
        rm "${sites_available}/${conf_file_name}"
    fi
    if [ ! -z "${_aliases}" ]; then
cat >> "${sites_available}/${conf_file_name}" << EOF
server {
listen 80;
server_name ${_aliases};
access_log /var/log/nginx/${HOST}-aliases.access.log;
error_log /var/log/nginx/${HOST}-aliases.error.log;
include snippets/vhost-letsencrypt.conf;
location / {
    return 301 http://${HOST}\$request_uri;
}
}
EOF
fi
cat >> "${sites_available}/${conf_file_name}" << EOF
    server {
        listen 80;
        server_name ${HOST};
        access_log /var/log/nginx/${HOST}.access.log;
        error_log /var/log/nginx/${HOST}.error.log;
        root ${_dir_public}; # config_path ${_dir}
        include snippets/vhost-letsencrypt.conf;
        include snippets/vhost-common.conf;
    }
EOF
    if ! [ -f "${sites_enabled}/${conf_file_name}" ]; then
        ln -s "${sites_available}/${conf_file_name}" "${sites_enabled}/${conf_file_name}"
    fi
    if ${_letsencrypt} && [ -n "${CERTBOT_PATH}" ] && [ -f "${CERTBOT_PATH}" ]; then
        restart_nginx # restart so the host goes live and is verifiable
        domains="${HOST}"
        for alias in ${_aliases}; do
            domains="${domains},${alias}"
        done
        letsencrypt_email="webmaster@${HOST}"
        printf "Requesting a certificate from Let's Encrypt:\n"
        printf " - email:   ${letsencrypt_email}\n"
        printf " - domains: ${domains}\n"
        echo "${CERTBOT_PATH} certonly --non-interactive --agree-tos --standalone --http-01-port 8008 --email \"${letsencrypt_email}\" -d \"${domains}\""
        "${CERTBOT_PATH}" certonly --non-interactive --agree-tos --standalone --http-01-port 8008 --email "${letsencrypt_email}" -d "${domains}"
        if [ ! -r "/etc/letsencrypt/live/${HOST}/fullchain.pem" ]; then
            echo "Can't find the certificate file. Aborting."
            if [ -f "${sites_available}/${conf_file_name}" ]; then
                rm "${sites_available}/${conf_file_name}"
            fi
            if [ -h "${sites_enabled}/${conf_file_name}" ]; then
                rm "${sites_enabled}/${conf_file_name}"
            fi
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
if [ ! -z "${_aliases}" ]; then
    cat >> "${sites_available}/${conf_file_name}" << EOF
    server {
        listen 443 ssl http2;
        server_name ${_aliases};
        ssl_certificate /etc/letsencrypt/live/${HOST}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${HOST}/privkey.pem;
        include snippets/vhost-ssl.conf;
        location / {
            return 301 https://${HOST}\$request_uri;
        }
    }
EOF
fi
cat >> "${sites_available}/${conf_file_name}" << EOF
    server {
        listen 443 ssl http2;
        server_name ${HOST};
        access_log /var/log/nginx/${HOST}.access.log;
        error_log /var/log/nginx/${HOST}.error.log;
        root ${_dir_public};
        include "${_dir}/.*ngaccess";
        include snippets/vhost-common.conf;
        ssl_certificate /etc/letsencrypt/live/${HOST}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${HOST}/privkey.pem;
        include snippets/vhost-ssl.conf;
    }
EOF
        restart_nginx 
    fi
    if [ -n "$(ini_get MYSQL_PORT)" ] && ${_database}; then
        $mysql -uroot -p$mysql_password -e "CREATE DATABASE \`${_database_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        $mysql -uroot -p$mysql_password -e "GRANT CREATE,SELECT,INSERT,UPDATE,DELETE ON \`${_database_name}\`.* TO ${_database_user}@localhost IDENTIFIED BY '${_database_password}';"
        $mysql -uroot -p$mysql_password -e "GRANT ALL ON \`${_database_name}\`.* TO $mysql_admin@localhost IDENTIFIED BY '$mysql_admin_password';"
        printf "Database:\n-name: ${_database_name}\n-user: ${_database_user}\n-pass: ${_database_password}\n"
        echo -n "Config file... "
        config_file=${_dir}"/config_spanel.php"
        if ! touch $config_file; then
            echo "ERROR (creating)."
        else
            if ! printf "<?php\n\$mysql=array();\n\$mysql['host']='localhost';\n\$mysql['name']='${_database_name}';\n\$mysql['user']='${_database_user}';\n\$mysql['pass']='${_database_password}';\n" > $config_file; then
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
            input "remove_db" "Remove ${database_name} and ${database_user}?" false
            if ${_remove_db}; then
                $mysql -uroot -p$mysql_password -e "DROP DATABASE $database_name;"
                $mysql -uroot -p$mysql_password -e "DROP USER '$database_user'@localhost;"
            fi
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
    ${CERTBOT_PATH} renew --standalone --http-01-port 8008 --allow-subset-of-names --post-hook "service nginx reload"
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
    SSH_PORT=$(ini_get "SSH_PORT")
    FTP_PORT=$(ini_get "FTP_PORT")
    MYSQL_PORT=$(ini_get "MYSQL_PORT")
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
        add "${2}" "" "" "${3}"
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
            printf "Checksum matched. Replacing ${0} with ${VAR_TMP}\n"
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
