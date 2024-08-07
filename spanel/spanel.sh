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
    NAME="${1}" # shorthand to name of requested variable; _ as word separator
    PROMPT="${2}" # shorthand to prompt text
    DEFAULT="${3}" # shorthand to default value
    HELP="${4}" # shorthand to the help text
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
        # 1. parse --KEY out of --KEY=VALUE
        # 2. receive --example-var, convert to __example_var
        #    dashes as word separators are common in command line arguments, but
        #    are not allowed in variable names; input() expects _ as separator
        KEY=$(echo ${ARG} | cut -f1 -d= | tr - _)
        if [ "${KEY}" != "__${NAME}" ]; then # skip keys that don't match
            continue
        fi
        KEY_LENGTH=${#KEY}
        VALUE="${ARG:$KEY_LENGTH+1}" # parse VALUE out of --KEY=VALUE
        if [ -z "${VALUE}" ]; then # this flag has been provided with no value
            header "Received ${ARG}"
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
        if [ ! -z "${HELP}" ]; then
            PROMPT_DEFAULT="${PROMPT_DEFAULT} / (?)" # indicate help is available
        fi
        read -p "${PROMPT}${PROMPT_DEFAULT}: " "VALUE" # finally, prompt
    fi
    if [ "_${VALUE}" = "_?" ] && [ ! -z "${HELP}" ]; then # user asked for help text
        echo -e "\nHELP: ${HELP}"
        input "$@"
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
    if ! grep -q "^${1} *= *" "${PATH_INI}" && [ -z "${2}" ]; then
        return 1
    fi
    BIN_CRUDINI=$(which crudini)
    if [ -n "${BIN_CRUDINI}" ]; then
        if [ -z "${1}" ] && [ ! -z "${2}" ]; then
            echo $(${BIN_CRUDINI} --get ${PATH_INI} "${2}") # "section" only
        else
            echo $(${BIN_CRUDINI} --get ${PATH_INI} "${2}" "${1}") # "section" "key"
        fi
        return 0
    fi
    BIN_CFGET=$(which cfget)
    if [ -n "${BIN_CFGET}" ]; then
        echo $(${BIN_CFGET} -qC ${PATH_INI} "${2}/${1}") # "section/key"
        return 0
    fi
}
ini_set() {
    PATH_INI="/root/.bonjour.ini"
    BIN_CRUDINI=$(which crudini)
    if [ -n "${BIN_CRUDINI}" ]; then
        echo $(${BIN_CRUDINI} --set ${PATH_INI} "${3}" "${1}" "${2}") # "section" "key" "value"
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
    HOST=$(echo $1 | idn)
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
    input "ssl_certificate_dir" "" "/etc/letsencrypt/live/${HOST}" # no prompt, use if passed, default to letsencrypt
    if [ -d "${_ssl_certificate_dir}" ]; then
        # Ignore the folder if it exists but does not contain the certificates
        if [ ! -r "${_ssl_certificate_dir}/fullchain.pem" ] || [ ! -r "${_ssl_certificate_dir}/privkey.pem" ]; then
            _ssl_certificate_dir=""
        fi
    fi
    if [ ! -d "${_ssl_certificate_dir}" ]; then
        LE_PROMPT="\n"
        LE_PROMPT=${LE_PROMPT}"You can get a free SSL/TLS certificate from Let's Encrypt.\n"
        LE_PROMPT=${LE_PROMPT}"Warning: your domain will be listed in public "
        LE_PROMPT=${LE_PROMPT}"certificate transparency logs, such as:\n\n"
        LE_PROMPT=${LE_PROMPT}"- https://transparencyreport.google.com/https/certificates\n"
        LE_PROMPT=${LE_PROMPT}"- https://crt.sh\n\n"
        LE_PROMPT=${LE_PROMPT}"Use Let's Encrypt?"
        input "letsencrypt" "$(echo -e $LE_PROMPT)" true
    fi
    # Site path
    input "dir" "Enter site directory path" "$(ini_get WWW_ROOT)/$HOST"
    input "dir_public" "" "${_dir}"
    # MySQL
    database_name_random=`echo $HOST | sed -e 's/\W//g'`;
    database_user_random=`random_string -l 16`
    database_password_waitforit_random=`random_string -l 16`
    if [ -n "$(ini_get MYSQL_PORT)" ]; then
        input "database" "Create MySQL database?" false
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
        fi
    fi
    # Adding
    echo ""
    echo "ADDING VIRTUALHOST $HOST"
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
    include "${_dir}/.*ngaccess";
    include snippets/vhost-common.conf;
}
EOF
    if ! [ -f "${sites_enabled}/${conf_file_name}" ]; then
        ln -s "${sites_available}/${conf_file_name}" "${sites_enabled}/${conf_file_name}"
    fi
    if [ ! -d "${_ssl_certificate_dir}" ] && ${_letsencrypt} && [ -n "${CERTBOT_PATH}" ] && [ -f "${CERTBOT_PATH}" ]; then
        restart_nginx # restart so the host goes live and is verifiable
        # Before continuing to Let's Encrypt, make sure the host is connectable
        timeout 5 telnet ${HOST} 80 >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            printf "\n"
            echo "Port 80 doesn't seem to be open on ${HOST}. Check firewall."
            echo "(On a cloud platform, make sure an ingress rule is created.)"
            read -p "When ready, press Enter to continue."
        fi
        # Prepare Let's Encrypt request
        domains="${HOST}"
        for alias in ${_aliases}; do
            domains="${domains},${alias}"
        done
        letsencrypt_email="webmaster@${HOST}"
        printf "Requesting a certificate from Let's Encrypt:\n"
        printf " - email:   ${letsencrypt_email}\n"
        printf " - domains: ${domains}\n"
        letsencrypt_args="--agree-tos --standalone --http-01-port 8008 --email ${letsencrypt_email} -d ${domains}"
        echo "${CERTBOT_PATH} certonly --non-interactive ${letsencrypt_args}"
        "${CERTBOT_PATH}" certonly --non-interactive ${letsencrypt_args}
        if [ ! -r "${_ssl_certificate_dir}/fullchain.pem" ] || [ ! -r "${_ssl_certificate_dir}/privkey.pem" ]; then
            printf "\n"
            echo "Certificate couldn't be issued, ${HOST} not added."
            input "letsencrypt_debug" "Debug Let's Encrypt challenges?" true \
            "Re-run certbot with --debug-challenges flag, which stops it after creating the challenge files. The files will remain available for you to manually check if they're accessible and fix connectivity issues, if any. Once ready, stop the process with Ctrl+C and try adding ${HOST} again."
            if ${_letsencrypt_debug}; then
                "${CERTBOT_PATH}" certonly --debug-challenges -v ${letsencrypt_args}
            fi
            echo "Removing ${conf_file_name} from ${sites_available} and ${sites_enabled}"
            if [ -f "${sites_available}/${conf_file_name}" ]; then
                rm "${sites_available}/${conf_file_name}"
            fi
            if [ -h "${sites_enabled}/${conf_file_name}" ]; then
                rm "${sites_enabled}/${conf_file_name}"
            fi
            exit 1
        fi
        chown -R www-data "/etc/letsencrypt/live/${HOST}"
        chown -R www-data "/etc/letsencrypt/archive/${HOST}"
    else
        echo "${_ssl_certificate_dir} exists"
    fi
    # If we have the certificate directory with both certificates after all
    if [ -d "${_ssl_certificate_dir}" ] && [ -r "${_ssl_certificate_dir}/fullchain.pem" ] && [ -r "${_ssl_certificate_dir}/privkey.pem" ]; then
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
    ssl_certificate ${_ssl_certificate_dir}/fullchain.pem;
    ssl_certificate_key ${_ssl_certificate_dir}/privkey.pem;
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
    ssl_certificate ${_ssl_certificate_dir}/fullchain.pem;
    ssl_certificate_key ${_ssl_certificate_dir}/privkey.pem;
    include snippets/vhost-ssl.conf;
}
EOF
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
    if [ -n "$(ini_get FTP_PORT)" ] && ${_user}; then
        cppassword=$(perl -e 'print crypt($ARGV[0], "password")' ${_user_password})
        if id -u ${_user_name} >/dev/null 2>&1; then
            pkill -u ${_user_name}
            killall -9 -u ${_user_name}
            usermod --password=${cppassword} --home="${_dir}" ${_user_name}
        else
            useradd -d "${_dir}" -p ${cppassword} -g www-data -s /bin/sh -M ${_user_name}
        fi
    fi
    chown -R $(ini_get "SSH_USER") "${_dir_public}"
    chown -R $(ini_get "SSH_USER") "${_dir}"
    restart_nginx
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
            input "remove_db" "Remove the database manually?" false
            if ${_remove_db}; then
                read -p "MySQL database name: " database_name
                read -p "MySQL database user: " database_user
            fi
        fi
        if [ "$database_name" != "" ] && [ "$database_user" != "" ]; then
            input "remove_db_confirm" "Remove ${database_name} and ${database_user}?" false
            if ${_remove_db_confirm}; then
                $mysql -uroot -p$mysql_password -e "DROP DATABASE $database_name;"
                $mysql -uroot -p$mysql_password -e "DROP USER '$database_user'@localhost;"
            fi
        fi
        echo ""
        echo "REMOVING $1 VIRTUALHOST"
        input "remove_dir" "Remove $site_dir?" false
        echo -n "Web root... "
        if ! ${_remove_dir}; then
            echo "untouched."
        else
            if [ ! rm -r $site_dir ]; then
                echo "ERROR."
            else
                echo "removed."
            fi
        fi
        conf_file_name=`nginx_vhost_conf_name ${1}`
        if [ -f "${sites_enabled}/${conf_file_name}" ]; then
            rm "${sites_enabled}/${conf_file_name}"
        fi
        if [ -f "${sites_available}/${conf_file_name}" ]; then
            rm "${sites_available}/${conf_file_name}"
        fi
        input "letsencrypt" "Delete the certbot certificate for ${1}?" true
        if ${_letsencrypt}; then
            ${CERTBOT_PATH} delete --non-interactive --cert-name "${1}"
        fi
    else
        echo "Can't find the config file $config_nginx"
    fi
}

certbot_update_all() {
    CHOWN_PATH=$(which chown)
    SERVICE_PATH=$(which service)
    ${CERTBOT_PATH} renew --non-interactive --standalone --http-01-port 8008 --allow-subset-of-names --deploy-hook "${CHOWN_PATH} -R www-data \"\$RENEWED_LINEAGE\" && ${CHOWN_PATH} -R www-data /etc/letsencrypt/archive && ${SERVICE_PATH} nginx reload"
}

# Receive a path as an argument, make it writable to the web server
# Optionally block HTTP access to that item and block PHP execution
# Optionally create the item if it does not exist and its type is known
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
    # Collect input
    if [ -e "${ITEMPATH}" ]; then # if the item exists
        echo "Setting ${ITEMPATH} to be writable by the web server."
        input "clear" "Clear the contents?" true
    else # try to create it if we know the type (file or directory)
        input "type" "Should ${ITEMPATH} be a file or a directory? [f/d]" ""
        if [ "_${_type}" = "_f" ]; then
            mkdir -p "$(dirname "${ITEMPATH}")" # ensure parent directory exists
            touch "${ITEMPATH}"
        elif [ "_${_type}" = "_d" ]; then
            mkdir -p "${ITEMPATH}"
        fi
    fi
    if [ ! -e "${ITEMPATH}" ]; then # final check
        echo "${ITEMPATH} does not exist"
        exit 1
    fi
    input "nohttp" "Block HTTP access? (Recommended.)" true
    if [ -d "${ITEMPATH}" ] && ! ${_nohttp}; then
        echo "Leaving a folder both writable and accessible may let attackers upload, access and execute malicious scripts inside it."
        input "nophp" "Block PHP execution? (Highly recommended.)" true
    fi
    # clean up, if requested
    if ${_clear}; then
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
    if ! ${_nohttp} && ! ${_nophp}; then
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
            TRY_PATH=$(dirname "$TRY_PATH")
        fi
    done
    # if the file was found
    if [ -e "${NGACCESS}" ]; then
        ITEMPATH_WEB=$(echo "${ITEMPATH}" | sed -e "s@${TRY_PATH}@@g")
        if ${_nohttp}; then
cat >> "${NGACCESS}" << BHEOF
location ~ ${ITEMPATH_WEB} {
    return 404;
}
BHEOF
        fi
        if ${_nophp}; then
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

# Receives user@host[:port] and sets it up as a backup destination
backup_add() {
    input "destination" "Backup destination in user@host[:port] format"
    # The :22 ensures predictable behaviour; see unix.stackexchange.com/a/465596
    destination_userhost=$(echo "${_destination}:22" | cut -f1 -sd:)
    destination_port=$(echo "${_destination}:22" | cut -f2 -sd:)
    destination_user=$(echo "${destination_userhost}" | cut -d'@' -f1)
    # Test if we can SSH into the destination server
    ssh -p "${destination_port}" "${destination_userhost}" exit
    destination_check=$? # shorthand
    if [ ${destination_check} -ne 0 ]; then
        printf "\nCan not SSH into ${destination_userhost} on port ${destination_port}. Make sure:\n- either PasswordAuthentication is enabled, or\n- this server's public key is added to ${destination_user}'s authorized_keys, normally /home/${destination_user}/.ssh/authorized_keys\n\nThe public key is:\n$(cat ~/.ssh/id_rsa.pub)\n"
        exit
    fi
    # Test if rsnapshot is available on the destination server
    ssh -p "${destination_port}" "${destination_userhost}" "command -v rsnapshot >/dev/null 2>&1"
    destination_rsnapshot_check=$? # shorthand
    if [ ${destination_rsnapshot_check} -ne 0 ]; then
        echo "Make sure rsnapshot is installed on the destination server"
        exit
    fi
    # Convert to ASCII so that it can serve as a key in an INI file
    destination_hexadecimal=$(echo -n "${_destination}" | od -A n -t x1 | tr -d ' \n')
    # Local restricted user on this machine the destination server will SSH into
    _backup_user=$(ini_get "${destination_hexadecimal}" "backup") # check if already defined
    if [ -z "${_backup_user}" ]; then
        input "backup_user" "Local user account" \
        "bkup$(date -u "+%N" | cut -c 1,2,4,8)" \
        "Local account for the backup destination server to SSH into"
        ini_set "${destination_hexadecimal}" "${_backup_user}" "backup"
    else
        echo "Local user account for ${_destination} is ${_backup_user}"
    fi
    backup_user_home="/home/${_backup_user}"
    if ! id "${_backup_user}" >/dev/null 2>&1; then
        echo "Creating user ${_backup_user}"
        useradd -md "${backup_user_home}" -g www-data -s /bin/bash "${_backup_user}"
    else
        echo "User ${_backup_user} exists"
    fi
    # Set up SSH access for the backup user
    #sed -i "s/AllowUsers [^$]*/& ${_backup_user}/" /etc/ssh/sshd_config
    grep -qE "AllowUsers .*${_backup_user}(\$|\\s)" /etc/ssh/sshd_config \
        || sed -i "/AllowUsers/s/\$/ ${_backup_user}/" /etc/ssh/sshd_config

    mkdir -p "${backup_user_home}/.ssh"
    touch "${backup_user_home}/.ssh/authorized_keys"
    # Authorise destination server public key here with the local backup user
    input "destination_identity" "Path to the private key on the destination server" "~/.ssh/id_rsa"
    # Check if the given key exists on the destination server
    ssh -p "${destination_port}" "${destination_userhost}" "[ -e ${_destination_identity} ]"
    if [ ${?} -ne 0 ]; then
        echo "Key ${_destination_identity} does not exist on ${_destination}"
        exit 2
    fi
    # Try to read the contents of the public key into a variable
    destination_pubkey_content=$(ssh -p "${destination_port}" \
        "${destination_userhost}" "cat ${_destination_identity}.pub")
    # Validate the public key
    echo "${destination_pubkey_content}" | ssh-keygen -l -f - 2>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "The public key in ${_destination_identity}.pub is not valid"
        exit 2
    fi
    # Append public key to backup user's authorized_keys if it's not there yet
    grep -qE "${destination_pubkey_content}" "${backup_user_home}/.ssh/authorized_keys" \
        || echo "command=\"$(which rrsync) -ro /\",no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding ${destination_pubkey_content}" >> "${backup_user_home}/.ssh/authorized_keys"
    # Allowing destination server IP to connect to SSH on this machine
    manage_trusted_ips "$(echo "${destination_userhost}" | cut -d'@' -f2)" "add"
    # Restart the ssh
    service sshd restart
    # Shorthand
    this_port=$(ini_get SSH_PORT)
    this_host=$(hostname -I | xargs) # xargs to trim whitespace
    # Add this machine to destination server known_hosts
    ssh -p "${destination_port}" "${destination_userhost}" \
        "ssh-keyscan -p ${this_port} ${this_host} >> ~/.ssh/known_hosts"
    # Pre-configure SSH connections to this machine on the destination server
    ssh -p "${destination_port}" "${destination_userhost}" \
        "printf \"Host ${this_host}\nPort ${this_port}\nIdentityFile ${_destination_identity}\n\n\" >> ~/.ssh/config"
    # Configure rsnapshot on the destination server
    ssh -p "${destination_port}" "${destination_userhost}" << EOF
# set cron to run backups as the non-root user
sudo sed -i "s|root|${destination_user}|g" /etc/cron.d/rsnapshot
# enable sample schedule
sudo sed -i 's|^#\s*\([0-9*]\)|\1|' /etc/cron.d/rsnapshot
# delete first rule (that actually does backups) as it will be triggered externally
sudo sed -i '/ alpha\$/d' /etc/cron.d/rsnapshot
# uncomment and enable cmd_ssh
sudo sed -i "s|#@CMD_SSH@\t|@CMD_SSH@	|g" /etc/rsnapshot.conf
sudo sed -i "s|#cmd_ssh\t|cmd_ssh	|g" /etc/rsnapshot.conf
# set the backup storage folder to be /var/backups/rsnapshot
sudo sed -i "s|snapshot_root\t\(.*\)|snapshot_root	/var/backups/rsnapshot|g" /etc/rsnapshot.conf
# set up logging and lockfile
sudo mkdir -p "/var/log/rsnapshot" "/var/run/rsnapshot" "/var/backups/rsnapshot"
sudo chown -R "${destination_user}" "/var/log/rsnapshot" "/var/run/rsnapshot" "/var/backups/rsnapshot"
sudo sed -i "s|^\(#\?\)logfile\t.*|logfile\t/var/log/rsnapshot/rsnapshot.log|g" /etc/rsnapshot.conf
sudo sed -i "s|^\(#\?\)lockfile\t.*|lockfile\t/var/run/rsnapshot/rsnapshot.pid|g" /etc/rsnapshot.conf
# comment out existing backup rules
sudo sed -i "s|^backup\t|#backup	|g" /etc/rsnapshot.conf
# set up our own backup rules specific to this host
sudo mkdir -p /etc/rsnapshot.d
sudo tee "/etc/rsnapshot.d/${this_host}.conf" > /dev/null << RSHEOF
include_conf	/etc/rsnapshot.conf
backup	${_backup_user}@${this_host}:/var/www	${this_host}/
backup	${_backup_user}@${this_host}:/var/backups/mysql	${this_host}/
backup	${_backup_user}@${this_host}:/etc	${this_host}/
RSHEOF
EOF
}

backup_run() {
    destinations=$(ini_get "" "backup")
    if [ -z "${destinations}" ]; then
        echo "No backup destinations defined"
        exit 0
    fi
    # Lockfile prevents new backup starting before previous one finishes
    lockfile="/tmp/backup.lock"
    if [ -f "${lockfile}" ] && [ -z "$(find ${lockfile} -mmin +60)" ]; then
        echo "Lockfile ${lockfile} exists and is not older than 1 hour. Aborting."
        spanel alert "Backup" "${lockfile} prevents another backup"
        exit 0
    fi
    touch "${lockfile}"
    # Skip database back up if it is stopped or not installed
    if /usr/sbin/service mysql status > /dev/null; then
        rm -rf "/var/backups/mysql" # make sure backups are always new
        $(which mariabackup) --backup --target-dir="/var/backups/mysql" \
            --user=root --password=$(ini_get MYSQL_ROOT_PASS) > "/var/log/mariabackup.log" 2>&1
        # Change ownership so that the backup user can read the folder
        chgrp -R www-data "/var/backups/mysql"
        chmod -R g+rx "/var/backups/mysql"
    else
        echo "Database not running; skipping"
    fi

    # The current timestamp used to determine how recent is backup
    timestamp=$(date -R)
    echo "Timestamp: ${timestamp}"
    # Directories to back up
    sources="/etc /var/www /var/backups/mysql"
    # Go through each directory
    for source in ${sources}; do
        # Skip if a given directory does not exist on this server
        if [ ! -d "${source}" ]; then
            echo "Directory ${source} does not exist; skipping"
            continue
        fi
        timestamp_file="${source}/.backup_timestamp"
        echo "${timestamp}" > "${timestamp_file}"
    done
    this_host=$(hostname -I | xargs)
    # Have each destination run the backup
    for destination_hex in ${destinations}; do
        # Decode the hexadecimal representation into user@host[:port]
        destination=$(echo -e $(echo -n "${destination_hex}" | sed 's/../\\x&/g'))
        echo "Starting backup to ${destination}"
        # The :22 ensures predictable behaviour; see unix.stackexchange.com/a/465596
        destination_userhost=$(echo "${destination}:22" | cut -f1 -sd:)
        destination_port=$(echo "${destination}:22" | cut -f2 -sd:)
        # Actually trigger the backup
        ssh -p "${destination_port}" "${destination_userhost}" \
            "/usr/bin/rsnapshot -c \"/etc/rsnapshot.d/${this_host}.conf\" alpha"
        # Check the timestamps
        for source in ${sources}; do
            # Skip if a given directory does not exist on this server
            if [ ! -d "${source}" ]; then
                continue
            fi
            remote_timestamp_file="/var/backups/rsnapshot/alpha.0/${this_host}${source}/.backup_timestamp"
            remote_timestamp=$(ssh -p "${destination_port}" "${destination_userhost}" "cat ${remote_timestamp_file}")
            if [ "_${remote_timestamp}" != "_${timestamp}" ]; then
                spanel alert "Backup timestamp mismatch" "Timestamp in ${source} does not match ${remote_timestamp_file} on ${destination_userhost}"
                echo "Timestamp in ${source} does not match ${remote_timestamp_file} on ${destination_userhost}"
            fi
        done
    done
    # Clean up
    rm "${timestamp_file}"
    rm "${lockfile}"
}

manage_http_basic_auth() {
    # prepare the variables
    WEBROOT=$(pwd)
    WEBCONF=$(grep -FliR -m 1 --color=never "root ${WEBROOT};" ${sites_available})
    if [ -z "${WEBCONF}" ] && [ "${WEBROOT}" = "/var/www" ]; then
        WEBCONF="/etc/nginx/nginx.conf"
    fi
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
            sed -E -i "s@^( *)(server|http) \{\$@\1\2 {\n\1    auth_basic \"Auth\";\n\1    auth_basic_user_file ${HTTP_HTPA};@g" ${WEBCONF}
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
            echo "Deleting the auth_basic directives in ${WEBCONF}"
            sed -i '/^\s*auth_basic/d' ${WEBCONF}
        fi
    fi
    service nginx restart
}

# always make sure this script is executable (for e.g. cron)
if [ ! -x "${0}" ]; then
    chmod +x "${0}"
fi

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
        backup_${2}
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
        if [ ! -L "/usr/bin/spanel" ]; then
            echo "Creating a symlink from /usr/bin/spanel to ${0}"
            ln -s "${0}" "/usr/bin/spanel"
        fi
        ;;
    "password")
        # make sure a website to work with is selected
        WEBROOT=$(pwd)
        WEBCONF=$(grep -FliR -m 1 --color=never "root ${WEBROOT};" ${sites_available})
        if [ -z "${WEBCONF}" ] && [ "${WEBROOT}" = "/var/www" ]; then
            WEBCONF="/etc/nginx/nginx.conf"
        fi
        if [ -z "${WEBCONF}" ]; then
            echo "Please cd to a folder that contains a Nginx-hosted website, or /var/www to include all websites."
            exit 1;
        fi
        # disabling auth if requested, regardless of the user account
        if [ "_${2}" = "_off" ]; then
            echo "Disabling HTTP Basic Auth for ${2}@${WEBROOT}"
            manage_http_basic_auth "${2}" "off"
            exit 0;
        fi
        HTTP_HTPA="${WEBCONF}.htpasswd"
        # if the passwords file exists
        if [ -f "${HTTP_HTPA}" ]; then
            # and if the requested user is already listed in the passwords file
            if grep -q "${2}:" "${HTTP_HTPA}"; then
                # ask whether to delete the user or update password
                read -p "User ${HTTP_USER} exists in ${HTTP_HTPA}. Update or delete? [U/d]:" HTTP_ACT
                if [ "_${HTTP_ACT}" = "_d" ] || [ "_${HTTP_ACT}" = "_D" ]; then
                    echo "Disabling HTTP Basic Auth for ${2}."
                    manage_http_basic_auth "${2}" "off"
                    exit 0;
                fi
            fi
        fi
        # otherwise, set password for the user (regardless of whether it exists already)
        echo "Configuring HTTP Basic Auth for ${2}@${WEBROOT}"
        manage_http_basic_auth "${2}" "on"
        ;;
    "alert")
        ALERT_SUBJECT="${2}"
        ALERT_TEXT="${3}"
        ALERT_BIN=$(which sendmail)
        ALERT_TO=$(ini_get "ALERT_EMAIL")
        # below is a way to avoid installing sendmail, exim, postfix, etc.
        # nullmailer is lightweight, but relay only; lets relay right to target MX
        # parse out recipient's email hostname
        ALERT_TO_HOST=$(echo "${ALERT_TO}" | awk -F "@" '{print $2}')
        # read it's MX address record
        ALERT_TO_MX=$(dig +short "${ALERT_TO_HOST}" mx | sort -n | nawk '{print $2; exit}' | sed -e 's/\.$//')
        ALERT_FROM="$(whoami)@localhost" # works and doesn't have SPF issues
        # save the MX record to nullmailer's config
        printf "${ALERT_TO_MX}" > /etc/nullmailer/remotes
        # prepend date and server information
        PREPEND=""
        PREPEND="${PREPEND}Server IP: $(hostname -I)\n"
        PREPEND="${PREPEND}Server Hostname: $(hostname)\n"
        PREPEND="${PREPEND}Date: $(LC_ALL=C date +"%a, %d %h %Y %T %z")\n"
        ALERT_TEXT="${PREPEND}\n${ALERT_TEXT}"
        # sending mail
        echo "Sending '${ALERT_SUBJECT}': from ${ALERT_FROM} to ${ALERT_TO} via ${ALERT_TO_MX}"
        printf %b "Subject: ${ALERT_SUBJECT}\n\n${ALERT_TEXT}" | "${ALERT_BIN}" -f "${ALERT_FROM}" "${ALERT_TO}"
        ;;
    *)
        echo "**** USAGE:"
        echo "spanel [add|remove] example.com"
        exit 1;
        ;;
esac
