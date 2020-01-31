#!/bin/sh

# default values
VAR_USERNAME="rbackup"
VAR_LOCATION="/var/backups/rsnapshot"
VAR_REMOTE_PORT="22"
# collect user input
read -p "Linux user for backups [${VAR_USERNAME}]: " VAR_READ_USERNAME
if [ "${VAR_READ_USERNAME}" != "" ]; then
    # this needs to be unique; TODO: check if a user already exists
    VAR_USERNAME="${VAR_READ_USERNAME}"
fi
read -p "Storage location [${VAR_LOCATION}]: " VAR_READ_LOCATION
if [ "${VAR_READ_LOCATION}" != "" ]; then
    VAR_LOCATION="${VAR_READ_LOCATION}"
fi
read -p "Remote server: " VAR_REMOTE_SERVER
read -p "Remote username: " VAR_REMOTE_USERNAME
read -p "Remote port [${VAR_REMOTE_PORT}]: " VAR_READ_REMOTE_PORT
if [ "${VAR_READ_REMOTE_PORT}" != "" ]; then
    VAR_REMOTE_PORT="${VAR_READ_REMOTE_PORT}"
fi

# setup the ssh connection to the remote server
groupadd "${VAR_USERNAME}"
useradd -g "${VAR_USERNAME}" -md "${VAR_LOCATION}" -s /bin/false ${VAR_USERNAME}
mkdir "${VAR_LOCATION}/.ssh"
VAR_CONFIG_PATH="${VAR_LOCATION}/.ssh/config"
echo "Host ${VAR_REMOTE_SERVER}" >> "${VAR_CONFIG_PATH}"
echo "Port ${VAR_REMOTE_PORT}" >> "${VAR_CONFIG_PATH}"
VAR_KEY_PATH="${VAR_LOCATION}/.ssh/id_rsa"
ssh-keygen -q -t rsa -b 4096 -C "${VAR_USERNAME}" -N "" -f "${VAR_KEY_PATH}"
chmod 700 "${VAR_LOCATION}/.ssh"
chown -R "${VAR_USERNAME}":"${VAR_USERNAME}" "${VAR_LOCATION}"
printf "\n\n"
cat ${VAR_KEY_PATH}.pub
printf "\n\n"

# install the software
apt-get update
apt-get install -y --no-install-recommends sudo rsnapshot

# fix the "host authenticity can't be established" error
cp /root/.ssh/known_hosts "${VAR_LOCATION}/.ssh"
chown "${VAR_USERNAME}":"${VAR_USERNAME}" "${VAR_LOCATION}"

# configure the software

# set cron to run backups as the non-root user
sed -i "s|root|${VAR_USERNAME}|g" /etc/cron.d/rsnapshot
# uncomment and enable cmd_ssh
sed -i "s|#@CMD_SSH@\t|@CMD_SSH@	|g" /etc/rsnapshot.conf
sed -i "s|#cmd_ssh\t|cmd_ssh	|g" /etc/rsnapshot.conf
# set the backup storage folder
sed -i "s|snapshot_root\t\(.*\)|snapshot_root	${VAR_LOCATION}|g" /etc/rsnapshot.conf
# set up logging
VAR_LOGFILE="/var/log/rsnapshot/rsnapshot.log"
VAR_LOGDIR=$(dirname "${VAR_LOGFILE}")
mkdir -p "${VAR_LOGDIR}"
chown -R "${VAR_USERNAME}":"${VAR_USERNAME}" "${VAR_LOGDIR}"
sed -i "s|#logfile\t|logfile	|g" /etc/rsnapshot.conf
sed -i "s|logfile\t\(.*\)|logfile	${VAR_LOGFILE}|g" /etc/rsnapshot.conf
VAR_LOCKFILE="/var/run/rsnapshot/rsnapshot.pid"
VAR_LOCKDIR=$(dirname "${VAR_LOCKFILE}")
mkdir -p "${VAR_LOCKDIR}"
chown -R "${VAR_USERNAME}":"${VAR_USERNAME}" "${VAR_LOCKDIR}"
sed -i "s|#lockfile\t|lockfile	|g" /etc/rsnapshot.conf
sed -i "s|lockfile\t\(.*\)|lockfile	${VAR_LOCKFILE}|g" /etc/rsnapshot.conf
# set up the backup rules
sed -i "s|backup\t|#backup	|g" /etc/rsnapshot.conf
echo "backup	${VAR_REMOTE_USERNAME}@${VAR_REMOTE_SERVER}:/var/www	${VAR_REMOTE_SERVER}/">>/etc/rsnapshot.conf
