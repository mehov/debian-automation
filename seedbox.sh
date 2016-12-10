#!/bin/sh

USER="seedbox"
DIR_BASE="/var/www/seedbox"
DIR_PUB="$DIR_BASE/public"
DIR_SESS="$DIR_BASE/session"
DIR_DL_NAME="downloads"
DIR_DL="$DIR_PUB/$DIR_DL_NAME"
DIR_UI_PATH="webui"
DIR_UI="$DIR_PUB/$DIR_UI_PATH"

echo "YOU WILL USE THESE TO LOG IN TO THE WEB UI"
read -p "htpasswd username: " htpasswd_user
read -p "htpasswd password: " htpasswd_pass

PORT_SCGI=$(date -u "+%N" | cut -c 6,7,8)
PORT_SCGI="5${PORT_SCGI}"
PORT_HTTP_DEF=$(date -u "+%N" | cut -c 6,7,8)
PORT_HTTP_DEF="8${PORT_HTTP_DEF}"
PORT_SSH_DEF=$(date -u "+%N" | cut -c 7,8)
PORT_SSH_DEF="22${PORT_SSH_DEF}"
read -p "SSH port [${PORT_SSH_DEF}]: " PORT_SSH
if [ "$PORT_SSH" = "" ]; then
    PORT_SSH=$PORT_SSH_DEF
fi
read -p "HTTP port [${PORT_HTTP_DEF}]: " PORT_HTTP
if [ "$PORT_HTTP" = "" ]; then
    PORT_HTTP=$PORT_HTTP_DEF
fi

# get the country code so we can use the closest debian mirror
##wget -O /tmp/countryCode http://ip-api.com/csv?fields=countryCode
##COUNTRYCODE=`cat /tmp/countryCode | sed 's/./\L&/g'`
##sed -i "s/\.us\./.${COUNTRYCODE}./g" /etc/apt/sources.list
sed -i "s/ftp\.debian\.org/httpredir.debian.org/g" /etc/apt/sources.list
sed -i "s/ftp\.\([a-z]\+\)\.debian\.org/httpredir.debian.org/g" /etc/apt/sources.list
sed -i "s/main/non-free main/g" /etc/apt/sources.list

# Fix the neighbour table overflow & net_ratelimit errors (#18)
echo "net.ipv4.neigh.default.gc_interval = 3600" >> /etc/sysctl.conf
echo "net.ipv4.neigh.default.gc_stale_time = 3600" >> /etc/sysctl.conf
echo "net.ipv4.neigh.default.gc_thresh3 = 4096" >> /etc/sysctl.conf
echo "net.ipv4.neigh.default.gc_thresh2 = 2048" >> /etc/sysctl.conf
echo "net.ipv4.neigh.default.gc_interval = 3600" >> /etc/sysctl.conf
echo "net.ipv6.neigh.default.gc_stale_time = 3600" >> /etc/sysctl.conf
echo "net.ipv6.neigh.default.gc_thresh1 = 1024" >> /etc/sysctl.conf
echo "net.ipv6.neigh.default.gc_thresh3 = 4096" >> /etc/sysctl.conf
echo "net.ipv6.neigh.default.gc_thresh2 = 2048" >> /etc/sysctl.conf
echo "net.ipv6.neigh.default.gc_thresh1 = 1024" >> /etc/sysctl.conf

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y debian-keyring 
apt-get install -y debian-archive-keyring
for k in $(apt-get update 2>&1|grep -o NO_PUBKEY.*|sed 's/NO_PUBKEY //g');do echo "key: $k";gpg --recv-keys $k;gpg --recv-keys $k;gpg --armor --export $k|apt-key add -;done
apt-get update

apt-get remove libxmlrpc-c*
apt-get install -q -y --no-install-recommends -o Dpkg::Options::="--force-confnew" gcc g++ build-essential ca-certificates curl apache2 libapache2-mod-scgi php5 php5-xmlrpc php5-cli rtorrent screen mediainfo libav-tools unrar unzip 

printf "SCGIMount \"/RPC2\" 127.0.0.1:${PORT_SCGI}">/etc/apache2/mods-available/scgi.conf

ln -s /etc/apache2/mods-available/scgi.conf /etc/apache2/mods-enabled/ 
ln -s /etc/apache2/mods-available/scgi.load /etc/apache2/mods-enabled/


cat > /etc/init.d/rtorrent <<END
#!/bin/sh
### BEGIN INIT INFO
# Provides:          rtorrent_autostart
# Required-Start:    \$local_fs \$remote_fs \$network \$syslog \$netdaemons
# Required-Stop:     \$local_fs \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: rtorrent script using screen(1)
# Description:       rtorrent script using screen(1) to keep torrents working without the user logging in
### END INIT INFO
#############
###<Notes>###
#############
# This script depends on screen.
# For the stop function to work, you must set an
# explicit session directory using ABSOLUTE paths (no, ~ is not absolute) in your rtorrent.rc.
# If you typically just start rtorrent with just "rtorrent" on the
# command line, all you need to change is the "user" option.
# Attach to the screen session as your user with
# "screen -dr rtorrent". Change "rtorrent" with srnname option.
# Licensed under the GPLv2 by lostnihilist: lostnihilist _at_ gmail _dot_ com
##############
###</Notes>###
##############

#######################
##Start Configuration##
#######################
# You can specify your configuration in a different file
# (so that it is saved with upgrades, saved in your home directory,
# or whateve reason you want to)
# by commenting out/deleting the configuration lines and placing them
# in a text file (say /home/user/.rtorrent.init.conf) exactly as you would
# have written them here (you can leave the comments if you desire
# and then uncommenting the following line correcting the path/filename
# for the one you used. note the space after the ".".
# . /etc/rtorrent.init.conf

#Do not put a space on either side of the equal signs e.g.
# user = user
# will not work
# system user to run as
user="$USER"

# the system group to run as, not implemented, see d_start for beginning implementation
# group=\`id -ng "\$user"\`

# the full path to the filename where you store your rtorrent configuration
config="\`su -c 'echo \$HOME' \$user\`/.rtorrent.rc"

# set of options to run with
options=""

# default directory for screen, needs to be an absolute path
base="\`su -c 'echo \$HOME' \$user\`"

# name of screen session
srnname="rtorrent"

# file to log to (makes for easier debugging if something goes wrong)
logfile="/var/log/rtorrentInit.log"
#######################
###END CONFIGURATION###
#######################
PATH=/usr/bin:/usr/local/bin:/usr/local/sbin:/sbin:/bin:/usr/sbin
DESC="rtorrent"
NAME=rtorrent
DAEMON=\$NAME
SCRIPTNAME=/etc/init.d/\$NAME

checkcnfg() {
    exists=0
    for i in \`echo "\$PATH" | tr ':' '\n'\` ; do
        if [ -f \$i/\$NAME ] ; then
            exists=1
            break
        fi
    done
    if [ \$exists -eq 0 ] ; then
        echo "cannot find rtorrent binary in PATH \$PATH" | tee -a "\$logfile" >&2
        exit 3
    fi
    if ! [ -r "\${config}" ] ; then
        echo "cannot find readable config \${config}. check that it is there and permissions are appropriate" | tee -a "\$logfile" >&2
        exit 3
    fi
    session=\`getsession "\$config"\`
    if ! [ -d "\${session}" ] ; then
        echo "cannot find readable session directory \${session} from config \${config}. check permissions" | tee -a "\$logfile" >&2
        exit 3
    fi
}

d_start() {
  #chmod 777 /var/run/screen #Fix Ubuntu 10.04 screen bug
  [ -d "\${base}" ] && cd "\${base}"
  stty stop undef && stty start undef
  su -c "screen -ls | grep -sq "\.\${srnname}[[:space:]]" " \${user} || su -c "screen -dm -S \${srnname} 2>&1 1>/dev/null" \${user} | tee -a "\$logfile" >&2
  # this works for the screen command, but starting rtorrent below adopts screen session gid
  # even if it is not the screen session we started (e.g. running under an undesirable gid
  #su -c "screen -ls | grep -sq "\.\${srnname}[[:space:]]" " \${user} || su -c "sg \"\$group\" -c \"screen -fn -dm -S \${srnname} 2>&1 1>/dev/null\"" \${user} | tee -a "\$logfile" >&2
  su -c "screen -S "\${srnname}" -X screen rtorrent \${options} 2>&1 1>/dev/null" \${user} | tee -a "\$logfile" >&2
}

d_stop() {
    session=\`getsession "\$config"\`
    if ! [ -s \${session}/rtorrent.lock ] ; then
        return
    fi
    pid=\`cat \${session}/rtorrent.lock | awk -F: '{print(\$2)}' | sed "s/[^0-9]//g"\`
    if ps -A | grep -sq \${pid}.*rtorrent ; then # make sure the pid doesn't belong to another process
        kill -s INT \${pid}
    fi
}

getsession() {
    session=\`cat "\$1" | grep "^[[:space:]]*session[[:space:]]*=" | sed "s/^[[:space:]]*session[[:space:]]*=[[:space:]]*//" \`
    echo \$session
}

checkcnfg

case "\$1" in
  start)
    echo -n "Starting \$DESC: \$NAME"
    d_start
    echo "."
    ;;
  stop)
    echo -n "Stopping \$DESC: \$NAME"
    d_stop
    echo "."
    ;;
  restart|force-reload)
    echo -n "Restarting \$DESC: \$NAME"
    d_stop
    sleep 1
    d_start
    echo "."
    ;;
  *)
    echo "Usage: \$SCRIPTNAME {start|stop|restart|force-reload}" >&2
    exit 1
    ;;
esac

exit 0
END

chmod +x /etc/init.d/rtorrent

update-rc.d rtorrent defaults


useradd $USER -U -d $DIR_BASE
mkdir -p $DIR_SESS $DIR_DL $DIR_UI

cat > "$DIR_BASE/.rtorrent.rc" <<END
#http://code.google.com/p/wtorrent/

directory = ${DIR_DL}
session = ${DIR_SESS}
scgi_port = localhost:${PORT_SCGI}
encoding_list = ISO-8859-1
port_range = 55990-56000
port_random = yes
use_udp_trackers = no
dht = disable
peer_exchange = no
check_hash = no
encryption = allow_incoming,enable_retry,try_outgoing

#ratio.enable=no
#ratio.min.set=100 
#ratio.max.set=150 
#ratio.upload.set=10M

#system.method.set_key = event.download.erased,rm_complete,"execute=rm,-rf,--,$d.get_base_path="
#system.umask.set = 000

log.execute = /tmp/exec.log

download_rate = 16384
view_sort_current = main,greater=d.get_creation_date=
END


wget https://github.com/Novik/ruTorrent/archive/master.tar.gz -O $DIR_BASE/rutorrent.tar.gz
tar xzf $DIR_BASE/rutorrent.tar.gz --strip 1 -C $DIR_UI
rm $DIR_BASE/rutorrent.tar.gz
echo "<?php header('Location: ./$DIR_UI_PATH/'); ?>">$DIR_PUB/index.php
chown -R $USER:$USER $DIR_BASE

find $DIR_UI/share -type d -exec chmod 0777 {} ';'

printf "Alias /$DIR_UI_PATH $DIR_UI\nAlias /$DIR_DL_NAME $DIR_DL\n<Directory \"$DIR_PUB\">\nAuthType Basic\nAuthName \"Authorization Required\"\nAuthUserFile $DIR_BASE/.htpasswd\nRequire valid-user\n</Directory>" > /etc/apache2/conf-available/$DIR_UI_PATH.conf
ln -s "/etc/apache2/conf-available/$DIR_UI_PATH.conf" "/etc/apache2/conf-enabled/$DIR_UI_PATH.conf"

cat > "/etc/apache2/sites-available/$DIR_UI_PATH" <<END
<VirtualHost *:$PORT_HTTP>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www
	ErrorLog \${APACHE_LOG_DIR}/$DIR_UI_PATH.error.log
	LogLevel warn
	CustomLog \${APACHE_LOG_DIR}/$DIR_UI_PATH.access.log combined
</VirtualHost>
END
ln -s "/etc/apache2/sites-available/$DIR_UI_PATH" "/etc/apache2/sites-enabled/$DIR_UI_PATH"

htpasswd -c -b "${DIR_BASE}/.htpasswd" $htpasswd_user $htpasswd_pass
rm "${DIR_UI}/.htaccess"

sed -i "s/scgi_port = 5000/scgi_port = $PORT_SCGI/g" $DIR_UI/conf/config.php
sed -i "s/Port 22/Port $PORT_SSH/g" /etc/ssh/sshd_config
sed -i "s/80/$PORT_HTTP/g" /etc/apache2/ports.conf

invoke-rc.d apache2 restart
invoke-rc.d rtorrent restart
apt-get clean
apt-get autoremove

echo "**** The new SSH port is: ${PORT_SSH}"
echo "**** The new HTTP port is: ${PORT_HTTP}"
invoke-rc.d ssh restart
reboot

