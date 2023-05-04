#!/bin/sh

USER="seedbox"
DIR_BASE="/var/www/${USER}"
DIR_SESS="${DIR_BASE}/.rtorrent.session"
DIR_PUB="${DIR_BASE}/public"
DIR_DL="${DIR_PUB}/downloads"
DIR_UI="${DIR_PUB}/rutorrent"

read -p "seedbox domain name: " hostname
PORT_HTTPS_DEF="443$(date -u "+%N" | cut -c 7,8)"
read -p "HTTPs port [${PORT_HTTPS_DEF}]: " PORT_HTTPS
if [ "$PORT_HTTPS" = "" ]; then
    PORT_HTTPS=$PORT_HTTPS_DEF
fi

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
apt-get install -q -y --no-install-recommends -o Dpkg::Options::="--force-confnew" gcc g++ build-essential ca-certificates curl php php-xmlrpc php-cli rtorrent screen mediainfo unrar unzip ffmpeg sox

# Prepare user account and folders
useradd $USER -U -d $DIR_BASE
mkdir -p $DIR_SESS $DIR_DL $DIR_UI

# Install init.d script for rTorrent
wget -O /etc/init.d/rtorrent-seedbox https://gist.githubusercontent.com/letiemble/5143971/raw/1cd6df3cf7479abda72f6a52b9638fdb0cd6d646/rtorrent-XXX
chmod +x /etc/init.d/rtorrent-${USER}
update-rc.d rtorrent-${USER} defaults

# Configure rTorrent
cat > "$DIR_BASE/.rtorrent.rc" <<END
directory.default.set = ${DIR_DL}
session.path.set = ${DIR_SESS}
 # the old init.d script expects the old session variable
session = ${DIR_SESS}
network.scgi.open_local = ${DIR_BASE}/.rtorrent.socket
execute.nothrow = chmod,770,${DIR_BASE}/.rtorrent.socket
encoding.add = utf8
network.port_range.set = 50000-50000
network.port_random.set = no
dht.mode.set = disable
protocol.pex.set = no
trackers.use_udp.set = no
check_hash = no
protocol.encryption.set = allow_incoming,enable_retry,try_outgoing
log.execute = /tmp/exec.log
view.sort_current = main,greater=d.get_creation_date=
END

/root/spanel.sh add $hostname --noninteractive --dir=$DIR_PUB # add virtual host
cat >> $DIR_PUB/.ngaccess <<END
location /RPC2 {
    include scgi_params;
    scgi_pass unix:${DIR_BASE}/.rtorrent.socket;
    scgi_param SCRIPT_NAME /RPC2;
}
END
# Install ruTorrent
wget https://github.com/Novik/ruTorrent/archive/master.tar.gz -O $DIR_BASE/rutorrent.tar.gz
tar xzf $DIR_BASE/rutorrent.tar.gz --strip 1 -C $DIR_UI
rm $DIR_BASE/rutorrent.tar.gz
echo "<?php header('Location: ./$(basename $DIR_UI)/'); ?>">$DIR_PUB/index.php
rm -rf $DIR_UI/plugins/_cloudflare # doesn't work by default
# Configure ruTorrent
sed -i -e "s|^[[:space:]]*\$scgi_port *= *[^$]*;|\$scgi_port = 0;|" $DIR_UI/conf/config.php
sed -i -e "s|^[[:space:]]*\$scgi_host *= *[^$]*;|\$scgi_host = \"unix://$DIR_BASE/.rtorrent.socket\";|" $DIR_UI/conf/config.php

# Post install
sed -i "s|10r/s|1000r/s|g" /etc/nginx/conf.d/limit_req.conf
sed -i "s/user www-data;/user $USER;/g" /etc/nginx/nginx.conf
sed -i "s/listen 443/listen $PORT_HTTPS/g" /etc/nginx/sites-available/vhost-$hostname.conf
sed -i "s/= www-data/= $USER/g" /etc/php/8.2/fpm/pool.d/www.conf
chown -R $USER:$USER $DIR_BASE

service nginx restart
service rtorrent-$USER restart
service php8.2-fpm restart

apt-get clean
apt-get autoremove

echo "ruTorrent is accessible at: "
echo ""
echo "    https://$hostname:$PORT_HTTPS/$(basename $DIR_UI)/"
echo ""
echo "To protect it with HTTP Basic Auth, run: "
echo ""
echo "    cd $DIR_PUB && /root/spanel.sh password \$username"
echo ""
echo "(Replace \$username with actual username you want to have.)"
