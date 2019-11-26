#!/bin/bash

# configuring dnsmasq to block known ad hosts and trackers
# use with xauth or ipsec vpn configured by github.com/hwdsl2/setup-ipsec-vpn

VAR_SERVERIP="123.123.123.123" # this server's public ip address

# install dnsmasq
apt-get update
apt-get upgrade
apt-get install --no-install-recommends dnsmasq

# initial configuration (https://github.com/BobNisco/adblocking-vpn)
VAR_CONF="/etc/dnsmasq.conf"
sed -i "s/^#domain-needed/domain-needed/g" ${VAR_CONF}
sed -i "s/^#bogus-priv/bogus-priv/g" ${VAR_CONF}
sed -i '/^#server=/a server=1.1.1.1\nserver=8.8.8.8' ${VAR_CONF}

# use crowdsourced hosts file (https://github.com/StevenBlack/hosts)
VAR_CROWDHOSTS="/etc/hostscrowdsourced"
wget https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts -O ${VAR_CROWDHOSTS}
sed -i "s/^#addn-hosts/addn-hosts/g" ${VAR_CONF}
sed -i "s;^addn-hosts=.*;addn-hosts=${VAR_CROWDHOSTS};g" ${VAR_CONF}

# bind to localhost (https://serverfault.com/a/830737)
sed -i "s/^#listen-address/listen-address/g" ${VAR_CONF}
sed -i "s/^listen-address=$/listen-address=127.0.0.1\nlisten-address=${VAR_SERVERIP}/g" ${VAR_CONF}

# configure the vpn to use the local dns server
# (https://github.com/hwdsl2/setup-ipsec-vpn#important-notes)
sed -i "s/8\.8\.8\.8 8\.8\.4\.4/${VAR_SERVERIP}/g" /etc/ipsec.conf
sed -i "s/^ms-dns 8\.8\.8\.8/ms-dns ${VAR_SERVERIP}/g" /etc/ppp/options.xl2tpd
sed -i '/^ms-dns 8\.8\.4\.4/d' /etc/ppp/options.xl2tpd

service ipsec restart
service dnsmasq restart

# block dns for everyone else
# (https://serverfault.com/questions/374846/block-all-incoming-dns-requests-except-from-ips-x-y/374853#374853)
iptables -A INPUT -p udp --dport 53 -s 192.168.43.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -s 192.168.43.0/24 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j DROP
iptables -A INPUT -p tcp --dport 53 -j DROP

iptables-save > /etc/iptables-dns.rules
cat > /etc/network/if-up.d/iptables-dns << EOF
#!/bin/sh
iptables-restore < /etc/iptables-dns.rules
EOF
chmod +x /etc/network/if-up.d/iptables-dns 
