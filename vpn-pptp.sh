#!/bin/sh

SERVER_IP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.' | grep -v '172.20.1.'`
echo "SERVER_IP: ${SERVER_IP}"

if ! [ $1 -eq "iptables" ]; then
apt-get update
apt-get install pptpd -y
update-rc.d pptpd defaults

echo "localip 172.20.1.1" >> /etc/pptpd.conf
echo "remoteip 172.20.1.2-254" >> /etc/pptpd.conf
echo "ms-dns 8.8.8.8" >> /etc/ppp/pptpd-options
echo "ms-dns 8.8.4.4" >> /etc/ppp/pptpd-options

random_string() {
    if [ $1="-l" ]; then
            length=$2
        else
            length="8"
        fi
    echo `cat /dev/urandom | tr -dc "a-zA-Z0-9" | fold -w $length | head -1`
}
username_rand=`random_string -l 5`
read -p "User [${username_rand}]: " username
if [ "$username" = "" ]; then
    username="${username_rand}"
fi
password_rand=`random_string -l 7`
read -p "Password [${password_rand}]: " password
if [ "$password" = "" ]; then
    password="${password_rand}"
fi
echo "${username} * ${password} *" >> /etc/ppp/chap-secrets

service pptpd restart

mkdir -p /dev/net
mknod /dev/net/tun c 10 200
chmod 600 /dev/net/tun
mknod /dev/ppp c 108 0
chmod 777 /dev/ppp

echo "1" > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

fi
service pptpd restart

#iptables -I INPUT -p tcp --dport 1723 -m state --state NEW -j ACCEPT
#iptables -I INPUT -p gre -j ACCEPT
#iptables -t nat -I POSTROUTING -o eth0 -j MASQUERADE
#iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -s 172.20.1.0/24 -j TCPMSS  

iptables -F -t nat

iptables -A FORWARD -i venet0 -o ppp0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i ppp0 -o venet0 -j ACCEPT
iptables -t nat -A POSTROUTING -j SNAT --to-source $SERVER_IP

#iptables -P FORWARD ACCEPT
#iptables -I INPUT -p tcp --dport 1723 -m state --state NEW -j ACCEPT
#iptables -I INPUT -p gre -j ACCEPT
#iptables -t nat -A POSTROUTING -s 172.20.1.0/24 -o venet0:0 -j SNAT --to-source $SERVER_IP
#iptables -t nat -A POSTROUTING -s 172.20.1.0/24 -o venet0:0 -j SNAT --to $SERVER_IP


iptables-save