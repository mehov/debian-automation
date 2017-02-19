#!/bin/sh

SERVER_IP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.' | grep -v '172.20.1.'`
echo "SERVER_IP: ${SERVER_IP}"

apt-get update
apt-get install -y openvpn

if [ -d "/etc/openvpn/easy-rsa" ]; then
    rm -rf /etc/openvpn/easy-rsa
fi
mkdir /etc/openvpn/easy-rsa
cp -R /usr/share/doc/openvpn/examples/easy-rsa/2.0/* /etc/openvpn/easy-rsa

mkdir /etc/openvpn/easy-rsa/keys
cat /dev/null > /etc/openvpn/easy-rsa/keys/index.txt
echo "00" > /etc/openvpn/easy-rsa/keys/serial

cd /etc/openvpn/easy-rsa
chmod 700 ./vars
source ./vars
./build-ca
./build-key-server server1
./build-key client1
./build-dh

gzip -cd /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz > /etc/openvpn/server1.conf

sed -i 's,\(proto udp\),;\1,' /etc/openvpn/server1.conf
sed -i 's,;\(proto tcp\),\1,' /etc/openvpn/server1.conf
sed -i 's,;\(push "redirect-gateway def1 bypass-dhcp"\),\1,' /etc/openvpn/server1.conf
sed -i 's,;\(push "dhcp-option DNS 208.67.222.222"\),\1,' /etc/openvpn/server1.conf
sed -i 's,ca ca.crt,ca /etc/openvpn/easy-rsa/keys/ca.crt,' /etc/openvpn/server1.conf
sed -i 's,cert server.crt,cert /etc/openvpn/easy-rsa/keys/server1.crt,' /etc/openvpn/server1.conf
sed -i 's,key server.key,key /etc/openvpn/easy-rsa/keys/server1.key,' /etc/openvpn/server1.conf
sed -i 's,dh dh1024.pem,dh /etc/openvpn/easy-rsa/keys/dh1024.pem,' /etc/openvpn/server1.conf

mkdir -p /dev/net
mknod /dev/net/tun c 10 200
chmod 600 /dev/net/tun
echo "1" > /proc/sys/net/ipv4/ip_forward
iptables -F -t nat
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o venet0 -j SNAT --to-source $SERVER_IP
iptables-save
/etc/init.d/openvpn start

cat <<EOF > /etc/openvpn/client1.conf
client
pull
dev tun
proto tcp
remote $SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
mute-replay-warnings
ca ca.crt
cert client1.crt
key client1.key
ns-cert-type server
comp-lzo
verb 3
keepalive 5 28
route-delay 3
win-sys env
EOF

mkdir /etc/openvpn/$SERVER_IP
cd /etc/openvpn/$SERVER_IP
cp /etc/openvpn/client1.conf ./$SERVER_IP.ovpn
cp /etc/openvpn/easy-rsa/keys/ca.crt ./ca.crt
cp /etc/openvpn/easy-rsa/keys/client1.crt ./client1.crt
cp /etc/openvpn/easy-rsa/keys/client1.key ./client1.key
cd ../
tar -czf $SERVER_IP.tar.gz $SERVER_IP
rm -rf ./$SERVER_IP