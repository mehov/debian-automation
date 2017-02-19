#!/bin/sh

SERVER_IP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.' | grep -v '10.8.0.'`
echo "SERVER_IP: ${SERVER_IP}"

apt-get update
apt-get install -y openvpn

mkdir -p /dev/net
mknod /dev/net/tun c 10 200
chmod 600 /dev/net/tun
echo "1" > /proc/sys/net/ipv4/ip_forward
iptables -F -t nat
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o venet0 -j SNAT --to-source $SERVER_IP
iptables-save

make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa
ln -s openssl-1.0.0.cnf openssl.cnf
chmod 777 /etc/openvpn/easy-rsa/vars
. /etc/openvpn/easy-rsa/vars
/etc/openvpn/easy-rsa/clean-all
/etc/openvpn/easy-rsa/build-ca
/etc/openvpn/easy-rsa/build-key-server server
/etc/openvpn/easy-rsa/build-key client

openssl dhparam 1024 > /etc/openvpn/dh4096.pem
openvpn --genkey --secret /etc/openvpn/easy-rsa/keys/ta.key
adduser --system --shell /usr/sbin/nologin --no-create-home openvpn_server

CONF_SERVER="/etc/openvpn/server.conf"
gzip -cd /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz > ${CONF_SERVER}
sed -i "s,;local a.b.c.d,local ${SERVER_IP}," ${CONF_SERVER}
sed -i 's,;user nobody,user openvpn_server,' ${CONF_SERVER}
sed -i 's,;\(group nogroup\),\1,' ${CONF_SERVER}
sed -i 's,\(proto udp\),;\1,' ${CONF_SERVER}
sed -i 's,;\(proto tcp\),\1,' ${CONF_SERVER}
sed -i 's,;\(push "redirect-gateway def1 bypass-dhcp"\),\1,' ${CONF_SERVER}
sed -i 's,;\(push "dhcp-option DNS 208.67.222.222"\),\1,' ${CONF_SERVER}
sed -i 's,ca ca.crt,ca /etc/openvpn/easy-rsa/keys/ca.crt,' ${CONF_SERVER}
sed -i 's,cert server.crt,cert /etc/openvpn/easy-rsa/keys/server.crt,' ${CONF_SERVER}
sed -i 's,key server.key,key /etc/openvpn/easy-rsa/keys/server.key,' ${CONF_SERVER}
sed -i 's,dh dh1024.pem,dh /etc/openvpn/dh4096.pem,' ${CONF_SERVER}
sed -i 's,;tls-auth ta.key,tls-auth /etc/openvpn/easy-rsa/keys/ta.key,' ${CONF_SERVER}
sed -i 's,;cipher AES-128-CBC,cipher AES-256-CBC,' ${CONF_SERVER}
echo 'auth SHA512' >> ${CONF_SERVER}
#echo 'tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-256-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA:TLS-DHE-RSA-WITH-AES-128-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA' >> ${CONF_SERVER}

CONF_CLIENT_DIR="/etc/openvpn/${SERVER_IP}"
CONF_CLIENT="${CONF_CLIENT_DIR}/$SERVER_IP.ovpn"
mkdir ${CONF_CLIENT_DIR}
cd ${CONF_CLIENT_DIR}
cp /usr/share/doc/openvpn/examples/sample-config-files/client.conf "${CONF_CLIENT}"
sed -i 's,;user nobody,user openvpn_server,' ${CONF_CLIENT}
sed -i 's,;\(group nogroup\),\1,' ${CONF_CLIENT}
sed -i 's,\(proto udp\),;\1,' ${CONF_CLIENT}
sed -i 's,;\(proto tcp\),\1,' ${CONF_CLIENT}
sed -i "s,remote my-server-1,remote ${SERVER_IP}," ${CONF_CLIENT}
sed -i 's,;\(tls-auth ta.key\),\1,' ${CONF_CLIENT}
sed -i 's,;cipher x,cipher AES-256-CBC,' ${CONF_CLIENT}
echo 'auth SHA512' >> ${CONF_CLIENT}
#echo 'tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-256-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA:TLS-DHE-RSA-WITH-AES-128-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA' >> ${CONF_CLIENT}
cp /etc/openvpn/easy-rsa/keys/ca.crt ${CONF_CLIENT_DIR}/ca.crt
cp /etc/openvpn/easy-rsa/keys/client.crt ${CONF_CLIENT_DIR}/client.crt
cp /etc/openvpn/easy-rsa/keys/client.key ${CONF_CLIENT_DIR}/client.key
cp /etc/openvpn/easy-rsa/keys/ta.key ${CONF_CLIENT_DIR}/ta.key
cd "${CONF_CLIENT_DIR}/../"
tar -czf $SERVER_IP.tar.gz $SERVER_IP
rm -rf ${CONF_CLIENT_DIR}

