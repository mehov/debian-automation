#!/bin/sh

apt-get purge dma

apt-get update
apt-get install 
apt-get install -y --no-install-recommends wget ca-certificates gcc bison flex make libc6-dev libssl-dev
wget -O /tmp/dma.tar.gz https://github.com/corecode/dma/archive/v0.13.tar.gz
tar xzf /tmp/dma.tar.gz -C /tmp
cd /tmp/dma-0.13
make CC=$(which gcc) YACC=$(which yacc) LEX=$(which lex) SH=$(which bash) INSTALL=$(which install)
make install sendmail-link mailq-link install-spool-dirs install-etc
#rm /tmp/dma-0.13

ALERT_EMAIL=$(cfget -qC ~/.bonjour.ini "ALERT_EMAIL")

echo "ALERT_EMAIL ${ALERT_EMAIL}"

#echo "" > /etc/dma/aliases

DMA_CONF="/etc/dma/dma.conf"
AUTH_CONF="/etc/dma/auth.conf"

wget -O "${DMA_CONF}" https://raw.githubusercontent.com/corecode/dma/master/dma.conf

read -p "Use external SMTP server? [Y/n]" SMTP_Yn

if [ "${SMTP_Yn}" = "" ] || [ "${SMTP_Yn}" = "Y" ] || [ "${SMTP_Yn}" = "y" ]; then
    read -p "External SMTP server: " SMTP_host
    read -p "External SMTP port: " SMTP_port
    read -p "External SMTP username: " SMTP_user
    read -p "External SMTP password: " SMTP_pass

    sed -i "s/^ *# *SMARTHOST[^$]*/SMARTHOST ${SMTP_host}/" ${DMA_CONF}
    sed -i "s/^ *# *PORT[^$]*/PORT ${SMTP_port}/" ${DMA_CONF}
    if [ "p587" = "p${SMTP_port}" ]; then # stackoverflow.com/q/17281669
        sed -i "s/^ *# *STARTTLS[^$]*/STARTTLS/" ${DMA_CONF}
    fi
    sed -i "s|^ *# *AUTHPATH[^$]*|AUTHPATH ${AUTH_CONF}|" ${DMA_CONF}
    sed -i "s/^ *# *SECURETRANSFER$/SECURETRANSFER/" ${DMA_CONF}
    sed -i "0,/^ *# *MASQUERADE/{s/^ *# *MASQUERADE[^$]*/MASQUERADE ${SMTP_user}/}" ${DMA_CONF}

    sed -i "/|${SMTP_host}:/d" ${AUTH_CONF}
    echo "${SMTP_user}|${SMTP_host}:${SMTP_pass}" >> ${AUTH_CONF}

    cat ${DMA_CONF}
    cat ${AUTH_CONF}
fi
