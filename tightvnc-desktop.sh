#!/bin/bash

apt-get update
apt-get install -y xorg openbox gnome-panel gnome-terminal gnome-screensaver tightvncserver autocutsel console-cyrillic firefox-esr
useradd vnc
passwd vnc
mkdir -p /home/vnc
chown -R vnc:sudo /home/vnc
su - vnc -c "vncserver -geometry 1280x800 -depth 16"
