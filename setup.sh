#!/bin/bash
print '[*] Installing Wine'
apt-get update
apt-get install wine -y
print '[*] Installing Python Requirements'
pip install blessings
print '[*] Git Cloning Pyinstaller Into /opt'
git clone https://github.com/pyinstaller/pyinstaller.git /opt/
print '[*] Downloading Python27 For Wine'
wget https://www.python.org/ftp/python/2.7.10/python-2.7.10.msi
wine msiexec python-2.7.10.msi
