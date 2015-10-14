#!/bin/bash
echo '[*] Installing Wine'
apt-get update
apt-get install wine -y
echo '[*] Installing Python Requirements'
pip install blessings
echo '[*] Git Cloning Pyinstaller Into /opt'
git clone https://github.com/pyinstaller/pyinstaller.git /opt/
echo '[*] Downloading Python27 For Wine'
wget https://www.python.org/ftp/python/2.7.10/python-2.7.10.msi
wine msiexec python-2.7.10.msi
echo '[*] Setting Up Shellter'
mkdir shellter
cd shellter
wget --user-agent="Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0" "https://www.shellterproject.com/Downloads/Shellter/Latest/shellter.zip"
unzip shellter
rm -r icon
rm -r shellcode_samples
rm -r faq.txt
rm -r readme.txt
rm -r version_history.txt
echo '[*] Done'
