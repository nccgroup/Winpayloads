#!/bin/bash
echo '[*] Installing Dependencies'
dpkg --add-architecture i386
apt-get update
apt-get -y install mingw-w64 monodoc-browser monodevelop mono-mcs unzip wget git python python-crypto python-pefile python-pip
echo '[*] Installing Wine '
apt-get -y install wine32
apt-get -y install wine
echo '[*] Installing Python Requirements'
pip install blessings
pip install impacket
echo '[*] Installting Pyinstaller'
wget https://github.com/pyinstaller/pyinstaller/releases/download/v2.0/pyinstaller-2.0.zip
unzip -q -o -d /opt pyinstaller-2.0.zip
echo '[*] Downloading Python27 and Pycrypto For Wine'
wget https://www.python.org/ftp/python/2.7.10/python-2.7.10.msi
wine msiexec /i python-2.7.10.msi TARGETDIR=C:\Python27 ALLUSERS=1 /q
wget http://www.voidspace.org.uk/downloads/pycrypto26/pycrypto-2.6.win32-py2.7.exe
unzip pycrypto-2.6.win32-py2.7.exe
cp -rf PLATLIB/* ~/.wine/drive_c/Python27/Lib/site-packages/
wget https://download.microsoft.com/download/1/1/1/1116b75a-9ec3-481a-a3c8-1777b5381140/vcredist_x86.exe
wine vcredist_x86.exe /qb!
wget http://sourceforge.net/projects/pywin32/files/pywin32/Build%20219/pywin32-219.win32-py2.7.exe/download 
mv download pywin32.exe
unzip pywin32.exe
cp -rf SCRIPTS/* ~/.wine/drive_c/Python27/Scripts/
echo '[*] Setting Up Shellter'
wget --user-agent="Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0" "https://www.shellterproject.com/Downloads/Shellter/Latest/shellter.zip"
unzip shellter.zip
cd shellter
rm -r icon
rm -r shellcode_samples
rm -r faq.txt
rm -r readme.txt
rm -r version_history.txt
cd ..
rm python-2.7.10.msi
rm shellter.zip
rm pyinstaller-2.0.zip
rm pycrypto-2.6.win32-py2.7.exe
rm vcredist_x86.exe
rm pywin32.exe
rm PLATLIB -rf
rm SCRIPTS -rf
echo '[*] Done'
