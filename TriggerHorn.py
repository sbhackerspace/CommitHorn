#!/usr/bin/python
# Dan Loman
# Description:
#   This script will generate one time passwords for triggering the github
#   horn at SBHX
import hmac
import hashlib
import random
import requests
import time
from SecretKey import getSecretKey

################################################################################
def getOneTimePassword(key, nonce, localTime):
  timeVal = [chr(int(i)) for i in str(int(localTime/10))[::-1]]
  timeVal = ''.join(timeVal)
  return hmac.new(key, nonce + timeVal, hashlib.sha256).hexdigest()

################################################################################
def getNonce():
  return '%030x' % random.randrange(16**30)

################################################################################
################################################################################
if __name__ == "__main__":
  nonce = getNonce()
  localTime = time.mktime(time.localtime())
  print 'triggering horn nonce =', nonce.encode("hex")
  print 'key =', getSecretKey().encode("hex")
  print 'otp =', getOneTimePassword(getSecretKey(), nonce, localTime)
  print 'nonce =', nonce
  #print 'localtime =', localTime
  data = \
    {'otp' : getOneTimePassword(getSecretKey(), nonce, localTime), \
    'nonce' : nonce.encode("hex"), \
    'time' : localTime}
  requests.post('http://10.18.15.12/horn', data = data)

