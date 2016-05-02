#!/bin/python3

# This is a partial implementation of HMAC. It is only designed to work for a fixed 32-byte HMAC key
# It does not truncate or properly extend keys where their lengths are longer or shorter than required
# This is simply to provide a demonstration of what the accompanying JavaCard implementation attempts to do

import hmac
from hashlib import sha256

#key = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])
#padding = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

# Generate a dummy key of 32 sequential bytes, 0 to 31
key = bytearray()
for i in range(32):
    key.append(i)

# Now pad with zeroes to length of the HMAC block (SHA256 is 64 bytes)
padded_key = key
for i in range(32):
    padded_key.append(0)

# Now work out ipad and opad
ipad = bytearray()
for i in range(64):
    ipad.append(0x36)
opad = bytearray()
for i in range(64):
    opad.append(0x5C)

ipadK = bytearray()
opadK = bytearray()

for i in range(len(ipad)):
    ipadK.append(ipad[i] ^ padded_key[i])

for i in range(len(opad)):
    opadK.append(opad[i] ^ padded_key[i])

# Some dummy data, 0x01, 0x02, 0x03, 0x04, 0x05
data = bytearray()
for i in range(1,6):
    data.append(i)
print("For data: " + str(data))

# Do the inner HMAC computation
h = sha256()
h.update(ipadK)
h.update(data)
innerDigest = h.digest()

# Do the outer HMAC computation
k = sha256()
k.update(opadK)
k.update(innerDigest)
outerDigest = k.hexdigest()
print(str(outerDigest))

# now use real hmac for comparison
hm = hmac.new(key, digestmod=sha256)
hm.update(data)
print(str(hm.hexdigest()))
