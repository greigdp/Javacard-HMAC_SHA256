import hmac
from hashlib import sha256
from binascii import unhexlify

# Quick helper function to strip spaces from hex strings
def cut_spaces(data):
    return data.replace(" ", "")

# The HMAC key (retrieved from the smartcard using the debug command)
key_hex = "7A 74 2B 85 DE EB DE DA B5 2F 6B 40 2E EA 26 8B 0D 75 10 B7 D9 7B 7D 12 76 E5 FD 18 B4 9F 51 09"
key = unhexlify(cut_spaces(key_hex))

# A message to generate the HMAC of
data = b"\x01\x02\x03\x04\x05"

# The HMAC digest returned by the card (for comparison below)
card_digest_hex = "FC 28 BA 8F 68 51 00 2C D7 2A 39 AC CB 40 0D B1 6B D2 88 FF D5 B6 7A 0A 93 14 1F 4A CA 35 7A 95"

# Now work out the "proper" HMAC using reference implementation
hm = hmac.new(key, digestmod=sha256)
hm.update(data)
# Show the HMAC python calculated
print("Reference python HMAC implementation:")
print(str(hm.hexdigest()))
# Show the HMAC the card generated, and is pasted above, but in same format to show it's the same
print("Smartcard response HMAC (from source):")
print(str(cut_spaces(card_digest_hex).lower()))
