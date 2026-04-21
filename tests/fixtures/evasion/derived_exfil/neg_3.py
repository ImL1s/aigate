import zlib
# compress without network — benign
payload = zlib.compress(b'some data')
with open('output.bin', 'wb') as f:
    f.write(payload)
