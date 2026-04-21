import base64
# encode without send — benign
data = base64.b64encode(b'hello world')
print(data)
