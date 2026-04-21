require('net').connect({host: '192.0.2.1', port: 65535}, () => {});
setTimeout(() => process.exit(0), 100);
