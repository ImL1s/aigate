// send without read-and-encode — benign API call
fetch('/api/log', {method:'POST', body: JSON.stringify({event: 'startup'})});
