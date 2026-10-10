// Echo backend (Node.js / llhttp). Replies with what it received, as JSON.
const http = require('http');
let seq = 0;
http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    seq++;
    const out = JSON.stringify({
      seq, method: req.method, target: req.url, version: req.httpVersion,
      headers: req.rawHeaders, body: Buffer.concat(chunks).toString('latin1'),
    });
    res.setHeader('Content-Type', 'application/json');
    res.end(out);
  });
}).listen(Number(process.env.PORT), '127.0.0.1');
