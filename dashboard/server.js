// AIR Blackbox Dashboard — Lightweight audit trail viewer
// Serves static HTML + proxies API calls to the Gate server

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const GATE_URL = process.env.GATE_URL || 'http://localhost:8000';

const indexHtml = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');

const server = http.createServer(async (req, res) => {
  // Serve dashboard
  if (req.url === '/' || req.url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(indexHtml);
    return;
  }

  // Proxy API calls to Gate
  if (req.url.startsWith('/api/')) {
    const gatePath = req.url.replace('/api', '');
    const gateUrl = new URL(gatePath, GATE_URL);

    try {
      const response = await fetch(gateUrl.toString());
      const data = await response.text();
      res.writeHead(response.status, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      });
      res.end(data);
    } catch (err) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Gate unavailable', detail: err.message }));
    }
    return;
  }

  // Health check
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'healthy', service: 'dashboard' }));
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Dashboard running at http://localhost:${PORT}`);
  console.log(`Proxying API calls to ${GATE_URL}`);
});
