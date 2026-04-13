// Simple static server for the browser test — no external deps.
// Usage: node serve-front-test.mjs [port]
import { createServer } from 'node:http';
import { readFile }     from 'node:fs/promises';
import { extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(import.meta.url), '..');
const PORT = Number(process.argv[2]) || 3000;

const MIME = {
  '.html': 'text/html',
  '.mjs':  'application/javascript',
  '.js':   'application/javascript',
  '.wasm': 'application/wasm',
  '.json': 'application/json',
};

createServer(async (req, res) => {
  // Normalize path — default to test.html
  const urlPath  = req.url === '/' ? '/test.html' : req.url;
  const filePath = join(ROOT, urlPath);

  // Safety: stay inside ROOT
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  try {
    const data = await readFile(filePath);
    const mime = MIME[extname(filePath)] ?? 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type': mime,
      'Cross-Origin-Opener-Policy':   'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end(`Not found: ${urlPath}`);
  }
}).listen(PORT, () => console.log(`→ http://localhost:${PORT}`));
