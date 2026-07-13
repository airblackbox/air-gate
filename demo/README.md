# air-gate live demo

A self-contained, interactive demo of air-gate. It faithfully re-implements the
package's policy engine, append-only audit chain, and signing (**real**
HMAC-SHA256 and Ed25519 via the browser's Web Crypto API) in a single static
HTML file. No backend, no build step, nothing leaves the page.

Visitors can:

- trigger agent actions and watch the **policy engine** auto-allow, hold for
  approval, or block them;
- **approve/reject** a held action — which *appends a signed decision event*
  (append-only), exactly like the shipped `EventStore.resolve()`;
- switch between **HMAC-SHA256** (symmetric) and **Ed25519** (asymmetric,
  publicly verifiable) signing;
- **tamper** with a stored event and hit **Verify** to watch the chain catch it.

## Run locally

```bash
cd demo
python3 -m http.server 8000
# open http://localhost:8000
```

It's a single file — you can also just open `index.html` directly.

## Deploy to Vercel (airblackbox.ai/gate)

The `demo/` directory is a static site. Point Vercel at it:

```bash
vercel --cwd demo --prod
```

Or in the Vercel dashboard, set **Root Directory** to `demo` (no build command,
no framework). `vercel.json` maps `/gate` → the demo and sets basic security
headers, so it serves at both `/` and `/gate`.

To host it under `airblackbox.ai/gate`, either deploy this as its own project on
that subpath or add a rewrite from the main site to this deployment.
