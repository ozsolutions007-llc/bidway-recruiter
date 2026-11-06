# BidWay Recruiter backend

Node/Express service that serves the single-page app and replaces the browser's IndexedDB with a
shared, server-side store, so the whole team works from one set of contractors, run history and
settings. Added 2026-11-05 as version 13.0 of the page.

## Run

```
cd server && npm install --omit=dev
node server.js            # https://0.0.0.0:8081
```

On the app server it runs under pm2 as `bidway-recruiter`. After pulling a new page version:

```
~/bidway-recruiter-update.sh   # git pull + pm2 restart
```

The server serves `bidway-recruiter.html` from the repo root, exactly as committed on GitHub. If that
file is absent it falls back to the newest `bidway-recruiter_v*.html`. Pushing a new page to `main`
is all that is needed; the deploy cron on the server pulls it within two minutes.

## First sign-in

On first start the server creates an `admin` account with a random temporary password and writes it
to `server/data/INITIAL_ADMIN_PASSWORD.txt` (mode 600). Sign in with it, set a real password, then
delete that file. Add team members from Settings > Users; each gets a temporary password and must
choose their own at first sign-in.

## Data

`server/data/recruiter.db` (SQLite via sql.js). Tables `recipients` (by UEI), `runs`, `kv`, plus `users`.
Records are stored as JSON, so the page can add fields without a schema change. Back up the `data`
directory; it also holds the session secret and the HTTPS certificate.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | 8081 | Listen port |
| `DATA_DIR` | `server/data` | Database, secret, certificate |
| `PUBLIC_DIR` | repo root | Where the page files live |
| `TRUSTED_PROXIES` | (none) | Proxies whose client-IP headers are trusted. Set to the addresses of the NexusPanel server and any reverse proxy in front of the app |
| `IDLE_TIMEOUT_MS` | 900000 | Inactivity sign-out |
| `FRAME_ANCESTORS` | (none) | Space-separated origins allowed to embed the app, e.g. the NexusPanel URL |
| `ALLOWED_PEERS` | (none = any) | Only these source addresses may connect. Set to `<nexuspanel-server-ip>,127.0.0.1` so the app is reachable only through NexusPanel's proxy at /apps/recruiter/ |
| `FRAME_ANCESTORS` | NexusPanel origins | Sites allowed to embed the app in a frame |

## Security

Same model as NexusPanel: bcrypt passwords, lockout after 5 failures per IP and per username, global
sign-in cap, temporary passwords forced to change, optional TOTP two-factor, 15-minute inactivity
sign-out, HttpOnly/Secure/SameSite=Strict cookie, security headers, cross-site write check. The
Scrape.do token is readable by every signed-in user (the browser needs it to call Scrape.do) but
only an admin can change it. Audit events are JSON lines in `pm2 logs bidway-recruiter`.

## Tests

`server/e2e_recruiter.sh` runs against a staging instance on port 8082 with its own `DATA_DIR`:

```
mkdir -p ~/recruiter-staging/data && cp server/data/{cert,key}.pem ~/recruiter-staging/data/
PORT=8082 DATA_DIR=~/recruiter-staging/data IDLE_TIMEOUT_MS=4000 TRUSTED_PROXIES=127.0.0.1 node server/server.js &
bash server/e2e_recruiter.sh
```
