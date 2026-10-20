# TrustVault

Secure document sharing where **the wrong person can never read the file**, and **you can prove who did**.
Built for the Snovasys Fresher Hiring Challenge 2026.

- Node.js 22+ only. **Zero npm dependencies** (built-in `http`, `node:sqlite`, `node:crypto`). Nothing to `npm install`.
- SQLite database, AES-256-GCM encrypted files, plain-JS front end (no build step).

## Quick start (clean clone)

```bash
git clone <your-repo-url> trustvault && cd trustvault
TV_SEED_DEMO=1 npm start          # loads demo users + documents, listens on http://127.0.0.1:3000
```

Open http://127.0.0.1:3000 and sign in with any account below.

### Demo accounts (public demo data, one per role)

| Role | Email | Password |
|---|---|---|
| Administrator | `admin@trustvault.demo` | `Admin#Demo2026` |
| Document owner | `alice@trustvault.demo` | `Owner#Demo2026` |
| Document owner | `bob@trustvault.demo` | `Owner#Demo2026` |
| Viewer | `carol@trustvault.demo` | `Viewer#Demo2026` |
| Viewer | `dave@trustvault.demo` | `Viewer#Demo2026` |
| Viewer (external partner) | `partner@external.demo` | `Partner#Demo2026` |

These passwords are public on purpose. **Never run `TV_SEED_DEMO=1` against real data.**

### Things to try (the judge's tour)

1. As **Alice**, open *Private notes* (shared with nobody). Then sign in as **Bob** and try to reach it by id
   (`/api/documents/<id>`) - you get `404`, same as a missing document. Alice's *activity* panel shows Bob's refused attempt.
2. As **Alice**, open *Salary letter*, click **Suggest who should see this**. Nothing is shared until you tick people and confirm.
3. As **Alice**, share with the external partner: an end date is required (max 30 days). Then **Remove access**; as the partner, the very next request fails.
4. As **Admin**, open *Documents* - metadata only, no way to open a file. Open *Audit trail* and click **Verify integrity**.
5. Run `npm test` - 60 tests, including the ones proving one user cannot reach another's documents.

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `TV_SECRET` | Root secret (>= 32 chars). Derives the file-encryption and audit-HMAC keys. **Required in production.** Losing it makes stored files unreadable. | dev: auto-generated into `data/dev-secret` |
| `NODE_ENV=production` | Secure cookies, HSTS, binds `0.0.0.0` | off |
| `PORT` / `HOST` | Listen address | `3000` / `127.0.0.1` (dev) |
| `TV_DATA_DIR` | Where the DB and encrypted files live | `./data` |
| `TV_TRUST_PROXY=1` | Trust `X-Forwarded-For` from your TLS proxy. Set **only** behind one. | off |
| `TV_ADMIN_EMAIL`, `TV_ADMIN_PASSWORD` | Create the first admin on an empty DB (must change password at first sign-in) | - |
| `TV_SEED_DEMO=1` | Load demo data into an empty DB. **Demo only.** | off |
| `TV_MAX_UPLOAD_BYTES` | Upload limit | 10 MB |
| `TV_TRASH_DAYS` | Trash retention before permanent purge | 30 |
| `TV_INSECURE_COOKIES=1` | Allow non-`Secure` cookies in production mode (only to test production mode over plain http) | off |

Helper: `npm run setup` prints a fresh `TV_SECRET` and the env vars to set.

## Database schema and setup scripts

- Schema: [`src/db.js`](src/db.js) (created automatically on first start; `CREATE TABLE IF NOT EXISTS`).
- `npm run setup` - generate secrets and print the production env block.
- `npm run seed` - load demo data into an empty database and print the demo accounts.
- First real admin: set `TV_ADMIN_EMAIL` and `TV_ADMIN_PASSWORD` for the first start.

## Deploy

**Render (blueprint included).** Push to GitHub, then *New > Blueprint* and pick the repo. `render.yaml` builds
the Dockerfile, generates `TV_SECRET`, and seeds demo data. The free plan has no persistent disk, so data resets
on restart (the seed re-creates it). For real use: a paid plan, a disk mounted at `/data`, and remove `TV_SEED_DEMO`.

**Any host with Docker or Node 22.**

```bash
docker build -t trustvault .
docker run -p 3000:3000 -v tv-data:/data \
  -e TV_SECRET="$(node scripts/setup.js | grep TV_SECRET | cut -d= -f2)" \
  -e TV_TRUST_PROXY=1 -e TV_ADMIN_EMAIL=you@example.com -e TV_ADMIN_PASSWORD='a-long-temporary-password' \
  trustvault
```

Put it behind HTTPS (the app sets `Secure` cookies and HSTS in production but does not terminate TLS).
Back up `/data` **and** keep `TV_SECRET` safe and separate.

## Tests

```bash
npm test      # 60 tests, ~10 s, uses a throw-away data directory and a fake clock
```

Suites: access control (cross-user, roles, revocation, expiry, trash, exhaustive SQL-vs-function agreement),
authentication and sessions, CSRF and request hygiene, uploads and storage, audit trail, AI sharing assistant.

## Documentation map

- [`docs/API.md`](docs/API.md) - every endpoint and **who may call it**.
- [`THREATS.md`](THREATS.md) - how it could be broken, what was done, what was knowingly accepted.
- [`PROMPTS.md`](PROMPTS.md) - how AI was used and where it was wrong.
- [`WRITEUP.md`](WRITEUP.md) - what was built, the permission model, what was not built, what is unfinished.

## Where the authorisation decision is made

`src/authz.js`: `decide()` and `requireDocument()`. The download route (`src/routes/documents.js`) calls
`requireDocument(ctx, id, 'read')` before it touches storage, and audits before sending a byte. Remove that
line and the `access.test.js` suite fails in dozens of places. List/search use `readableWhere()`, which a test
proves agrees with `decide()` for every user and document.

## Project layout

```
server.js            entry point
src/app.js           server, router, session + CSRF + role gates, headers
src/authz.js         THE authorisation decision
src/audit.js         hash-chained audit trail
src/crypto.js        scrypt, envelope encryption
src/storage.js       encrypted file store
src/validate.js      upload validation
src/suggest.js       "who should see this" assistant (suggests only)
src/routes/*.js      auth, documents, sharing, admin
public/              plain-JS front end
test/                60 tests
```

## Demo video (5 minutes) - suggested script

1. (0:00) The promise and the three non-negotiables. 2. (0:30) Alice uploads and shares; Bob is refused; show Alice's
activity. 3. (1:30) Revoke; the partner's next click fails. 4. (2:15) Admin: metadata only, then Audit, Verify.
5. (3:00) Tamper with a row in the DB file, press Verify, watch it fail. 6. (3:45) The AI suggestion: nothing
changes until a person confirms. 7. (4:30) `npm test`, then open `src/authz.js`.
