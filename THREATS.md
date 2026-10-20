# THREATS.md

How I think TrustVault could be broken, what I did about each, and what I knowingly accepted.
"Test" names point at the automated tests that exercise the defence (`npm test`).

## The core rule

A document is reachable **only** by its owner or by a person holding an **active per-document grant**. One function decides this (`src/authz.js`, `decide()` / `requireDocument()`); every document route calls it, and list/search use a SQL twin (`readableWhere`) that a test proves agrees with it for **every user x every document**.

## Threats and responses

| # | Attack | What I did | Test |
|---|---|---|---|
| 1 | **Guess or enumerate document ids** (IDOR) | Ids are random UUIDs, but I don't rely on that: every route authorises. No-access returns `404`, identical to a non-existent id. | access: "no grant gets 404... same as a missing id" |
| 2 | **Reach another user's file through list, search, tags** | List, search and the tag cloud are filtered in SQL by the same rule. Tags of unreachable documents don't appear. | access: "guessing ids via list/search/tags" |
| 3 | **Version-number trick to read another document's file** | Versions are looked up *within* the authorised document. | access: "a version number can never reach another document's file" |
| 4 | **Admin abuse / compromised admin** | Admins have **no content access by design**: no read, no download, no grants to them. They see metadata and the audit trail. Every admin view is itself audited. | access: "admins have NO content access" |
| 5 | **Role escalation through a forged grant** | Viewer role caps at read even if an `edit` row exists. Role is re-read from the DB on every request, so a demotion is immediate. | access: "viewer with a forged edit grant" |
| 6 | **Folder over-sharing** (the brief's first example) | Folders carry **no permissions**. Putting a file in a folder never shares it. Per-document grants only. | access: "folders carry no permissions" |
| 7 | **Leaver's access / link still works** | No share links exist. Access is a named grant row checked per request. Disabling a user kills their sessions at once. Trash revokes all grants. Expiry is checked per request (no cron to be late). | access: revocation, expiry, disabled user, trash |
| 8 | **Taking access away isn't immediate** | There is no cache and no token that outlives the grant: the grant row is read on every request. Sessions prove *who you are*, not *what you may open*. The cost: one indexed query per request. | access: "revoking takes effect on the very next request" |
| 9 | **Tampering with the audit trail** | HMAC-SHA256 hash chain (key not in the DB). SQLite triggers reject UPDATE/DELETE. A head pointer file detects deleted tail rows. Audit write is in the same transaction as the change, and a download is audited *before* bytes are sent. `Verify` is in the admin UI. | audit: edit, delete, truncate, forge-without-secret, atomicity |
| 10 | **Refused attempts not recorded** | Denials are audited with the reason; the owner sees them in their document's activity view; admin alerts flag probing. | audit; access: "every refused attempt..." |
| 11 | **Stolen disk / backup of the data dir** | Files are AES-256-GCM with a per-file key wrapped by a master key from `TV_SECRET` (not stored with the data). Ciphertext is bound to its record (AAD), so swapping two files fails to decrypt. | uploads: "encrypted at rest", "tampering or swapping detected" |
| 12 | **Malicious upload** (html/svg/exe/polyglot, wrong extension) | Allow-list of extensions **and** content sniffing; size cap enforced while streaming; random storage names (no user input in any path); names sanitised; downloads are always `attachment`, `application/octet-stream`, `nosniff`, under a strict CSP. | uploads: dangerous files, sanitising, nosniff |
| 13 | **Path traversal** | Static files come from an exact-match allow-list, never a path built from the URL. Storage keys must match `^[0-9a-f]{32}$`. | csrf/hygiene: "only the explicit static files" |
| 14 | **XSS** | No `innerHTML` in the front end (text nodes only); CSP `default-src 'none'; script-src 'self'`; no inline script or style. | hygiene: headers; uploads: markup stored as text |
| 15 | **CSRF** | `SameSite=Strict` cookie + required `X-CSRF-Token` header + `Origin` check. | hygiene: CSRF tests |
| 16 | **Session theft/fixation** | `HttpOnly`, `Secure` (production), `__Host-` prefix, new random id on every login, only a SHA-256 of the token is stored, idle (30 min) and absolute (8 h) timeouts, logout destroys server-side, password change kills other sessions. | auth tests |
| 17 | **Credential stuffing / brute force** | scrypt hashing; per-account **and** per-IP throttling keyed on the email *string* (so unknown accounts behave identically); a correct password doesn't bypass an active lock; identical error and equalised timing for unknown users. | auth: throttle, identical failures |
| 18 | **SQL injection** | All queries are parameterised; sort columns come from a fixed map; LIKE input is escaped. | hygiene: "SQL-injection style input is data" |
| 19 | **Smuggling grants through the AI helper** | The suggester is read-only and has no path to the grant function. Confirming someone who wasn't suggested is refused. Same rules (expiry caps, viewer read-only) apply on confirm. One decision per suggestion. | assistant tests |
| 20 | **Lock-out** | Cannot remove or disable the last admin, or yourself. | auth: "admin cannot lock everyone out" |
| 21 | **Race: access revoked while an upload is in flight** | New-version upload re-checks permission *inside* the transaction. | (design; covered by the transaction) |
| 22 | **Information leaks in errors** | 500s return an id only; details stay in the server log. | hygiene: "errors never leak internals" |

## Knowingly accepted (the honest list)

1. **Someone with the secret AND write access to the DB and head file can rewrite the audit trail.** The HMAC key and the DB live on the same host. Mitigation I'd do next: ship the head hash off-box on a schedule (the admin Verify screen shows it so you can copy it by hand today).
2. **If `TV_SECRET` is lost, every file is unrecoverable. If it leaks together with a data copy, files can be decrypted.** No KMS or key rotation. Accepted for scope.
3. **Once a person has downloaded a file, I cannot un-download it.** "Immediately" means the *next request* is refused. That is the strongest guarantee a server can give; the audit trail tells you what left.
4. **403 vs 404 reveals existence to people who already hold access** (e.g. a reader trying to edit gets 403). They already know the document exists, so nothing new leaks. People with *no* access always get 404.
5. **No MFA, no email, no self-service password reset.** Admin-issued temporary passwords (shown once, must be changed). Weak spot: a phished password is enough. Next step would be TOTP.
6. **TLS is the host's job.** The app sets `Secure` cookies and HSTS in production but does not terminate TLS. Run it behind HTTPS (Render, Fly, nginx).
7. **Throttling is on sign-in only.** Other endpoints have no general rate limit; a signed-in user could hammer the API. Body size limits and per-request auth bound the damage.
8. **Single-node SQLite.** Fine for this scale, not for horizontal scaling. Files are read fully into memory (10 MB cap), so large files and heavy concurrency are not supported.
9. **No antivirus scanning** of uploads. I limit what types are accepted and never render them, but a malicious-but-valid PDF/docx is stored as-is and opened by the recipient's own software.
10. **The suggester is rule-based, not an LLM.** That is deliberate (see WRITEUP.md): contents never leave the server and there is no model to prompt-inject. Its suggestions are only as good as the metadata.
11. **`X-Forwarded-For` is trusted only if `TV_TRUST_PROXY=1`.** If set while *not* behind a proxy, a client could spoof its IP in logs and dodge the IP throttle (per-account throttling still holds).
12. **The demo seed has public passwords** (they're in the README). Never turn `TV_SEED_DEMO` on for real data.
13. **Audit log grows forever.** No retention or archival.

## Things I'd test next

Concurrency stress on grant/revoke races, a fuzz run over upload parsers, and a second reviewer attacking the deployed instance with a proxy (Burp/ZAP).
