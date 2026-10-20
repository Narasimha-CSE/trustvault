# TrustVault API

All endpoints are under `/api`, speak JSON (uploads are raw bytes), and need a session cookie unless stated.

**Conventions**

- **CSRF:** every `POST/PATCH/DELETE` must send the header `X-CSRF-Token` (returned by `/api/auth/login` and `/api/auth/me`), and any `Origin` header must match the host.
- **"Owner of doc" / "Reader" / "Editor":** the *per-document* permission, decided by one function (`src/authz.js`) on every request, never cached.
- **Errors:** `401` not signed in, `403` signed in but not allowed (role, or you can see the document but not do this action), `404` you have no access *or* it does not exist (the two are indistinguishable), `400/413/415` bad input, `429` too many sign-in attempts.
- Every call that touches a document is written to the audit trail, **including the refused ones**.

## Who can call what

Roles: **admin**, **owner** (document owner), **viewer**. "Any signed-in user" means all three.

### Authentication

| Endpoint | Who may call | Notes |
|---|---|---|
| `POST /api/auth/login` | Anyone (no session) | `{email, password}`. Throttled per account and per IP. Same error for unknown email, wrong password and disabled account. |
| `POST /api/auth/logout` | Any signed-in user | Destroys the session server-side. |
| `GET /api/auth/me` | Any signed-in user | Current user and CSRF token. |
| `POST /api/auth/password` | Any signed-in user (also while a password change is forced) | `{currentPassword, newPassword}`. Signs out every other session. |
| `GET /api/users/directory?q=` | owner, admin | Active people to pick when sharing. |

### Documents

| Endpoint | Who may call | Notes |
|---|---|---|
| `GET /api/documents?q&scope&tag&folder&sort&dir&limit&offset` | Any signed-in user | Returns **only** documents the caller can read (owned, or actively granted). `scope`: `all`, `mine`, `shared`. |
| `GET /api/tags` | Any signed-in user | Tag counts across documents the caller can read only. |
| `POST /api/documents?name=&title=&description=&tags=&folderId=` | **owner** role | Body: raw bytes, `Content-Type: application/octet-stream`. Allow-listed type, content sniffed, 10 MB cap. Creates a private document. |
| `GET /api/documents/:id` | owner of doc, reader, editor | Metadata and version list. Audited as a view. |
| `GET /api/documents/:id/download?version=` | owner of doc, reader, editor | Decrypts and streams as an attachment. **Audited before any byte is sent.** |
| `PATCH /api/documents/:id` | owner of doc, editor (owner role required) | Name, description, tags. Moving to a folder: owner of doc only. |
| `POST /api/documents/:id/versions?name=` | owner of doc, editor (owner role required) | New version; old versions kept. |
| `DELETE /api/documents/:id` | owner of doc | Move to trash. **Revokes every grant.** |
| `POST /api/documents/:id/restore` | owner of doc | Restores as private. |
| `DELETE /api/documents/:id/purge` | owner of doc (must be in trash) | Permanent delete of rows and encrypted files. |
| `GET /api/trash` | owner role | Own trashed documents. |
| `GET /api/documents/:id/activity` | owner of doc | Who viewed, downloaded, changed, or was refused. |

### Sharing

| Endpoint | Who may call | Notes |
|---|---|---|
| `GET /api/documents/:id/grants` | owner of doc | Active and past grants. |
| `POST /api/documents/:id/grants` | owner of doc | `{userId, permission: read|edit, expiresAt?}`. External people: expiry required, max 30 days. Viewers cannot get `edit`. Admins cannot be granted. |
| `DELETE /api/documents/:id/grants/:grantId` | owner of doc | Effective on the next request. |
| `POST /api/documents/:id/ai/suggest` | owner of doc | Returns suggestions only. **Grants nothing.** |
| `POST /api/documents/:id/ai/suggestions/:sid/decision` | owner of doc who requested it | `{accept:[{userId,permission?,expiresAt?}], reject:[ids]}`. Only people who were actually suggested can be confirmed; every normal grant rule applies. Suggestion and decision are both audited. |

### Folders (organisation only; they grant nothing)

| Endpoint | Who may call |
|---|---|
| `GET/POST /api/folders`, `PATCH/DELETE /api/folders/:id` | owner role, own folders only |

### Administration

| Endpoint | Who may call | Notes |
|---|---|---|
| `GET /api/admin/users` | admin | |
| `POST /api/admin/users` | admin | Returns a one-time temporary password; user must change it at first sign-in. |
| `PATCH /api/admin/users/:id` | admin | Name, role, department, disabled. Disabling logs the person out immediately. Cannot remove the last admin or yourself. |
| `POST /api/admin/users/:id/reset-password` | admin | One-time temporary password; kills all sessions. |
| `GET /api/admin/documents` | admin | **Metadata only.** No content, no storage keys. |
| `GET /api/admin/grants` | admin | All active grants. |
| `POST /api/admin/grants/:id/revoke` | admin | Force-revoke, audited. |
| `GET /api/admin/audit?category&denied&actor&target&from&to&before&limit` | admin | Filter the trail. |
| `GET /api/admin/audit/verify` | admin | Recomputes the hash chain; reports the first broken entry. |
| `GET /api/admin/alerts` | admin | Things worth noticing (see THREATS.md). |

Anything not listed here does not exist. Unknown routes return `404`; wrong methods `405`.
