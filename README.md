# TrustVault — Secure Document Sharing with a Verifiable Audit Trail

**Built for the Snovasys Fresher Hiring Challenge 2026**

**Live Demo:** https://trustvault-x5qb.onrender.com

**Demo Video:** [Watch the TrustVault Demo](https://drive.google.com/file/d/185Fcn_F8hm3ppjUvL6C-FMp82SkAyqpy/view?usp=drive_link)


TrustVault is a secure document-sharing platform designed to ensure that documents are accessible only to authorised users and that document activity can be investigated through an auditable record.

The project focuses on three essential security requirements:

1. **Authorisation on every request:** Hiding a button is not access control. The server must verify permission before allowing a user to read, download, edit, or delete a document.
2. **Accountable document activity:** Record important actions, including denied access attempts, and provide an integrity-verification mechanism for the audit trail.
3. **Immediate access revocation:** Once a permission is revoked, subsequent requests must no longer be authorised by that grant.

TrustVault is built with Node.js, SQLite, built-in cryptographic APIs, and a plain JavaScript frontend.

---

## Table of Contents

- [Live Demo](#live-demo)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Architecture](#architecture)
- [Roles and Permissions](#roles-and-permissions)
- [Security Design](#security-design)
- [Demo Accounts](#demo-accounts)
- [Try the Live Demo](#try-the-live-demo)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Database Schema and Setup](#database-schema-and-setup)
- [Automated Tests](#automated-tests)
- [API Documentation](#api-documentation)
- [Threat Model](#threat-model)
- [AI Usage and Review](#ai-usage-and-review)
- [Deployment](#deployment)
- [Demo Video](#demo-video)
- [Known Limitations](#known-limitations)
- [Project Structure](#project-structure)
- [Future Improvements](#future-improvements)

---

## Live Demo

**Application:** https://trustvault-x5qb.onrender.com

The live application is intended for evaluation using synthetic demo data.

The demo credentials below are public by design. Do not upload real confidential documents or reuse personal passwords.

The deployment uses Render. Its storage behaviour depends on the configured service and disk. If the service uses an ephemeral filesystem, locally stored database records and encrypted files may be lost during restarts or redeployments.

For production use, configure persistent storage, secure secret management, backups, and a tested recovery procedure.

---

## Key Features

### 1. Authentication and role-based access

- User authentication and session management.
- Administrator, document owner, and viewer roles.
- Server-side role and document-permission checks.
- Session security and request-protection mechanisms.

### 2. Document management

- Upload and organise documents.
- Search and manage document metadata.
- Filter documents by name, owner, category, and date, where supported by the implementation.
- Manage document lifecycle operations, including deletion and trash retention, where enabled.

### 3. Document-level permissions

- Grant read or edit access to named users.
- Revoke previously granted permissions.
- Support time-limited sharing for external partners, where configured.
- Enforce access restrictions on the server rather than relying on frontend visibility.

### 4. Encrypted file storage

- AES-256-GCM authenticated encryption for stored file contents.
- Cryptographic key derivation using a root secret.
- Separation of file-storage operations from authorisation decisions.

### 5. Audit trail

- Record important document and permission activities.
- Record refused access attempts where instrumented.
- Maintain a hash-chained audit log.
- Provide an audit-integrity verification function.

### 6. AI-assisted sharing suggestions

- Suggest potential recipients to a document owner.
- Require a human decision before changing permissions.
- Do not allow an AI suggestion alone to grant access.

### 7. Automated security testing

The repository includes tests intended to cover authentication, authorisation, permission revocation, request protection, file validation, storage, audit integrity, and AI-assisted sharing.

Run the test suite yourself before relying on its reported test count or coverage.

---

## Technology Stack

| Component | Technology |
|---|---|
| Runtime | Node.js 22+ |
| HTTP server | Built-in `node:http` |
| Database | SQLite using `node:sqlite` |
| Cryptography | Built-in `node:crypto` |
| File encryption | AES-256-GCM |
| Password hashing | Scrypt |
| Frontend | HTML, CSS, and plain JavaScript |
| Testing | Node.js test runner, if configured in the repository |
| Deployment | Docker and Render |

**Dependencies:** The project is designed to use zero third-party npm runtime dependencies. Verify the repository's `package.json` before claiming that every development and test dependency is absent.

**Compatibility:** Use a Node.js release that supports the project's use of `node:sqlite`. Check the runtime requirements and startup logs before deployment.

---

## Architecture

TrustVault separates the main security responsibilities into dedicated modules.

```text
Browser
   |
   v
HTTP Server and Router
   |
   +--> Authentication and Session Management
   |
   +--> Role and Document Authorisation
   |        |
   |        v
   |     Permission Decision
   |
   +--> Document Routes
   |        |
   |        +--> Input Validation
   |        +--> Encrypted File Storage
   |        +--> SQLite Metadata
   |        +--> Audit Trail
   |
   +--> Administration and Audit Verification
   |
   +--> AI-Assisted Sharing Suggestions
```

The server is responsible for making access decisions. Client-side controls improve usability but must not be treated as security boundaries.

### Main security modules

- `src/authz.js` — central authorisation decision functions.
- `src/audit.js` — audit-event recording and integrity verification.
- `src/crypto.js` — password hashing and cryptographic key operations.
- `src/storage.js` — encrypted document storage.
- `src/validate.js` — document-upload validation.
- `src/suggest.js` — AI-assisted sharing suggestions.
- `src/routes/` — authentication, document, sharing, and administrative routes.

---

## Roles and Permissions

The intended permission model distinguishes platform administration from access to document contents.

| Action | Administrator | Document owner | Viewer |
|---|---|---|---|
| View administrative metadata | Yes | No, unless separately granted | No, unless separately granted |
| Read an authorised document | No automatic content access | Yes, for owned documents | Yes, with read permission |
| Upload documents | According to configured policy | Yes | According to configured policy |
| Edit a document | No automatic content access | Yes, for owned documents | Only with edit permission |
| Grant document access | Administrative functions only, as implemented | Yes, for owned documents | No |
| Revoke document access | Administrative functions only, as implemented | Yes, for owned documents | No |
| Inspect administrative audit view | Yes | No | No |
| Access another user's private document | No automatic access | No, without a valid grant | No, without a valid grant |

The table describes the intended model. The actual routes and policy implementation are authoritative; any unsupported action must be rejected by the server.

### Important distinction

An administrator should not automatically gain permission to read every document simply because they administer the platform. Administrative access to metadata and administrative access to document contents are separate decisions.

---

## Security Design

### 1. Server-side authorisation

Document access must be checked on every applicable request.

The intended central authorisation functions are:

- `decide()` — determine whether an action is permitted.
- `requireDocument()` — enforce the required permission for a document operation.
- `readableWhere()` — restrict list and search results to documents the current user can access.

A download route must authorise access before reading or returning file contents.

Changing a document ID in a URL must not grant access to another user's document.

### 2. Non-disclosing access denials

When a document is unavailable to a user, returning the same response for an inaccessible document and a nonexistent document can reduce document-ID enumeration.

For example, the documented demo expects an unauthorised request to:

```text
/api/documents/<id>
```

to return `404` for an inaccessible document.

The exact endpoint, response, and audit behaviour should be verified against the deployed implementation.

### 3. Permission revocation

After a grant is revoked, subsequent requests must evaluate the updated permission state.

Cached permissions, previously issued links, and other access mechanisms must not bypass the new decision. If temporary download URLs or tokens are introduced, their revocation behaviour must be documented and tested.

### 4. Encrypted file storage

Stored file contents are designed to use AES-256-GCM authenticated encryption.

The root secret, `TV_SECRET`, is used to derive cryptographic keys. Losing this secret may make stored files unreadable.

Keep the secret separate from the database and encrypted files. Never commit production secrets to GitHub or include them in screenshots, logs, or the demo video.

Encryption at rest does not replace access control. The application must still authorise a user before returning decrypted document contents.

### 5. Audit integrity

The intended audit trail uses a hash chain and an integrity-verification mechanism.

A hash chain can make unauthorised changes detectable when verification is implemented correctly and the trusted chain state is protected. It does not, by itself, prevent an attacker with sufficient database access from rewriting the entire chain.

For stronger production evidence, consider an independently protected checkpoint, append-only external logging, or a separately controlled audit service.

### 6. Upload validation

Uploads should be validated for:

- File size.
- Permitted file types and content.
- Filename handling.
- Safe storage paths.
- Rejection of invalid or malformed requests.

File extensions alone are not sufficient to establish a file's actual type.

### 7. Session and request security

Review the implementation of:

- Secure cookies in production.
- Session expiry and invalidation.
- CSRF protection for state-changing operations.
- Security headers.
- HTTPS enforcement.
- Request-size limits.
- Rate limiting for authentication and other sensitive endpoints.

Document any controls that are not yet implemented as known limitations.

---

## Demo Accounts

The following accounts are documented for public demo use.

| Role | Email | Password |
|---|---|---|
| Administrator | `admin@trustvault.demo` | `Admin#Demo2026` |
| Document owner | `alice@trustvault.demo` | `Owner#Demo2026` |
| Document owner | `bob@trustvault.demo` | `Owner#Demo2026` |
| Viewer | `carol@trustvault.demo` | `Viewer#Demo2026` |
| Viewer | `dave@trustvault.demo` | `Viewer#Demo2026` |
| External partner | `partner@external.demo` | `Partner#Demo2026` |

**These are expected demo credentials, not a guarantee that the current live deployment has the same seeded accounts.** Verify each account on the deployed application before submission.

Never use these public passwords for real accounts.

---

## Try the Live Demo

Use synthetic data only.

### Scenario 1: Cross-user access denial

1. Sign in as Alice.
2. Open the private document named *Private notes*.
3. Sign out and sign in as Bob.
4. Attempt to access Alice's document using its document ID.
5. Verify that Bob cannot read or download the document.
6. Return to Alice's activity view and check whether the refused attempt is recorded.

### Scenario 2: Human-confirmed sharing suggestions

1. Sign in as Alice.
2. Open *Salary letter*.
3. Select **Suggest who should see this**.
4. Review the proposed recipients.
5. Confirm that no permission changes occur merely because suggestions were generated.
6. Grant access only after an explicit human confirmation.

### Scenario 3: Immediate permission revocation

1. Sign in as Alice.
2. Grant access to the external partner, if the deployed feature supports it.
3. Sign in as the partner and access the shared document.
4. Return to Alice and revoke the grant.
5. As the partner, make a fresh request for the document.
6. Verify that the new request is denied.

### Scenario 4: Administrative separation

1. Sign in as the administrator.
2. Open the document-management view.
3. Verify which metadata the administrator can see.
4. Confirm that administrative metadata access does not automatically grant document-content access.
5. Open the audit view and run integrity verification.

### Scenario 5: Audit-tampering detection

Use a disposable local test database rather than the live deployment.

1. Create a fresh test environment.
2. Generate audit events.
3. Alter a test audit record.
4. Run the integrity-verification function.
5. Confirm that the expected tampering is detected.
6. Preserve the test output as evidence.

Do not modify the live database or interfere with other judges' evaluation.

---

## Quick Start

### Prerequisites

- Git.
- Node.js 22+ with support for `node:sqlite`.
- A terminal or command prompt.
- Docker, if using the Docker workflow.

### 1. Clone the repository

Replace the placeholder with your actual public repository URL.

```bash
git clone <YOUR_PUBLIC_GITHUB_REPOSITORY_URL> trustvault
cd trustvault
```

### 2. Start with demo data

```bash
TV_SEED_DEMO=1 npm start
```

Open:

```text
http://127.0.0.1:3000
```

This command is for a disposable demo environment. Do not enable demo seeding against real data.

On Windows PowerShell, use:

```powershell
$env:TV_SEED_DEMO = "1"
npm start
```

### 3. Run automated tests

In a separate terminal:

```bash
npm test
```

Review the actual test output and exit status. The README's expected test count should match the tests present in the current repository.

### 4. Generate a production secret

```bash
npm run setup
```

Follow the script's instructions to generate a secret and configure the required environment variables.

Never publish the resulting secret.

---

## Configuration

| Variable | Purpose | Default or requirement |
|---|---|---|
| `TV_SECRET` | Root secret used to derive cryptographic keys | Required in production; at least 32 characters according to the application configuration |
| `NODE_ENV` | Enables production settings | Set to `production` in production |
| `PORT` | HTTP listening port | `3000`, unless overridden by the host |
| `HOST` | Interface to bind | `127.0.0.1` in development; production configuration may use `0.0.0.0` |
| `TV_DATA_DIR` | Location for database and encrypted files | `./data`, unless overridden |
| `TV_TRUST_PROXY` | Trust proxy-provided client IP information | Enable only behind a correctly configured trusted proxy |
| `TV_ADMIN_EMAIL` | Initial administrator account email | Required when creating the initial administrator through this configuration |
| `TV_ADMIN_PASSWORD` | Initial administrator password | Use a strong, unique secret |
| `TV_SEED_DEMO` | Loads demo data into an empty database | `0` or unset outside disposable demo environments |
| `TV_MAX_UPLOAD_BYTES` | Maximum upload size | `10485760` bytes (10 MiB), if configured that way in the application |
| `TV_TRASH_DAYS` | Trash retention period | `30`, if configured that way in the application |
| `TV_INSECURE_COOKIES` | Allows non-Secure cookies in selected test scenarios | Do not enable for normal HTTPS production use |

Check the implementation and deployment configuration for the exact defaults. Do not place secret values in this file.

### Secret management

- Keep production secrets in the hosting provider's secret or environment-variable settings.
- Never commit `.env`, private keys, passwords, or generated secret files.
- Back up the encrypted data and database according to a tested recovery plan.
- Store a protected copy of the root secret separately from the data it protects.
- Restrict who can change production environment variables.

---

## Database Schema and Setup

The schema is defined in:

- [`src/db.js`](src/db.js)

The application is designed to initialise the database schema when it starts.

The repository also documents these helper commands:

```bash
npm run setup
npm run seed
```

- `npm run setup` generates a fresh secret and prints configuration instructions.
- `npm run seed` loads demo data into an empty database, according to the seed implementation.

Review the scripts before running them against any existing database.

### Production database considerations

Before using TrustVault for real confidential documents:

- Use persistent storage.
- Verify transaction and permission-update behaviour.
- Establish backup and restore procedures.
- Protect encryption keys independently.
- Test recovery after service restarts.
- Avoid running demo seeding against production data.

---

## Automated Tests

Run the complete test suite:

```bash
npm test
```

The project documentation reports a target of 60 tests. Confirm the current count and result from the actual repository before citing that number in a presentation or submission.

The reported test areas include:

- Cross-user document access.
- Role-based restrictions.
- Permission grants and revocation.
- Expired permissions.
- Trash and deletion behaviour.
- Agreement between authorisation decisions and document-list filtering.
- Authentication and sessions.
- CSRF and request validation.
- Upload and storage handling.
- Audit-trail integrity.
- AI-assisted sharing suggestions.

### Security testing principle

A useful authorisation test must fail when the relevant security check is removed.

Test direct HTTP requests, not only the user interface. A hidden button does not prove that the underlying endpoint is protected.

The expected security outcomes should include:

- A user cannot retrieve another user's private document.
- A viewer cannot perform an edit operation without edit permission.
- A revoked grant no longer authorises subsequent requests.
- An expired grant cannot be used.
- Invalid uploads are rejected.
- Tampered audit data is detected within the documented threat model.

Tests must run against isolated test data and must not damage the live deployment.

---

## API Documentation

The endpoint-level documentation is maintained in:

- [`docs/API.md`](docs/API.md)

For every endpoint, the API documentation should state:

- HTTP method and route.
- Authentication requirement.
- Permitted roles.
- Required document permission, if applicable.
- Input validation rules.
- Expected success and error responses.
- Relevant audit events.

The server must make the final access decision for every protected request.

Do not assume that an endpoint is safe because the frontend does not display a link to it.

---

## Threat Model

The threat model is documented in:

- [`THREATS.md`](THREATS.md)

It should cover the threats considered during development, the mitigations implemented, and the risks knowingly accepted.

Important areas to evaluate include:

- Insecure direct object references.
- Missing authorisation checks on individual routes.
- Permission revocation and expired grants.
- Session theft and fixation.
- CSRF and request forgery.
- Upload validation and malicious file content.
- Path traversal.
- Audit-record tampering.
- Secret leakage and encryption-key loss.
- Brute-force authentication attempts.
- Information disclosure through errors and logs.
- Denial of service and resource exhaustion.
- Backup compromise and data recovery.
- AI suggestions that could improperly widen access.
- Administrator privileges and insider threats.

Every documented threat should be linked to the relevant mitigation and, where practical, an automated test.

Do not describe a risk as eliminated unless the implementation and tests support that claim.

---

## AI Usage and Review

The AI-development record is maintained in:

- [`PROMPTS.md`](PROMPTS.md)

The competition requires at least five dated entries describing how AI was used, what it produced, what was wrong, and how the issue was corrected. At least two entries must concern authorisation, access control, or audit integrity.

The repository's actual commit history should reflect the development process. Do not invent prompts, dates, errors, or commits after the fact.

### AI-assisted sharing

TrustVault's sharing assistant is intended to suggest potential recipients rather than grant access automatically.

The owner must review and explicitly confirm any permission changes. AI output must never bypass the normal server-side authorisation and auditing rules.

---

## Deployment

### Render

Live demo:

https://trustvault-x5qb.onrender.com

The repository documents a Render Blueprint and Docker-based deployment.

Before deploying, verify:

- The Node.js runtime is compatible.
- `TV_SECRET` is generated and securely configured.
- The application listens on the port provided by Render.
- `NODE_ENV=production` is configured as intended.
- The data directory and persistent-storage requirements are understood.
- Demo seeding is enabled only when intentionally required.
- The live health and login flows work.
- The application does not expose secrets through errors or logs.

### Persistence on Render

A free web service without a persistent disk should be treated as an ephemeral environment for locally stored data. Files and SQLite records can be lost when the filesystem is replaced or the service restarts.

For a production-oriented deployment:

1. Configure suitable persistent storage.
2. Keep `TV_SECRET` stable and securely backed up.
3. Disable demo seeding for real data.
4. Implement and test backups.
5. Verify restoration of both the database and encrypted files.
6. Test the deployment after a restart.
7. Confirm that permission revocation and audit verification still work.

### Docker

The documented Docker workflow is:

```bash
docker build -t trustvault .
docker run --rm -p 3000:3000 trustvault
```

This basic example is suitable only for checking that the image starts. Production deployment requires the environment variables, persistent storage, secret management, and network settings documented by the project.

Do not run a production instance with a development secret or insecure cookies.

---

## Demo Video

**Required deliverable:** A five-minute project demonstration.

Suggested recording plan:

| Time | Demonstration |
|---|---|
| 0:00–0:30 | Introduce TrustVault and the security problem |
| 0:30–1:30 | Show Alice's private document and Bob's denied request |
| 1:30–2:15 | Grant access to the external partner and revoke it |
| 2:15–3:00 | Show administrator metadata and audit verification |
| 3:00–3:45 | Demonstrate audit-tampering detection in an isolated local test environment |
| 3:45–4:20 | Show AI sharing suggestions and human confirmation |
| 4:20–5:00 | Show automated test results and explain the authorisation code |

### Recording checklist

- Keep the video within the competition's duration requirement.
- Use readable browser zoom and terminal text.
- Avoid showing secrets, personal information, or real confidential documents.
- Prepare the demo accounts and test data before recording.
- Show genuine application behaviour.
- Do not alter the live production database to create a security demonstration.
- Verify that the final exported video plays correctly.

---

## Known Limitations

The current implementation and deployment should be evaluated against these areas before any production use:

- A free hosting environment may not provide durable local storage.
- The application depends on retaining the root encryption secret to recover encrypted files.
- A hash-chained audit log is not equivalent to an independently protected, immutable audit service.
- Security guarantees depend on every protected route enforcing the intended authorisation policy.
- The effectiveness of upload validation depends on the actual validation rules and supported file types.
- The availability of AI suggestions depends on the configured implementation and any required external service.
- Production readiness requires verified backup, restoration, monitoring, and incident-response procedures.

The authoritative project-specific limitations are recorded in [`WRITEUP.md`](WRITEUP.md) and [`THREATS.md`](THREATS.md).

---

## Project Structure

```text
trustvault/
├── server.js
├── src/
│   ├── app.js
│   ├── authz.js
│   ├── audit.js
│   ├── crypto.js
│   ├── storage.js
│   ├── validate.js
│   ├── suggest.js
│   ├── db.js
│   └── routes/
├── public/
├── test/
├── docs/
│   └── API.md
├── scripts/
├── THREATS.md
├── PROMPTS.md
├── WRITEUP.md
├── Dockerfile
├── render.yaml
├── package.json
└── README.md

This is the documented project layout. Check the actual repository for the exact filenames and directories.
