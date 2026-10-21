# TrustVault — Secure Document Sharing with a Verifiable Audit Trail

**Built for the Snovasys Fresher Hiring Challenge 2026**

**Live Demo:** https://trustvault-x5qb.onrender.com

**Demo Video:** [Watch the TrustVault Demo](https://drive.google.com/file/d/185Fcn_F8hm3ppjUvL6C-FMp82SkAyqpy/view?usp=drive_link)

TrustVault is a secure document-sharing platform designed to help ensure that documents are accessible only to authorised users and that document activity can be investigated through an auditable record.

The project focuses on three essential security requirements:

1. **Authorisation on every request:** Hiding a button is not access control. The server must verify permission before allowing a user to read, download, edit, or delete a document.
2. **Accountable document activity:** Important actions, including denied access attempts where instrumented, should be recorded and supported by an audit-integrity verification mechanism.
3. **Access revocation:** After a permission is revoked, subsequent requests must no longer be authorised by that grant.

TrustVault uses Node.js, SQLite, built-in cryptographic APIs, and a plain JavaScript frontend.

> **Evaluation note:** The live demo is intended for evaluation using synthetic data. The repository's source code, automated test results, and deployed behaviour are authoritative for determining which security controls are implemented and working.

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
- [Future Improvements](#future-improvements)
- [Project Structure](#project-structure)

---

## Live Demo

**Application:** https://trustvault-x5qb.onrender.com

The deployed application is intended for evaluation using synthetic demo data.

The demo credentials in this README are public by design. Do not upload real confidential documents or reuse personal passwords.

The deployment uses Render. Persistence depends on the service configuration and whether persistent storage is attached. If the application stores its database and encrypted files on an ephemeral filesystem, those files may be lost when the filesystem is replaced or the service is redeployed.

For production use, configure persistent storage, secure secret management, backups, monitoring, and a tested recovery procedure.

## Key Features

### 1. Authentication and role-based access

- User authentication and session management.
- Administrator, document-owner, and viewer roles, according to the application configuration.
- Server-side role and document-permission checks.
- Session and request-protection mechanisms, where implemented.

### 2. Document management

- Upload and organise documents.
- Search and manage document metadata.
- Filter documents by name, owner, category, or date where supported.
- Document lifecycle operations, including deletion and trash retention where implemented.

### 3. Document-level permissions

- Grant read or edit access to named users, where supported.
- Revoke previously granted permissions.
- Time-limited sharing for external partners, if enabled.
- Server-side enforcement of document access restrictions.

### 4. Encrypted file storage

- AES-256-GCM authenticated encryption for stored file contents, as described by the project implementation.
- Cryptographic key derivation using a root secret.
- Separation of file-storage operations from authorisation decisions.

### 5. Audit trail

- Recording of important document and permission activities.
- Recording of denied access attempts where instrumented.
- Hash-chained audit records, according to the implementation.
- An audit-integrity verification mechanism, if enabled.

### 6. AI-assisted sharing suggestions

- Suggestions for potential document recipients.
- Human review before a suggested permission change is applied.
- AI suggestions must not independently grant access or bypass normal authorisation checks.

### 7. Automated security testing

The project is intended to test security-sensitive behaviour, including authentication, authorisation, permission revocation, request protection, upload validation, storage, audit integrity, and AI-assisted sharing.

Run the test suite and inspect the actual output before relying on a reported test count or coverage figure.

---

## Technology Stack

| Component | Technology |
|---|---|
| Runtime | Node.js 22+ |
| HTTP server | Built-in `node:http` |
| Database | SQLite using `node:sqlite` |
| Cryptography | Built-in `node:crypto` |
| File encryption | AES-256-GCM, as implemented |
| Password hashing | Scrypt, as implemented |
| Frontend | HTML, CSS, and plain JavaScript |
| Testing | Node.js test runner, if configured |
| Deployment | Docker and Render, where configured |

The project is designed to minimise third-party runtime dependencies. Check `package.json` to confirm the actual runtime and development dependencies.

Use a Node.js release compatible with the project's use of `node:sqlite`. Review startup logs and the package configuration if the application fails to start.

## Architecture

TrustVault separates the main application responsibilities into modules. The following diagram represents the intended architecture; verify the exact module boundaries against the current source code.

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

The server must make the final access decision. Client-side controls improve usability but must not be treated as security boundaries.

### Main security modules

The documented module responsibilities are:

- `src/authz.js` — central authorisation decision functions.
- `src/audit.js` — audit-event recording and integrity verification.
- `src/crypto.js` — password hashing and cryptographic key operations.
- `src/storage.js` — encrypted document storage.
- `src/validate.js` — document-upload validation.
- `src/suggest.js` — AI-assisted sharing suggestions.
- `src/routes/` — authentication, document, sharing, and administrative routes.

Confirm that these paths and responsibilities match the files in the submitted repository.

## Roles and Permissions

The intended permission model distinguishes platform administration from access to document contents.

| Action | Administrator | Document owner | Viewer |
|---|---|---|---|
| View administrative metadata | According to administrative policy | No, unless separately permitted | No, unless separately permitted |
| Read an authorised document | No automatic content access | Yes, for owned documents | With valid read permission |
| Upload documents | According to configured policy | According to configured policy | According to configured policy |
| Edit a document | No automatic content access | Yes, for owned documents | Only with edit permission |
| Grant document access | According to administrative policy | For owned documents, if supported | No |
| Revoke document access | According to administrative policy | For owned documents, if supported | No |
| Inspect administrative audit view | If authorised | No, unless separately permitted | No, unless separately permitted |
| Access another user's private document | No automatic access | No, without a valid grant | No, without a valid grant |

This table describes the intended model, not proof that every action is implemented. The actual server-side policy and routes determine the permissions available in the running application.

### Important distinction

An administrator should not automatically gain permission to read every document simply because they administer the platform. Administrative metadata access and document-content access are separate security decisions.

## Security Design

### 1. Server-side authorisation

Document access should be checked on every applicable request.

The documented central authorisation functions are:

- `decide()` — determine whether an action is permitted.
- `requireDocument()` — enforce the required permission for a document operation.
- `readableWhere()` — restrict document-list and search results to documents the current user can access.

A download route must authorise access before reading or returning file contents. Changing a document ID in a URL must not grant access to another user's private document.

### 2. Non-disclosing access denials

Returning the same response for an inaccessible document and a nonexistent document can help reduce document-ID enumeration.

For example, an unauthorised request to a document endpoint such as:

```text
/api/documents/<id>
```

may return `404` when the document is inaccessible, depending on the implemented API policy.

Verify the actual endpoint, response status, response body, and audit behaviour against the deployed application and `docs/API.md`.

### 3. Permission revocation

After a grant is revoked, subsequent requests must evaluate the updated permission state.

Cached permissions, previously issued links, and other access mechanisms must not bypass the new decision. If temporary download URLs or tokens are supported, their revocation behaviour should be documented and tested.

### 4. Encrypted file storage

The project describes AES-256-GCM authenticated encryption for stored file contents.

The root secret, `TV_SECRET`, is documented as a source for cryptographic key derivation. Losing the required secret may make stored files unreadable.

- Keep secrets separate from the database and encrypted files.
- Never commit production secrets to GitHub.
- Never include secrets in screenshots, logs, or the demo video.
- Test key management and recovery procedures before storing important data.

Encryption at rest does not replace access control. The application must authorise a user before returning decrypted document contents.

### 5. Audit integrity

The intended audit trail uses a hash chain and an integrity-verification mechanism.

A correctly implemented hash chain can make certain record changes detectable. It does not, by itself, prevent an attacker with sufficient database access from rewriting the entire chain.

For stronger production assurance, consider an independently protected checkpoint, append-only external logging, or a separately controlled audit service.

### 6. Upload validation

Upload handling should validate:

- File size.
- Permitted file types and content.
- Filename handling.
- Safe storage paths.
- Invalid or malformed requests.

File extensions alone are not sufficient to establish a file's actual type. The implementation should also prevent path traversal and unsafe file handling.

### 7. Session and request security

Review the implementation and configuration of:

- Secure cookies in production.
- Session expiry and invalidation.
- CSRF protection for state-changing operations.
- Security headers.
- HTTPS enforcement.
- Request-size limits.
- Rate limiting for authentication and sensitive endpoints.

Controls that are not implemented should be documented as limitations rather than presented as completed protections.

---

## Demo Accounts

The following accounts are documented for public demonstration.

| Role | Email | Password |
|---|---|---|
| Administrator | `admin@trustvault.demo` | `Admin#Demo2026` |
| Document owner | `alice@trustvault.demo` | `Owner#Demo2026` |
| Document owner | `bob@trustvault.demo` | `Owner#Demo2026` |
| Viewer | `carol@trustvault.demo` | `Viewer#Demo2026` |
| Viewer | `dave@trustvault.demo` | `Viewer#Demo2026` |
| External partner | `partner@external.demo` | `Partner#Demo2026` |

**Important:** These are the expected demo credentials, not a guarantee that the current live deployment contains these accounts. Verify each account on the deployed application before submission.

These credentials are public demo credentials. Never use them for real accounts or confidential documents.

## Try the Live Demo

Use synthetic data only.

### Scenario 1: Cross-user access denial

1. Sign in as Alice.
2. Open the private document named *Private notes*, if present.
3. Sign out and sign in as Bob.
4. Attempt to access Alice's document using its document ID.
5. Verify that Bob cannot read or download the document.
6. Return to the appropriate activity view and check whether the denied attempt was recorded.

### Scenario 2: Human-confirmed sharing suggestions

1. Sign in as Alice.
2. Open *Salary letter*, if present.
3. Select **Suggest who should see this**, if the feature is available.
4. Review the proposed recipients.
5. Confirm that generating suggestions alone does not change document permissions.
6. Grant access only after an explicit human confirmation.

### Scenario 3: Permission revocation

1. Sign in as Alice.
2. Grant access to the external partner, if supported.
3. Sign in as the partner and access the shared document.
4. Return to Alice and revoke the grant.
5. As the partner, make a fresh request for the document.
6. Verify that the new request is denied.

### Scenario 4: Administrative separation

1. Sign in as the administrator.
2. Open the administrative view.
3. Verify which metadata the administrator can see.
4. Confirm that metadata access does not automatically grant document-content access.
5. Open the audit view and run integrity verification, if available.

### Scenario 5: Audit-tampering detection

Use a disposable local test database, not the live deployment.

1. Create an isolated test environment.
2. Generate audit events.
3. Alter a test audit record.
4. Run the integrity-verification function.
5. Confirm that the expected tampering is detected.
6. Preserve the test output as evidence.

Do not modify the live database or interfere with other evaluators' testing.

---

## Quick Start

### Prerequisites

- Git.
- A compatible Node.js release, preferably Node.js 22 or later for the documented runtime.
- A terminal or command prompt.
- Docker, if using the Docker workflow.

### 1. Clone the repository

```bash
git clone https://github.com/Narasimha-CSE/trustvault.git
cd trustvault
```

### 2. Install dependencies

```bash
npm install
```

If the repository intentionally has no external npm dependencies, this command should still be checked against the actual `package.json` and lockfile.

### 3. Start with demo data

For a disposable local demo environment, the documented command is:

```bash
TV_SEED_DEMO=1 npm start
```

On Windows PowerShell:

```powershell
$env:TV_SEED_DEMO = "1"
npm start
```

Open the local URL shown in the application startup output. If the application uses the documented default port, the URL is:

```text
http://127.0.0.1:3000
```

Do not enable demo seeding against real data. Confirm the application's seed behaviour before running it.

### 4. Run automated tests

```bash
npm test
```

Review the actual test output and exit status. The test count and coverage claims in this README must match the current repository.

### 5. Generate a production secret

The documented setup command is:

```bash
npm run setup
```

Follow the script's instructions to generate a secret and configure the required environment variables. Verify that this script exists and understand its behaviour before running it.

Never publish the generated secret.

---

## Configuration

The following table describes the documented configuration variables. Exact names, defaults, and requirements must be confirmed against the current source code.

| Variable | Purpose | Configuration guidance |
|---|---|---|
| `TV_SECRET` | Root secret used for cryptographic key derivation | Configure a strong secret in production |
| `NODE_ENV` | Runtime environment | Set to `production` in production |
| `PORT` | HTTP listening port | Use the port provided by the hosting platform |
| `HOST` | Network interface to bind | Configure according to local or hosted deployment requirements |
| `TV_DATA_DIR` | Database and encrypted-file location | Ensure persistence and appropriate filesystem permissions |
| `TV_TRUST_PROXY` | Trust proxy-provided client information | Enable only behind a correctly configured trusted proxy |
| `TV_ADMIN_EMAIL` | Initial administrator email | Use according to the application's setup procedure |
| `TV_ADMIN_PASSWORD` | Initial administrator password | Use a strong, unique secret |
| `TV_SEED_DEMO` | Loads demo data | Enable only for intentional, disposable demo environments |
| `TV_MAX_UPLOAD_BYTES` | Maximum upload size | Verify the actual configured limit |
| `TV_TRASH_DAYS` | Trash retention period | Verify the actual configured value |
| `TV_INSECURE_COOKIES` | Allows non-Secure cookies in selected scenarios | Do not enable for normal HTTPS production use |

Check the implementation and hosting configuration for exact defaults. Do not put secret values in this README.

### Secret management

- Keep production secrets in the hosting provider's secret or environment-variable settings.
- Never commit `.env`, private keys, passwords, or generated secret files.
- Back up the encrypted data and database according to a tested recovery plan.
- Store a protected copy of the required root secret separately from the data it protects.
- Restrict who can change production environment variables.
- Rotate secrets using a documented procedure that accounts for existing encrypted data.

---

## Database Schema and Setup

The documented database schema module is:

- [`src/db.js`](src/db.js)

The application is described as initialising the database schema during startup. Confirm the actual initialisation flow in the source code.

The documented helper commands are:

```bash
npm run setup
npm run seed
```

- `npm run setup` — intended to generate a fresh secret and provide configuration instructions.
- `npm run seed` — intended to load demo data into an empty database, according to the seed implementation.

Review the scripts and database initialisation behaviour before running them against an existing database.

### Production database considerations

Before using TrustVault for confidential documents:

- Use suitable persistent storage.
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

The project documentation has previously referenced a target of 60 tests. Confirm the current count and result from the actual repository before citing that number in a presentation or submission.

Test areas intended for evaluation include:

- Cross-user document access.
- Role-based restrictions.
- Permission grants and revocation.
- Expired permissions.
- Trash and deletion behaviour.
- Consistency between authorisation decisions and document-list filtering.
- Authentication and sessions.
- CSRF and request validation.
- Upload and storage handling.
- Audit-trail integrity.
- AI-assisted sharing suggestions.

### Security testing principle

A useful authorisation test must fail when the relevant security check is removed.

Test direct HTTP requests, not only the user interface. A hidden button does not prove that the underlying endpoint is protected.

Expected security outcomes should include:

- A user cannot retrieve another user's private document.
- A viewer cannot edit a document without edit permission.
- A revoked grant no longer authorises subsequent requests.
- An expired grant cannot be used.
- Invalid uploads are rejected.
- Audit-data tampering is detected within the documented threat model.

Tests should use isolated test data and must not damage the live deployment.

---

## API Documentation

Endpoint-level documentation is maintained in:

- [`docs/API.md`](docs/API.md)

For every endpoint, the API documentation should specify:

- HTTP method and route.
- Authentication requirement.
- Permitted roles.
- Required document permission, if applicable.
- Input validation rules.
- Expected success and error responses.
- Relevant audit events.

The server must make the final access decision for every protected request. Do not assume an endpoint is safe because the frontend does not display a link to it.

---

## Threat Model

The threat model is documented in:

- [`THREATS.md`](THREATS.md)

It should explain the threats considered during development, the mitigations actually implemented, and the risks knowingly accepted.

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

Every documented threat should be linked to its mitigation and, where practical, an automated test.

Do not describe a risk as eliminated unless the implementation and tests support that conclusion.

---

## AI Usage and Review

The AI-development record is documented in:

- [`PROMPTS.md`](PROMPTS.md)

The competition requires at least five dated entries describing AI usage, what was produced, what was wrong, and how the issue was corrected. At least two entries must concern authorisation, access control, or audit integrity.

Entries should accurately reflect the development process and include the required evidence, such as relevant commit links. Do not invent prompts, dates, errors, or commits after the fact.

### AI-assisted sharing

The sharing assistant is intended to suggest potential recipients rather than grant access automatically.

The owner should review and explicitly confirm permission changes. AI output must not bypass server-side authorisation or audit rules.

Document any AI-generated implementation errors and how they were identified, corrected, and tested.

---

## Deployment

### Render

**Live demo:** https://trustvault-x5qb.onrender.com

The repository documents a Render and Docker deployment workflow. Confirm the current deployment configuration before making changes.

Before deployment, verify:

- The Node.js runtime is compatible.
- `TV_SECRET` is generated and securely configured.
- The application listens on the port provided by Render.
- `NODE_ENV=production` is configured as intended.
- The data directory and persistence requirements are understood.
- Demo seeding is enabled only when intentionally required.
- The health check and login flows work.
- The application does not expose secrets through errors or logs.

### Persistence on Render

A service without a persistent disk should be treated as an ephemeral environment for locally stored data. Files and SQLite records may be lost when the filesystem is replaced or the service is redeployed.

For a production-oriented deployment:

1. Configure suitable persistent storage.
2. Keep `TV_SECRET` stable and securely backed up.
3. Disable demo seeding for real data.
4. Implement and test backups.
5. Verify restoration of both the database and encrypted files.
6. Test the deployment after a restart.
7. Confirm that permission revocation and audit verification still work.

### Docker

If the repository contains the documented Dockerfile, the basic workflow is:

```bash
docker build -t trustvault .
docker run --rm -p 3000:3000 trustvault
```

This example is for checking that the image builds and starts. A production deployment also requires the appropriate environment variables, persistent storage, secret management, and network settings.

Do not run a production instance with a development secret or insecure cookies.

---

## Demo Video

**Required deliverable:** A five-minute project demonstration.

The video is available here:

[Watch the TrustVault Demo](https://drive.google.com/file/d/185Fcn_F8hm3ppjUvL6C-FMp82SkAyqpy/view?usp=drive_link)

Suggested recording plan:

| Time | Demonstration |
|---|---|
| 0:00–0:30 | Introduce TrustVault and the security problem |
| 0:30–1:30 | Show Alice's private document and Bob's denied request |
| 1:30–2:15 | Grant access to the external partner and revoke it |
| 2:15–3:00 | Show administrator metadata and audit verification |
| 3:00–3:45 | Demonstrate audit-tampering detection in an isolated local test environment |
| 3:45–4:20 | Show AI sharing suggestions and human confirmation |
| 4:20–5:00 | Show actual automated test results and explain the authorisation code |

### Recording checklist

- Keep the video within the competition's duration requirement.
- Use readable browser zoom and terminal text.
- Avoid showing secrets, personal information, or real confidential documents.
- Prepare demo accounts and synthetic test data before recording.
- Show genuine application behaviour.
- Do not alter the live database to create a security demonstration.
- Verify that the final exported video plays correctly and that the sharing permissions allow evaluators to view it.

---

## Known Limitations

The current implementation and deployment should be evaluated against these areas before any production use:

- A free hosting environment may not provide durable local storage.
- The application depends on retaining the required encryption secret to recover encrypted files.
- A hash-chained audit log is not equivalent to an independently protected, immutable audit service.
- Security guarantees depend on every protected route enforcing the intended authorisation policy.
- The effectiveness of upload validation depends on the actual validation rules and supported file types.
- AI-suggestion availability depends on the configured implementation and any required external service.
- Production readiness requires verified backup, restoration, monitoring, and incident-response procedures.

The authoritative project-specific limitations should be recorded in [`WRITEUP.md`](WRITEUP.md) and [`THREATS.md`](THREATS.md).

## Future Improvements

Potential improvements, subject to the current implementation and available development time, include:

- Stronger independent protection for audit records.
- More comprehensive automated authorisation and revocation tests.
- Persistent, monitored production storage with tested backups.
- Better operational logging and security monitoring.
- Rate limiting and abuse protection for sensitive endpoints.
- Expanded API documentation and repeatable clean-install instructions.
- Additional security review and testing of file uploads and session handling.

These are proposed improvements, not claims that the features are already implemented.

---

## Project Structure

The following is the documented project layout. Confirm every path against the actual repository before relying on this tree.

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
```

This tree is descriptive, not a substitute for checking the submitted repository. Remove or update entries that do not exist in the current version.

---
