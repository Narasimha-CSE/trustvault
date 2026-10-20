# WRITEUP

> The brief asks for the permission model "in your own words". I've written it plainly below, but **before
> you submit, reread this and rewrite anything you couldn't defend out loud**. You will be asked to walk
> through the code and change it live.

## What I built

TrustVault is a document platform where a file can be reached **only** by its owner or by a named person who
holds an active grant, and where every access, including refused ones, is recorded in a tamper-evident trail.

- **Roles:** administrator, document owner, viewer (plus an "external" flag for people outside the company).
- **Documents:** upload (type allow-list + content check), versions, tags, folders, search, trash with
  retention and restore, permanent purge.
- **Sharing:** read or edit, to *named people*, optional end date (mandatory and capped at 30 days for
  external people). Owners can take access away at any moment.
- **Audit:** every view, download, change, grant, revoke, sign-in and *refusal*; hash-chained; verifiable in the UI.
- **Admin:** manage accounts, see document *metadata*, see and force-revoke grants, read and verify the audit
  trail, and an "worth noticing" panel.
- **Security:** encrypted files at rest, scrypt passwords, CSRF, strict CSP, throttled sign-in.
- **60 automated tests**, API docs, threat model, zero npm dependencies.

## The permission model, in plain words

1. A document starts **private to its owner**.
2. The owner can give a **named person** `read` or `edit`, optionally until a date.
3. That grant is **one row in the database**. The server looks at it **on every request**. So removing it, or
   letting it expire, or disabling the person, stops access on their very next click. There is nothing cached
   and no link that keeps working.
4. **Admins are not super-users for content.** They run the system (accounts, audit) but cannot open files.
   If they need access, the owner has to grant it, and that is recorded.
5. **Viewers are read-only** no matter what grants exist. Folders **never** grant anything: they only tidy up
   your own files. (The brief's first horror story is "access to a folder, now they can see forty files". I
   chose to have no inheritance at all, so that cannot happen.)
6. If you are refused, you are told "not found", exactly as if the document didn't exist. The real reason is
   written to the audit trail.

**What "immediately" costs:** one indexed query per request instead of a fast token check. At this scale that
is nothing, and it is what makes revocation instantaneous.

## Where AI fits, and where it must not decide

*In building it:* heavily. PROMPTS.md says where it was wrong.

*In the product:* "Suggest who should see this". It looks at **metadata only** (title, description, tags, who
the owner has shared similar things with, departments), never at file contents, and it **returns a list**. It
has no code path to the grant function. The owner ticks who they accept; a normal grant is created through the
same function and same rules as a manual one; and both the suggestion and the decision are audited. It never
suggests admins or external people, never suggests `edit`, and warns on sensitive-looking documents.
I made it rule-based rather than an LLM on purpose: no file content leaves the server, nothing to prompt-inject,
and it is deterministic enough to test. The result shape would let a model replace it without touching
authorisation.

## What I deliberately did not build, and why

A smaller system whose permission model holds beats a larger one with a hole in it.

- **Share links / public links.** The brief's second horror story is a leaver whose link still works. No links = no such bug.
- **Groups and folder inheritance.** They are where over-sharing comes from. Named, per-document grants are
  easy to reason about and to audit. Cost: sharing with ten people is ten clicks.
- **Admin content access / "break glass".** Would need its own approval and audit design; safer to omit.
- **MFA, SSO, email invites, self-service reset.** Real needs, but each adds attack surface and I'd rather
  document the gap (THREATS.md #5) than ship half of it.
- **In-browser preview.** Rendering uploads in our origin is the classic XSS door. Downloads only.
- **Full-text search inside files.** It would mean decrypting and indexing content, widening what can leak.
- **Antivirus, key rotation, off-box audit shipping, horizontal scaling.** Listed as accepted risks.

## What is unfinished

- The things in THREATS.md "Knowingly accepted".
- **Live URL, public repo with history across the week, and the five-minute demo video are yours to produce**:
  see README "Deploy" and "Demo script". I could not deploy for you or record the video.
- Items I could only partly see in the brief's screenshots (requirements 6 and 7 are cut off between two
  images): I implemented them as "audit of who downloaded, and when" and "access that ends on a date". Check
  them against the original text.
