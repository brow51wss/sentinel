---
name: security-audit
description: "Run a two-pass security and code quality audit on a local codebase, and verify claimed fixes against the last audit. Pass 1 discovers possibly-sensitive fields and waits for developer confirmation. Pass 2 runs deterministic scans (via the Sentinel MCP server if available) plus LLM judgment of context-laden findings, producing a prioritized dated report. Pass 3 verifies claimed fixes against the most recent audit with PASS/FAIL/PARTIAL verdicts and a regression scan. Use when the user asks to run the security audit, run Sentinel, audit a project, scan for security issues, check for code slop, verify fixes, re-audit changed areas, confirm Cursor's work, or similar phrases."
---

# Sentinel — Security & Code-Quality Audit Skill (v3)

## What this skill is

Sentinel is a two-form auditor for local codebases:

1. **MCP server** (`sentinel` server; tools: `sentinel_pass1_discover`, `sentinel_pass2_audit`, `sentinel_pass3_verify`) — runs deterministic regex/AST/subprocess checks and writes structured reports. **The MCP is the source of truth for deterministic checks.**
2. **This skill** — guides the LLM (you, when running this skill) through the *judgment-laden* parts of an audit: things a regex can't decide. The skill also covers the workflow (when to scan, how to present findings, how to verify fixes) when the MCP is not available.

If the MCP is available in the calling client, **invoke it** rather than re-implementing its scans in chat. Then apply your judgment on top of its output.

If the MCP is NOT available, fall back to manually performing the audit using the rule families listed below as your checklist.

---

## Auditor / builder discipline (read first)

If you wrote (or are co-writing) the code being audited, you are a **biased auditor**. Specifically:

- You will tend to accept your own implementation choices as correct.
- You will tend to accept code comments like *"TODO: harden later"* or *"deferred to scope.md"* as severity downgrades. They are not. Severity is determined by the technical risk in the current code, not by intent.
- You will tend to miss problems in code you just convinced yourself was fine.

When running this skill from **Cowork (or any client other than the one that wrote the code)**, you are the independent auditor. Your job is to surface the issues the builder may have rationalized away. Read source files directly. Re-grade severity from scratch. Do not defer to the builder's framing.

When running this skill from **the same client that wrote the code** (e.g., Cursor running Sentinel on its own work), you must:

- Run the deterministic checks (those don't have judgment bias).
- For judgment-laden sections (auth coverage, ownership filtering, route-level access control, server-side validation, etc.), leave placeholders (`_(awaiting independent auditor)_`) rather than filling them in yourself.
- Do not assign PASS/FAIL/PARTIAL verdicts to your own fixes in Pass 3.

---

## When each pass runs

- **Pass 1** — on the first Sentinel invocation for a project session, or when the user asks for a new audit ("run Sentinel", "audit this project", "scan for issues"). Discovers candidate sensitive fields and waits for developer confirmation.
- **Pass 2** — after the developer confirms or dismisses Pass 1's discovery list. The full audit. Writes a dated report to `audits/`.
- **Pass 3** — when (a) the user says fixes are done ("fixes are in", "Cursor finished the HIGH items", "re-audit the changes", "verify Sentinel"), OR (b) Cursor reports fixes via a shared message/screenshot, OR (c) the user explicitly invokes verification. Pass 3 requires a prior audit report to exist in `audits/`. If none exists, fall back to Pass 1/2.

---

## Pass 1 — sensitive field discovery

**If the MCP is available:** call `sentinel_pass1_discover(project_path)`. The tool walks the codebase and returns a JSON structure of candidate sensitive fields grouped by category (PII, CREDENTIAL, FINANCIAL, HEALTH, IDENTIFIER), plus any fields already declared in `project-context.md` → `SENSITIVE_FIELDS`.

**First-time setup detection.** If the Pass 1 response contains `"first_time_setup_recommended": true`, the project has not been initialized for Sentinel (no `project-context.md`, no `audits/` folder). Before showing the Pass 1 results, ask the user:

> This project hasn't been set up for Sentinel yet. Want me to initialize it? That creates `project-context.md` (a template you'll fill in), an `audits/` folder, and (in Cursor) checkpoint rules. Or would you prefer to run a minimal audit now without project-specific context?

- If yes → call `sentinel_init` with the args from the response's `suggested_init_call`. Tell the user to edit `project-context.md` (specifically: SENSITIVE_FIELDS, USER_ROLES, COMPLIANCE_REQUIREMENTS, HIGH_RISK_FEATURES). After they confirm edits are done, re-run `sentinel_pass1_discover`.
- If they want minimal audit anyway → proceed with Pass 1 results as returned. Project-specific checks will be skipped; deterministic layer still runs.

**If the MCP is not available:** walk source files (skip node_modules, .git, .next, dist, build, .expo, Pods, .venv, __pycache__, coverage, audits) and look for variable/field/schema/form-input names matching common sensitive patterns: email, name, phone, address, dob, ssn, password, token, secret, api_key, jwt, credit_card, account_number, medical, diagnosis, prescription, etc.

**Then present to developer:**

```
SENSITIVE FIELD DISCOVERY — [Project Name]
I found the following fields and data that might be sensitive. Please tell me
which ones actually are, and why.

POSSIBLY SENSITIVE (confirm or dismiss each):
- [field/variable name]: [where I found it] — [what it appears to store]
- ...

I will wait for your response before running the full security audit.
```

**If `project-context.md` already declares SENSITIVE_FIELDS**, those are pre-confirmed — do NOT re-ask the developer to confirm those. Only ask about candidates not already in the declared list.

---

## Pass 2 — full audit

**If the MCP is available:** call `sentinel_pass2_audit(project_path, confirmed_fields, trigger_label, audits_dir)`. The tool:

- Loads `project-context.md` automatically (auto-merges declared SENSITIVE_FIELDS).
- Computes a project fingerprint (path + project-context hash).
- Captures git state (HEAD, branch, dirty/clean).
- Runs **all deterministic check families** (see "What the MCP catches deterministically" below).
- Detects **carry-over** by reading prior fingerprint-matched reports from audits_dir.
- Gathers **judgment-layer context**: API routes, DB query sites, upload sites, form handlers.
- Writes a dated markdown report to `audits_dir/YYYY-MM-DD-{trigger_label}.md`.

**Then you (the LLM running this skill):**

1. **Read the report file the MCP wrote.** Do not just look at the JSON response — read the markdown report on disk.
2. **Surface CRITICAL → HIGH → MEDIUM** deterministic findings to the user with their "Tell Cursor" instructions.
3. **Review carry-over entries** — confirm whether each is truly unresolved or a false-positive excerpt match.
4. **Apply judgment** to the "Pending Manual Review" section by reading the referenced files (API route handler heads, DB query call sites, upload sites, form handlers). For each, decide whether the judgment-laden questions are satisfied. Append findings under the appropriate severity heading.
5. **Independently re-audit** the deterministic findings if you are the independent auditor (not the builder). Read the source code for the highest-severity items and verify the MCP's grading isn't undercounted (e.g., a HIGH that's actually CRITICAL given the business context).
6. **Update the report file** with your judgment additions. Use clear sub-section headers (e.g., `## HIGH ISSUES (judgment — Cowork independent review)`) so future readers can tell what came from deterministic scan vs. LLM judgment.
7. **Update the "SUGGESTED AUDIT HISTORY ENTRY"** with final findings counts.

**If the MCP is not available:** perform the audit manually by running the rule families listed below against the codebase. Report in the same format the MCP would produce (see "Report format" section).

---

## Pass 2 — what the MCP catches deterministically

If the MCP is running, these rule families execute automatically. If you are running this skill manually (no MCP), use these as your checklist:

### Secrets / credentials (OWASP Mobile M1, OWASP A2)
- Hardcoded provider-pattern secrets (AWS, GCP, Stripe, GitHub, Slack, Twilio, etc.)
- Hardcoded generic credentials (API keys, passwords, tokens)
- `.env`, `.env.local`, `.env.production` listed in `.gitignore`
- Default/admin/test passwords (`"admin"`, `"password"`, `"123456"`, etc.) in non-test files
- Secrets in `*.plist`, `*.xml`, `*.json`, `*.yml`, `*.yaml`, `app.json`, `eas.json`

### Injection sinks (OWASP Mobile M4, OWASP A3)
- `dangerouslySetInnerHTML` use
- `eval`, `new Function`, `setTimeout`/`setInterval` with string args
- WebView `injectedJavaScript` and `source={{ html: ... }}`
- WebView `originWhitelist={['*']}`
- `child_process.exec/spawn` with template literals (likely user input)
- SQL queries built via string concatenation or template literal interpolation
- Path-traversal obvious in-line cases (`fs.readFile(req.params.X)`, `path.join(req.X, ...)`)
- Prototype pollution obvious cases (`Object.assign(target, req.body)`, lodash `merge`/`mergeWith`/`defaultsDeep`/`set` with request data)
- SSRF obvious cases (`fetch(req.body.url)`, `axios.get(req.params.url)`)
- Insecure deserialization (`JSON.parse(req.body)` without schema; Node `vm` module usage)

### Authentication / authorization (OWASP Mobile M3)
- `jwt.decode()` used instead of `jwt.verify()` (signature not checked)
- JWT verifier configured to accept the `none` algorithm
- (Judgment-only: auth check at top of each route handler; admin-only role verification; ownership filtering on DB queries — surfaced as gathered context)

### Communication / network (OWASP Mobile M5)
- Hardcoded `http://` URLs (non-localhost)
- TLS bypass: `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `trustAllCerts`, `TrustManager.acceptAllIssuers`, `setHostnameVerifier(ALLOW_ALL)`
- iOS `NSAllowsArbitraryLoads` (ATS disabled)
- Android `android:usesCleartextTraffic="true"`
- CORS wildcard origin (`Access-Control-Allow-Origin: *`)

### Privacy / data exposure (OWASP Mobile M6, M9)
- Sensitive fields in `console.log/warn/error/info/debug/trace`
- Sensitive fields in URL strings (route definitions or query params)
- AsyncStorage usage of fields requiring SecureStore/Keychain (per project-context)
- Sensitive fields in analytics/error-reporter calls (PostHog, Sentry, Amplitude, Mixpanel, Firebase Analytics) — per project-context
- Dangerous iOS permissions requested (camera, microphone, location, contacts, photos, calendar, motion, health, Face ID, Bluetooth, speech, user tracking)
- Dangerous Android permissions requested (camera, mic, location, contacts, storage, SMS, sensors, calendar, Bluetooth, notifications, system alerts)
- Screen-capture protection absence when sensitive fields are declared

### Cryptography (OWASP Mobile M10)
- Weak hash algorithms (MD5, SHA1) in crypto contexts
- `Math.random()` used in security-material contexts (token, password, secret, key, nonce, salt)
- bcrypt rounds < 10 (CRITICAL) or 10-11 (HIGH)
- PBKDF2 iterations < 100,000
- Hardcoded initialization vectors (IVs)
- Hardcoded symmetric encryption keys

### Code quality
- Files > 200 lines (refactor candidates)
- TypeScript `any` overuse (threshold: 5+ per file)

### Misconfiguration (OWASP Mobile M8)
- Hardcoded localhost URLs in shipped code
- `debug: true` flags not gated by `__DEV__`

### Supply chain (OWASP Mobile M2)
- Missing lockfile (`package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` / `bun.lockb`)
- `npm audit` vulnerabilities (one finding per vulnerable package, severity mapped from npm's grading)

### Cross-cutting
- CSRF middleware absence when state-changing HTTP routes exist (cookie-auth projects)

---

## Pass 2 — what requires LLM judgment (the MCP CANNOT decide)

For these, the MCP gathers context and surfaces it; you (running this skill) make the call.

### Authorization correctness
- For each API route the MCP listed: is there an auth/session check at the top of the handler? Is admin-only routing verifying user role (not just login)?
- For each DB query site the MCP listed: is the query filtered by the current user's ID (ownership)? Does the handler accept a user ID from request body/URL without verifying it matches the session?
- For each upload endpoint the MCP listed: server-side MIME type and size validation?
- For each form handler the MCP listed: client-side schema validation present? Server-side validation on submit? Input sanitization before render or storage? No dangerous sink for unsanitized input? Rate limiting/captcha on public-facing forms?

### Data exposure breadth
- For each API response shape: does it return fields the user shouldn't see?
- For each error/log payload: does it embed sensitive data through serialization (e.g., logging a whole user object that includes email and tokens)?

### Project-context items not statically verifiable
- For each COMPLIANCE_REQUIREMENT in project-context.md: does the implementation exist? (Surface as items requiring manual confirmation.)
- For each HIGH_RISK_FEATURE in project-context.md: apply extra scrutiny when scanning related files; flag any gaps.
- USER_ROLES: confirm route-level access control matches the permissions described.

### Things the deferral list says we don't deterministically check
- Multi-file data flow (non-inline cases of path traversal, prototype pollution, SSRF)
- Authorization logic correctness (which role for which route)
- Privacy policy / compliance document review
- ReDoS detection (regex AST analysis)
- Race conditions / TOCTOU
- Binary protections (build-artifact, not source)
- Auth-bypass TODO comments (too noisy without smart context)
- `__DEV__`-gated production leaks (pattern needs careful design)

For any of the above, if you find a real issue during manual review, add it as a judgment-layer finding under the appropriate severity heading.

---

## Pass 2 — report format

The MCP writes this format automatically. If you're running manually, mirror it:

```markdown
# CODE SLOP & SECURITY AUDIT REPORT

- **Project:** [name]
- **Project path:** [absolute path]
- **Project fingerprint:** [hash — leave blank if running manually]
- **Scanned:** [ISO timestamp]
- **Trigger:** [trigger label]
- **Git HEAD:** [short hash] (branch: [branch]) · [clean/dirty]
- **Sensitive fields audited:** [comma-separated list]
- **Files scanned:** [count]
- **project-context.md:** [loaded / not found]
- **Generated by:** Sentinel skill (manual) / Sentinel MCP

---

## Summary
- CRITICAL: N
- HIGH: N
- MEDIUM: N
- Carry-over from prior audits: N
- Awaiting LLM judgment: N

---

## CARRY-OVER FROM PRIOR AUDITS
[findings from prior reports whose excerpt is still present in current code]

## CRITICAL ISSUES
### [Title]
- **File:** `[path]` (line N)
- **Rule:** `[rule_id]`
- **Excerpt:** `[code line]`
- **Tell Cursor:** [exact instruction]

## HIGH ISSUES
[same shape]

## MEDIUM ISSUES
[same shape]

---

## PENDING MANUAL REVIEW
[API routes / DB queries / uploads / form handlers gathered by MCP for judgment]

---

## PASSED CHECKS (deterministic)
[everything that ran clean]

---

## PROJECT-CONTEXT REMINDERS
### USER_ROLES
### COMPLIANCE_REQUIREMENTS
### HIGH_RISK_FEATURES

---

## SUGGESTED AUDIT HISTORY ENTRY for project-context.md
| YYYY-MM-DD | [trigger] | N Critical · N High · N Medium | [status] |
```

**File naming:** `audits/YYYY-MM-DD-[trigger].md`. If a file with that name already exists, suffix `-v2`, `-v3`, etc.

---

## Pass 3 — fix verification

**If the MCP is available:** call `sentinel_pass3_verify(project_path, report_path, claimed_fixes, audits_dir)`. The tool:

- Validates the project fingerprint matches the source report's fingerprint (refuses to verify across mismatched projects).
- Parses the prior report into structured findings.
- Collects deterministic evidence per finding (file existence, original excerpt still present, rule-specific re-checks for file size / `any` count / `.gitignore` re-check / hardcoded literal grep / `npm audit` re-run for supply-chain findings).
- Runs a regression scan: for each prior finding with a recoverable pattern, re-grep the entire codebase to detect whether the original anti-pattern reappeared elsewhere.
- Writes a draft verification report to `audits_dir/YYYY-MM-DD-verification-{trigger}.md` with deterministic evidence pre-filled and verdict lines waiting for your assignment.

**Then you (the LLM running this skill):**

1. **Read the verification report file** the MCP wrote.
2. For each finding, **assign a final verdict**: PASS / FAIL / PARTIAL with a one-line justification grounded in the deterministic evidence.
   - PASS — every claim is supported by filesystem/git evidence; artifact matches (or exceeds) the spec in the original "Tell Cursor".
   - FAIL — the claim is not supported, artifact missing, or the fix introduced a new problem.
   - PARTIAL — partially supported; artifact exists but missing a component; defensible deviation worth documenting; documentation-only fix for what needed code; etc.
3. **Always name what was NOT verified.** Static inspection cannot confirm runtime behavior (whether an iOS entitlement lands in the built `.ipa`, whether a deep link actually routes on a real device, whether a Supabase dashboard setting is correct, whether a network request succeeds against the real backend). For every PASS with runtime implications, include a "Runtime verification I could not perform" note with the specific check the user/Cursor needs to do manually.
4. **If the regression scan flagged anything**, treat those as new CRITICAL/HIGH findings that reset the audit cycle. Document and propose immediate fix.
5. **Update the AUDIT HISTORY table** in `project-context.md` with the verification outcome.

**If the MCP is not available:** for each prior finding, manually verify using filesystem reads, `git log`, `git show`, grep across the codebase, and (where applicable) running build/test scripts (`tsc --noEmit`, `npm run lint`, the project's test command).

**Pass 3 — what you must not do:**

- Do not assign PASS to fixes you yourself made.
- Do not run a fresh Pass 2 full audit after verification. Pass 2 fires only on new Sentinel checkpoints; verification is narrow by design.
- Do not auto-extend scope. If the user said "verify the 4 HIGH items", verify only those — but always run the regression scan across all prior findings, since regressions can appear anywhere.

**Pass 3 — file naming:** `audits/YYYY-MM-DD-verification-[trigger].md` where `[trigger]` is the same trigger as the audit being verified (e.g., `2026-04-24-verification-baseline.md`). Multiple verifications same day → suffix `-v2`, `-v3`.

**Pass 3 — post-verification:**
- All PASS → update AUDIT HISTORY in `project-context.md`; offer to remove "pending" status.
- Any FAIL → restate failed findings with fresh "Tell Cursor" instructions; do not suggest new features until failures are re-fixed.
- Any PARTIAL → surface the specific deviation and ask the user whether to accept-and-document or require a proper fix.

---

## project-context.md integration

Each project should have a `project-context.md` at its root declaring:

- **SENSITIVE_FIELDS** — bullets in form: `` `qualified.field_name` — category — rules `` (e.g., "never logged, never in URL", "SecureStore only", "scrub from breadcrumbs"). The MCP auto-loads these.
- **USER_ROLES** — list of roles + what each can do.
- **COMPLIANCE_REQUIREMENTS** — GDPR, HIPAA, App Store Privacy Labels, etc.
- **HIGH_RISK_FEATURES** — auth flows, payment processing, storage of credentials, deep links, WebViews, sensitive data flows.
- **AUDIT HISTORY** — table tracking each audit's date, trigger, findings counts, and status.

If a project does NOT have `project-context.md`, perform a minimal version: scan only the fixed-layer checks; surface a recommendation to create one before the next audit.

---

## Project isolation (when running with MCP)

The MCP embeds a project fingerprint in every report. Pass 3 refuses to verify against a report whose fingerprint doesn't match the current project. Carry-over scans also refuse to mix reports across fingerprints. This prevents accidental cross-project audit contamination.

If you're running this skill manually (no MCP) across multiple projects, you are responsible for not mixing report histories across projects. Always confirm you are operating on the right project's `audits/` folder.

---

## Auditor/builder separation when both are LLMs

When this skill runs in Cowork while a separate client (Cursor, Claude Code, etc.) writes the project's code:

- The file system is the bridge. Reports written by the MCP to `audits/` are visible to both clients on disk.
- No copy-paste between clients is necessary. Tell the user the report path; the other client can read it directly.
- Each client maintains its discipline: the building client leaves judgment placeholders; the auditing client (Cowork via this skill) fills them in.

When this skill runs in the SAME client that's writing code (e.g., Cursor running Sentinel on its own work), the discipline section at the top applies — Cursor must leave judgment placeholders for an independent auditor to fill in.

---

## Tone and reporting

- Be direct. State severity plainly.
- Do not sandbag findings to spare feelings.
- Do not let developer comments (`// TODO`, `// deferred`, `// known issue`) downgrade severity. Severity is technical risk in current code.
- Frame "Tell Cursor" instructions as concrete, executable steps — not high-level advice.
- When in doubt about severity, err high. The user can downgrade explicitly with reasoning if needed.
