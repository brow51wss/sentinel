# Sentinel MCP

A local security and code-quality auditor for TypeScript / JavaScript / React Native / Expo projects, exposed as a [Model Context Protocol](https://modelcontextprotocol.io/) server.

Sentinel runs on your machine, scans your code with deterministic checks (regex, AST, subprocess), and produces structured audit reports. The LLM client that calls it (Cursor, Claude Desktop, Cowork, Claude Code) handles the judgment-laden parts: ambiguous severity grading, multi-file flow questions, business-logic correctness.

**It is not a replacement for human security review.** It is a fast, consistent first pass that catches the patterns regex can catch — leaving the judgment work for humans and LLMs.

---

## What it catches

Sentinel maps to the [OWASP Mobile Top 10 2024](https://owasp.org/www-project-mobile-top-10/) and the OWASP ASVS / API Top 10 for general web/backend code. ~50+ deterministic rule IDs across:

- **Secrets / credentials** — hardcoded API keys (AWS, Stripe, Google, GitHub, Slack, JWT, generic patterns), `.env` files not gitignored, default passwords in source, secrets in `*.plist` / `*.xml` / `app.json` / `eas.json`
- **Injection sinks** — `dangerouslySetInnerHTML`, `eval` family, WebView injection (`injectedJavaScript`, `source={{ html }}`, wildcard `originWhitelist`), command injection, SQL concat / template literals, path traversal (obvious cases), prototype pollution (obvious cases), SSRF (obvious cases), unsafe deserialization
- **Authentication / authorization** — `jwt.decode()` without verify, JWT `none` algorithm acceptance
- **Communication / transport** — hardcoded `http://`, TLS bypass patterns (`rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, trust-all-certs), iOS `NSAllowsArbitraryLoads`, Android `usesCleartextTraffic`, wildcard CORS
- **Cryptography** — MD5/SHA1 in crypto contexts, `Math.random()` for security material, weak bcrypt rounds (<10), low PBKDF2 iterations, hardcoded IVs, hardcoded encryption keys
- **Privacy** — sensitive fields in `console.log` / analytics / error reporters (project-context driven), dangerous iOS / Android permissions, screen-capture protection absence
- **Storage** — AsyncStorage usage of fields requiring SecureStore / Keychain (project-context driven)
- **Supply chain** — missing lockfile, `npm audit` integration (one finding per vulnerable package)
- **Misconfiguration** — hardcoded localhost in shipped code, ungated `debug: true` flags, CSRF middleware absence on state-changing routes
- **Code quality** — files > 200 lines, TypeScript `any` overuse

For the full rule list, see [docs/coverage.md](docs/coverage.md) (or read `sentinel_mcp.py` directly — every pattern is documented inline).

---

## Quickstart

Five minutes from clone to first audit.

```bash
# 1. Clone
git clone https://github.com/brow51wss/sentinel.git
cd sentinel

# 2. Install
./install.sh
# (Or manually: python3 -m venv .venv && source .venv/bin/activate && pip install "mcp[cli]")

# 3. Verify it loads
.venv/bin/python -c "import sentinel_mcp; print('OK')"
```

Then register it with your MCP client. For **Cursor**, edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "/absolute/path/to/sentinel/.venv/bin/python",
      "args": ["/absolute/path/to/sentinel/sentinel_mcp.py"]
    }
  }
}
```

Restart Cursor (Cmd+Q then reopen). Then in any Cursor Agent chat, say:

> Use the sentinel_pass1_discover tool on `/path/to/my/project`.

If this is your first time auditing this project, Sentinel will detect that and offer to initialize the project — creating `project-context.md` (a template you fill in), an `audits/` folder, and Cursor checkpoint rules.

---

## Requirements

- **Python 3.10 or higher** (uses modern type hints). On macOS run `python3 --version`; if it's below 3.10, install via Homebrew: `brew install python@3.12`.
- **An MCP-compatible client**:
  - [Cursor](https://www.cursor.com/) (recommended — has agent mode and rules support)
  - [Claude Desktop](https://claude.ai/download)
  - Cowork (Anthropic's desktop research preview)
  - [Claude Code](https://claude.com/claude-code) (CLI)
- **(Optional) `npm`** — only needed for the supply-chain CVE scan. If absent, Sentinel surfaces a "npm not available" finding and skips that one check; everything else still runs.

---

## Installation

### Option A — install script (recommended)

```bash
git clone https://github.com/brow51wss/sentinel.git
cd sentinel
./install.sh
```

The script creates a Python virtual environment in `.venv/` and installs the `mcp[cli]` package. Re-run it any time you want to refresh.

### Option B — manual

```bash
git clone https://github.com/brow51wss/sentinel.git
cd sentinel
python3 -m venv .venv
source .venv/bin/activate
pip install "mcp[cli]"
```

### Option C — install without git

Download the [latest release](https://github.com/brow51wss/sentinel/releases) as a zip, unzip, then run `./install.sh` (or the manual steps above).

---

## Configuration

### Cursor

Edit `~/.cursor/mcp.json` (create the file if it doesn't exist):

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "/absolute/path/to/sentinel/.venv/bin/python",
      "args": ["/absolute/path/to/sentinel/sentinel_mcp.py"]
    }
  }
}
```

Replace `/absolute/path/to/sentinel` with your actual install path. Fully quit Cursor (Cmd+Q) and reopen — Cursor reads `mcp.json` only at startup.

Verify it loaded: **Settings → MCP**. You should see `sentinel` listed with a green dot and four tools (`sentinel_init`, `sentinel_pass1_discover`, `sentinel_pass2_audit`, `sentinel_pass3_verify`).

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent on your platform. Use the same `mcpServers` block as Cursor. Restart Claude Desktop.

### Cowork

Cowork auto-discovers local MCP servers under the same configuration. Use the same JSON snippet as Cursor in whatever location your Cowork instance reads. (Cowork is a research preview; configuration details may change.)

---

## Usage

### First-time setup on a new project

Just say:

> Run Sentinel on `/path/to/my-project`.

Sentinel will detect that the project has no `project-context.md` and offer to initialize it. Say yes. It creates:

- `project-context.md` at the project root — template you fill in
- `audits/` folder — where reports land
- `.cursor/rules/sentinel-checkpoints.mdc` — Cursor rules that prompt for audits at security-relevant moments

Open `project-context.md` and fill in the four sections (SENSITIVE_FIELDS, USER_ROLES, COMPLIANCE_REQUIREMENTS, HIGH_RISK_FEATURES). The file has examples for each. See [examples/project-context.md.example](examples/project-context.md.example) for a filled-in version.

Once the file is filled in, run Sentinel again. The audit will now include project-specific checks.

### Run a security audit

> Run Sentinel.

Or more explicitly:

> Use the sentinel_pass2_audit tool with project_path=`/path/to/project`, trigger_label=`auth-touched`.

The tool runs all deterministic checks plus gathers context for judgment-laden checks. It writes a dated markdown report to `audits/YYYY-MM-DD-{trigger}.md`. The LLM client then reads the report and either surfaces deterministic findings to you or applies judgment to the "Pending Manual Review" section, depending on which client is running.

Recommended trigger labels:

| Trigger | When to use |
|---|---|
| `baseline` | First audit on a fresh project |
| `auth-touched` | After login / signup / password reset / OAuth changes |
| `secrets-touched` | After env vars / API keys / signing config changes |
| `networking-touched` | After API client / TLS / WebSocket changes |
| `storage-touched` | After Keychain / SecureStore / AsyncStorage / DB changes |
| `permissions-touched` | After Info.plist or AndroidManifest permission additions |
| `deeplink-touched` | After URL scheme / Universal Link changes |
| `webview-touched` | After WebView introduced or modified |
| `sdk-added` | After a new third-party SDK added |
| `pre-push` | Before pushing to a remote |
| `pre-release` | Before TestFlight / Play Console / store submission |
| `weekly-cadence` | Routine weekly check |
| `ad-hoc` | Anything else |

### Verify fixes

After you (or Cursor) claim findings are fixed:

> Verify the Sentinel fixes.

This runs `sentinel_pass3_verify` against the most recent audit report, collects deterministic evidence per finding (file existence, original excerpt presence, file-size re-check, `any` count re-check, hardcoded literal grep across the codebase, npm audit re-run for supply-chain findings), runs a regression scan, and writes a verification report. The LLM client then assigns PASS / FAIL / PARTIAL verdicts.

---

## Architecture — hybrid context-gatherer

Sentinel deliberately does NOT try to encode every audit decision in Python. Instead:

- **Python (this server)** runs the deterministic checks — patterns that don't require judgment. It also walks the codebase and *gathers context* for judgment-laden checks: API route file heads, DB query call sites, upload sites, form handlers. It writes these into the report under "Pending Manual Review."
- **The calling LLM** (Cursor's Claude, Cowork's Claude, etc.) applies judgment to the gathered context and edits the report file with its findings. It also assigns PASS / FAIL / PARTIAL verdicts in Pass 3.

This separation has two consequences:

1. **Sentinel is fast and consistent on the deterministic checks** — same input always produces the same output, no token cost, no API key needed.
2. **Audit quality on judgment-laden questions depends on the LLM** running it. A more capable LLM with better instructions produces a better audit. The file format (markdown report on disk) means any LLM can read prior audits to maintain continuity.

### Auditor/builder discipline

A subtle but important rule: when the LLM auditing the code is the *same* LLM that wrote the code, it tends to accept its own implementation choices as correct. To prevent this, the Cursor rules (`sentinel-checkpoints.mdc`) instruct Cursor's Claude to:

- Run deterministic checks (no bias risk there)
- For judgment-laden sections, leave `_(awaiting independent auditor)_` placeholders rather than filling them in
- Not assign PASS / FAIL / PARTIAL verdicts on its own fixes in Pass 3

The "independent auditor" is meant to be a separate LLM context (e.g., Cowork) that reads the report file from disk and applies independent judgment. The report on disk is the bridge between the two clients — no copy-paste required.

---

## What Sentinel does NOT check (honest limitations)

**Structural limits — no static source scanner can do these:**

- **Authorization correctness** — "does this admin route check the right role?" requires understanding intent.
- **Binary protections** (OWASP M7) — anti-tamper, obfuscation, root/jailbreak detection. Build-time concerns, source can't verify.
- **Race conditions / TOCTOU** — concurrent-execution bugs need runtime analysis.
- **Multi-file data flow** — path traversal, prototype pollution, SSRF *beyond* in-line obvious cases require following data across many files. Sentinel catches the obvious cases (`fs.readFile(req.body.path)`); it can't catch the subtle ones.
- **ReDoS** — catastrophic regex backtracking detection requires regex AST analysis.
- **Privacy policy / compliance documents** — written content, not code.

**Engineering — could be added with careful design:**

- Auth-bypass `TODO` markers (too noisy without smart context awareness)
- `__DEV__`-gated production leaks
- `tsc --noEmit` and test-script integration in Pass 3

If you spot a gap in coverage, **file an issue** or send a PR adding the pattern to the appropriate list (`INJECTION_PATTERNS`, `MISCONFIG_PATTERNS`, etc.).

---

## project-context.md

Each project should have a `project-context.md` at its root declaring:

- **SENSITIVE_FIELDS** — fields containing sensitive data and the rules governing them (e.g., "never logged", "SecureStore only")
- **USER_ROLES** — what roles exist and what each can access
- **COMPLIANCE_REQUIREMENTS** — GDPR, HIPAA, PCI-DSS, App Store Privacy Labels, etc.
- **HIGH_RISK_FEATURES** — auth flow, payments, file uploads, WebViews, etc.

Sentinel auto-loads this file when it scans. Declared SENSITIVE_FIELDS automatically merge into `confirmed_fields`; declared rules drive project-specific checks (e.g., "session_token requires SecureStore" → Sentinel scans for AsyncStorage misuse of `session_token`).

See [examples/project-context.md.example](examples/project-context.md.example) for a filled-in version.

`sentinel_init` creates this file as a template — you fill in the project-specific values.

---

## Reports

Reports are markdown files written to `audits/` (or a user-specified `audits_dir`). Each report contains:

- **Header** — project name, fingerprint, timestamp, trigger, git HEAD + branch + dirty status, sensitive fields audited, files scanned
- **Summary** — counts by severity
- **Carry-over from prior audits** — findings flagged in earlier reports that are still present in current code
- **CRITICAL / HIGH / MEDIUM ISSUES** — deterministic findings with file, line, excerpt, "Tell Cursor" instruction
- **Pending Manual Review** — judgment-laden items (API routes, DB queries, upload sites, form handlers) with judgment prompts
- **Passed Checks** — every deterministic check that ran clean
- **Project-context reminders** — declared USER_ROLES, COMPLIANCE_REQUIREMENTS, HIGH_RISK_FEATURES
- **Suggested AUDIT HISTORY entry** — line to append to project-context.md

Verification reports are written to `audits/YYYY-MM-DD-verification-{trigger}.md` after Pass 3 runs.

### Project fingerprint

Every report embeds a fingerprint (sha256 of resolved project path + first 200 chars of `project-context.md`). Pass 3 refuses to verify against a report whose fingerprint doesn't match the current project. This prevents accidental cross-project audit contamination.

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'mcp'`**
You're outside the virtual environment. Run `source .venv/bin/activate` first, or use the full path: `.venv/bin/python -c "import sentinel_mcp; print('OK')"`.

**Cursor shows `sentinel` in MCP settings but tools never fire**
You're in Ask mode instead of Agent mode. Switch to Agent mode (dropdown at the top of Cursor's chat). MCP tools only execute in Agent mode.

**`sentinel` doesn't appear in Cursor's MCP settings**
Fully quit Cursor (Cmd+Q on macOS — closing the window isn't enough). Cursor reads `~/.cursor/mcp.json` only at startup. Reopen and check again.

**`npm audit` errors in report output**
You don't have npm installed, or the project has no `package.json`. Sentinel surfaces this as a "npm not available" finding and continues with all other checks. Install Node.js / npm if you want supply-chain CVE scanning.

**`Python 3.12.1` shown but tools error with "type hint" failures**
The Python version is fine. Check that you installed `mcp[cli]` (not bare `mcp`) — the `[cli]` extra is required for FastMCP.

**Reports going to the wrong folder**
Pass `audits_dir=/absolute/path/to/audits` when calling `sentinel_pass2_audit` or `sentinel_pass3_verify`. Default is `{project_path}/audits/`.

**Tool runs but reports are empty / report shows 0 files scanned**
Wrong `project_path` argument — pass the absolute path to the project's source folder (not the parent folder). Sentinel skips `node_modules`, `.git`, `.next`, `dist`, `build`, `.expo`, `Pods`, `__pycache__`, `coverage`, `audits` automatically.

---

## Contributing

To add a new check:

1. Open `sentinel_mcp.py`.
2. Decide which category the check fits into. Most checks fit one of the existing pattern lists:
   - `SECRET_PATTERNS` — high-confidence credential detection
   - `SENSITIVE_PATTERNS` — candidate fields for Pass 1 discovery
   - `INJECTION_PATTERNS` — injection sinks, unsafe APIs, cert-validation bypass, JWT decode/none, KDF strength, hardcoded crypto, deserialization, path traversal / prototype pollution / SSRF obvious cases, default credentials
   - `MISCONFIG_PATTERNS` — debug flags, transport configs, hardcoded localhost
   - `DANGEROUS_IOS_USAGE_KEYS` / `DANGEROUS_ANDROID_PERMISSIONS` — privacy/permissions
3. Add a tuple: `(regex, severity, rule_id, title_template, tell_cursor_template)`. Severity is one of `CRITICAL`, `HIGH`, `MEDIUM`. Rule IDs are dotted-namespace strings (e.g., `injection.eval`, `crypto.weak_algorithm`).
4. Add the rule ID to the Pass 3 evidence-collection list and the regression-scan list so it's verified properly when fixes are claimed.
5. Add a test case to the project being scanned (see `examples/` for fixture suggestions).
6. Open a PR.

For new check *categories* (not just new patterns), add a new check function (e.g., `_check_my_category`), wire it into `sentinel_pass2_audit`, and add a passed-message string for the case where the check runs clean.

---

## License

MIT. See [LICENSE](LICENSE).

---

## Acknowledgments

Sentinel's check coverage is informed by:

- [OWASP Mobile Top 10 2024](https://owasp.org/www-project-mobile-top-10/)
- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)
- [React Native Security Guide](https://reactnative.dev/docs/security)
- [Semgrep React ruleset](https://semgrep.dev/p/react)
- [RNSec — React Native security scanner](https://www.rnsec.dev/)

Built on the [Model Context Protocol](https://modelcontextprotocol.io/) and the [`mcp[cli]`](https://github.com/modelcontextprotocol/python-sdk) Python SDK.
