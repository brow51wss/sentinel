"""
Sentinel MCP Server
Local code-audit MCP server. Exposes Sentinel's three audit passes as MCP tools
for use from any MCP-compatible client (Cursor, Cowork, Claude Desktop).

Architecture: Hybrid context-gatherer (Option C).
  - Python walks the codebase, runs deterministic regex/AST checks, and produces
    structured findings.
  - The calling LLM (Cursor's Claude or Cowork's Claude) applies final judgment
    on context-laden questions (auth coverage, access control, etc.) and may
    edit the report file with additional findings.

Tools:
  - sentinel_pass1_discover: scan for candidate sensitive fields    (LIVE)
  - sentinel_pass2_audit:    run the full audit and write report   (LIVE)
  - sentinel_pass3_verify:   verify claimed fixes                  (LIVE)
"""

from mcp.server.fastmcp import FastMCP
from pathlib import Path
from datetime import datetime
import re
import json
import hashlib
import subprocess

mcp = FastMCP("sentinel")

# ====================================================================
# Shared constants — file walking
# ====================================================================

SCAN_EXTENSIONS = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".py",
    ".swift", ".kt", ".java",
    ".dart",
    ".go", ".rs",
    ".rb",
    ".php",
    ".sql",
    ".prisma",
    ".graphql", ".gql",
}

SKIP_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", ".turbo",
    ".expo", ".expo-shared", "Pods",
    ".venv", "venv", "__pycache__", ".pytest_cache",
    "coverage", ".nyc_output", ".cache",
    "audits",  # Sentinel's own outputs.
}


def _walk_source_files(root: Path):
    """Yield every source file under root, skipping ignored folders and non-source extensions."""
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        yield path


# ====================================================================
# Project context loading (project-context.md)
# ====================================================================

def _load_project_context(project_path: Path):
    """Look for project-context.md at project_path/project-context.md and parse it.
    Returns a dict with sensitive_fields, user_roles, compliance, high_risk, raw_text,
    and source_path. Returns empty defaults when the file is missing.

    Format expected (loose markdown):

        ## SENSITIVE_FIELDS
        - `users.email` — GDPR/PII — never logged, never in URL
        - ...

        ## USER_ROLES
        - `user` — default
        - ...

        ## COMPLIANCE_REQUIREMENTS
        - GDPR — ...
        - ...

        ## HIGH_RISK_FEATURES
        - Auth flow — ...
        - ...
    """
    context_file = project_path / "project-context.md"
    empty = {
        "found": False,
        "source_path": str(context_file),
        "sensitive_fields": [],
        "user_roles": [],
        "compliance": [],
        "high_risk": [],
        "raw_text": "",
    }
    if not context_file.exists() or not context_file.is_file():
        return empty

    try:
        text = context_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return empty

    sections = {"SENSITIVE_FIELDS": [], "USER_ROLES": [], "COMPLIANCE_REQUIREMENTS": [], "HIGH_RISK_FEATURES": []}
    current = None
    for line in text.splitlines():
        m = re.match(r"^##\s+(\w+)\b", line)
        if m:
            heading = m.group(1).upper()
            current = heading if heading in sections else None
            continue
        if current and line.strip().startswith("- "):
            sections[current].append(line.strip()[2:].strip())

    # For SENSITIVE_FIELDS, parse out the field token (in backticks) and the rules text.
    parsed_fields = []
    for raw in sections["SENSITIVE_FIELDS"]:
        token_match = re.match(r"`([^`]+)`\s*[—-]?\s*(.*)$", raw)
        if token_match:
            field = token_match.group(1).strip()
            rules = token_match.group(2).strip()
        else:
            field = raw.split("—")[0].strip().strip("`")
            rules = raw[len(field):].strip(" —-`")
        parsed_fields.append({"raw": raw, "field": field, "rules": rules})

    return {
        "found": True,
        "source_path": str(context_file),
        "sensitive_fields": parsed_fields,
        "user_roles": sections["USER_ROLES"],
        "compliance": sections["COMPLIANCE_REQUIREMENTS"],
        "high_risk": sections["HIGH_RISK_FEATURES"],
        "raw_text": text,
    }


def _sensitive_field_short_names(parsed_fields):
    """From parsed sensitive_fields, extract short tokens for use in regex.
    Drops dotted prefixes (users.email → email)."""
    names = set()
    for entry in parsed_fields:
        token = entry["field"]
        # Drop prefix (e.g., users.email → email; supabase.session_token → session_token)
        leaf = token.split(".")[-1]
        names.add(leaf)
        # Add the snake-cased version too if camelCase
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", leaf).lower()
        names.add(snake)
    return sorted(names)


# ====================================================================
# Git state capture
# ====================================================================

def _capture_git_state(project_path: Path):
    """Run `git rev-parse HEAD`, branch lookup, and a porcelain status check.
    Returns dict with head, short, branch, dirty, untracked, error.
    Returns {error: ...} if git isn't available or path isn't a repo.
    """
    state = {"head": None, "short": None, "branch": None, "dirty": None, "untracked_count": None, "error": None}

    def _run(args):
        return subprocess.run(args, cwd=str(project_path), capture_output=True, text=True, timeout=10)

    try:
        head = _run(["git", "rev-parse", "HEAD"])
        if head.returncode != 0:
            state["error"] = head.stderr.strip() or "git rev-parse HEAD failed"
            return state
        state["head"] = head.stdout.strip()
        state["short"] = state["head"][:8]

        branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
        if branch.returncode == 0:
            state["branch"] = branch.stdout.strip()

        status = _run(["git", "status", "--porcelain"])
        if status.returncode == 0:
            lines = [l for l in status.stdout.splitlines() if l.strip()]
            state["dirty"] = len(lines) > 0
            state["untracked_count"] = sum(1 for l in lines if l.startswith("??"))
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
        state["error"] = str(e)

    return state


# ====================================================================
# Project fingerprint (isolation guarantee)
# ====================================================================

def _compute_project_fingerprint(project_path: Path, context: dict):
    """Stable identifier for a project. Built from:
        - Resolved absolute path
        - First 200 chars of project-context.md (if present) — so renaming a path
          to point at a different project is detected
    Returns short hash string.
    """
    h = hashlib.sha256()
    h.update(str(project_path.resolve()).encode("utf-8"))
    if context.get("found"):
        h.update(b"\x00")
        h.update(context["raw_text"][:200].encode("utf-8", errors="ignore"))
    return h.hexdigest()[:16]


def _extract_fingerprint_from_report(report_text: str):
    """Pull out the project fingerprint embedded in a Sentinel report's header.
    Returns string or None."""
    m = re.search(r"^\s*-\s*\*\*Project fingerprint:\*\*\s*`([0-9a-f]{8,})`", report_text, re.MULTILINE)
    return m.group(1) if m else None


# ====================================================================
# Pass 1 — sensitive-field discovery
# ====================================================================

SENSITIVE_PATTERNS = [
    (r"\b(email|e_?mail|email_?address)\b", "PII", "email address"),
    (r"\b(first_?name|last_?name|full_?name|display_?name|user_?name)\b", "PII", "personal name"),
    (r"\b(phone|mobile|telephone|phone_?number|tel)\b", "PII", "phone number"),
    (r"\b(street|address|address_?line|zip|zip_?code|postal|postal_?code)\b", "PII", "physical address"),
    (r"\b(dob|birth_?date|birth_?day|date_?of_?birth)\b", "PII", "date of birth"),
    (r"\b(ssn|social_?security|tax_?id|tin|sin)\b", "PII", "government identifier"),
    (r"\b(drivers?_?license|license_?number|passport|passport_?number)\b", "PII", "government ID document"),

    (r"\b(password|passwd|pwd|pass_?word)\b", "CREDENTIAL", "password"),
    (r"\b(secret|api_?key|access_?key|auth_?token|bearer)\b", "CREDENTIAL", "secret/key"),
    (r"\b(jwt|refresh_?token|session_?token|id_?token)\b", "CREDENTIAL", "auth token"),

    (r"\b(credit_?card|card_?number|cvv|cvc|cc_?num)\b", "FINANCIAL", "credit card data"),
    (r"\b(account_?number|routing_?number|iban|swift_?code)\b", "FINANCIAL", "bank account data"),

    (r"\b(diagnosis|prescription|medical_?record|patient_?id|insurance_?id)\b", "HEALTH", "medical/PHI"),

    (r"\b(user_?id|customer_?id|account_?id)\b", "IDENTIFIER", "user identifier (sensitivity depends on use)"),
]
_compiled_sensitive = [(re.compile(pat, re.IGNORECASE), cat, why) for pat, cat, why in SENSITIVE_PATTERNS]


def _scan_file_for_sensitive_fields(path: Path, root: Path):
    findings = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings
    for line_num, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith(("//", "#", "*", "/*", "<!--")):
            continue
        for pattern, category, why in _compiled_sensitive:
            match = pattern.search(line)
            if match:
                findings.append({
                    "field": match.group(0),
                    "category": category,
                    "why_possibly_sensitive": why,
                    "file": str(path.relative_to(root)),
                    "line": line_num,
                    "excerpt": stripped[:200],
                })
    return findings


def _dedupe_pass1_findings(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f["field"].lower(), f["file"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


@mcp.tool()
def sentinel_pass1_discover(project_path: str) -> str:
    """Discover candidate sensitive fields in the codebase. Returns JSON of fields
    awaiting developer confirmation before Pass 2 runs.

    Result groups candidates by category (PII, CREDENTIAL, FINANCIAL, HEALTH, IDENTIFIER)
    with file location and code excerpt for each. The calling LLM should present this
    to the developer and collect a confirmed list to feed into sentinel_pass2_audit.

    If a project-context.md exists with declared SENSITIVE_FIELDS, those are returned
    in the response so the calling LLM can default to them rather than re-asking the
    developer for fields already documented.
    """
    root = Path(project_path).expanduser().resolve()
    if not root.exists():
        return json.dumps({"error": f"Path does not exist: {root}"}, indent=2)
    if not root.is_dir():
        return json.dumps({"error": f"Path is not a directory: {root}"}, indent=2)

    context = _load_project_context(root)

    all_findings = []
    files_scanned = 0
    for file_path in _walk_source_files(root):
        files_scanned += 1
        all_findings.extend(_scan_file_for_sensitive_fields(file_path, root))

    deduped = _dedupe_pass1_findings(all_findings)
    by_category = {}
    for f in deduped:
        by_category.setdefault(f["category"], []).append(f)

    # Detect first-time setup — project-context.md missing and no prior audits.
    suggested_audits_dir = str(root / "audits")
    audits_exists = (root / "audits").exists()
    first_time = not context["found"] and not audits_exists

    response = {
        "project_path": str(root),
        "files_scanned": files_scanned,
        "candidates_found": len(deduped),
        "by_category": by_category,
        "project_context_loaded": context["found"],
        "declared_sensitive_fields": [e["raw"] for e in context["sensitive_fields"]] if context["found"] else [],
    }

    if first_time:
        response["first_time_setup_recommended"] = True
        response["suggested_init_call"] = {
            "tool": "sentinel_init",
            "args": {
                "project_path": str(root),
                "audits_dir": suggested_audits_dir,
                "include_cursor_rules": True,
            },
            "note": (
                "audits_dir defaults to {project_path}/audits/. If you prefer to track audits "
                "in a separate folder (e.g., a dedicated 'Sentinel on <Project>' tracking project), "
                "override audits_dir before calling."
            ),
        }
        response["instructions_for_caller"] = (
            "FIRST-TIME SETUP: this project has no project-context.md and no audits/ folder. "
            "Before continuing with Pass 1 results, ask the user: 'This project hasn't been set up "
            "for Sentinel yet. Want me to initialize it? That creates project-context.md (a template "
            "you'll fill in), an audits/ folder for reports, and (in Cursor) checkpoint rules. "
            "Or do you want to run a minimal audit without project-specific context?' "
            "If the user says yes to init, call sentinel_init with the suggested_init_call args. "
            "Then re-run sentinel_pass1_discover to surface candidates against the now-initialized "
            "project. After Pass 1 results are presented and confirmed, proceed to sentinel_pass2_audit."
        )
    else:
        response["first_time_setup_recommended"] = False
        response["instructions_for_caller"] = (
            "Present these candidates to the developer grouped by category. "
            "If declared_sensitive_fields is non-empty, those are already confirmed by the developer "
            "via project-context.md — use them directly as input to sentinel_pass2_audit instead of "
            "re-asking. Only confirm/dismiss the candidates that are NOT already in declared_sensitive_fields."
        )

    return json.dumps(response, indent=2)


# ====================================================================
# Pass 2 — fixed-layer deterministic checks
# ====================================================================

# ---------- Hardcoded secret patterns ----------
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]", "AWS secret access key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe live secret key"),
    (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe test secret key"),
    (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe restricted key"),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe publishable key (live)"),
    (r"ghp_[A-Za-z0-9]{36,}", "GitHub personal access token"),
    (r"gho_[A-Za-z0-9]{36,}", "GitHub OAuth token"),
    (r"ghs_[A-Za-z0-9]{36,}", "GitHub server-to-server token"),
    (r"xox[abprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "Private key block"),
    (r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", "JWT (possibly hardcoded)"),
    (r"(?i)(api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][^'\"\s]{12,}['\"]",
     "Generic credential assignment with literal value"),
]
_compiled_secrets = [(re.compile(pat), label) for pat, label in SECRET_PATTERNS]

TEST_PATH_HINTS = re.compile(r"(?:^|/)(tests?|__tests__|spec|fixtures?|mocks?|examples?|stories|.*\.test\.|.*\.spec\.)", re.IGNORECASE)


def _is_likely_test_file(rel_path: str) -> bool:
    return bool(TEST_PATH_HINTS.search(rel_path))


# Secret scanning runs over a broader set than the default source walker — config
# files (app.json, eas.json, *.plist, *.xml, *.yml) frequently leak credentials too.
SECRET_SCAN_EXTRA_EXTENSIONS = {".plist", ".xml", ".json", ".yml", ".yaml"}


def _walk_files_for_secrets(root: Path):
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        suffix = path.suffix.lower()
        if suffix not in SCAN_EXTENSIONS and suffix not in SECRET_SCAN_EXTRA_EXTENSIONS:
            continue
        # Skip lockfiles — they contain integrity hashes that look like credentials
        # but aren't.
        if path.name in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"}:
            continue
        yield path


def _check_hardcoded_secrets(root: Path):
    findings = []
    for path in _walk_files_for_secrets(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        for line_num, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("//", "#", "*", "/*", "<!--")):
                continue
            for regex, label in _compiled_secrets:
                if regex.search(line):
                    findings.append({
                        "severity": "CRITICAL",
                        "rule": "secrets.hardcoded",
                        "title": f"Hardcoded {label} in {path.suffix or path.name}",
                        "file": rel,
                        "line": line_num,
                        "excerpt": stripped[:200],
                        "tell_cursor": (
                            f"Remove the hardcoded {label.lower()} from {rel}:{line_num}. "
                            f"Move it to a .env file (already gitignored) and read via the project's "
                            f"environment-config layer. Confirm the literal does not appear anywhere else "
                            f"in the codebase or in git history before considering this resolved. "
                            f"Config files like app.json and *.plist are committed — they MUST NOT contain secrets."
                        ),
                    })
    return findings


def _check_env_in_gitignore(root: Path):
    findings = []
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        findings.append({
            "severity": "HIGH",
            "rule": "secrets.no_gitignore",
            "title": "No .gitignore file at repo root",
            "file": ".gitignore",
            "line": 0,
            "excerpt": "(file missing)",
            "tell_cursor": "Create a .gitignore at the repo root and add .env, .env.local, .env.production, "
                           "node_modules, .expo, ios/Pods, android/build, and any other build artifacts.",
        })
        return findings

    contents = gitignore.read_text(encoding="utf-8", errors="ignore")
    required = [".env", ".env.local", ".env.production"]
    missing = []
    for entry in required:
        pattern = rf"(?m)^\s*({re.escape(entry)}|\.env\*|\.env\.\*|\*\.env)\s*$"
        if not re.search(pattern, contents):
            missing.append(entry)

    if missing:
        findings.append({
            "severity": "CRITICAL",
            "rule": "secrets.env_not_ignored",
            "title": f".gitignore does not cover {', '.join(missing)}",
            "file": ".gitignore",
            "line": 0,
            "excerpt": "(see .gitignore contents)",
            "tell_cursor": (
                f"Add the following entries to .gitignore: {', '.join(missing)}. "
                "Then run `git ls-files | grep -E '\\.env'` to confirm no .env file is currently tracked. "
                "If any are tracked, remove them from history with `git rm --cached` and rotate the secrets they contained."
            ),
        })
    return findings


def _check_file_size(root: Path, threshold: int = 200):
    findings = []
    for path in _walk_source_files(root):
        try:
            line_count = sum(1 for _ in path.read_text(encoding="utf-8", errors="ignore").splitlines())
        except Exception:
            continue
        if line_count > threshold:
            rel = str(path.relative_to(root))
            findings.append({
                "severity": "MEDIUM",
                "rule": "code_quality.file_too_long",
                "title": f"File exceeds {threshold} lines ({line_count} lines)",
                "file": rel,
                "line": line_count,
                "excerpt": f"({line_count} lines total)",
                "tell_cursor": (
                    f"Refactor {rel} into smaller modules. Identify cohesive sections "
                    f"(by responsibility) and extract them into separate files. Aim for "
                    f"{threshold} lines or fewer per file."
                ),
            })
    return findings


ANY_PATTERN = re.compile(r"(?<![A-Za-z0-9_])(?::\s*any\b|as\s+any\b|<any>)", re.IGNORECASE)


def _check_any_overuse(root: Path, threshold: int = 5):
    findings = []
    for path in _walk_source_files(root):
        if path.suffix not in {".ts", ".tsx"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        count = len(ANY_PATTERN.findall(text))
        if count >= threshold:
            findings.append({
                "severity": "MEDIUM",
                "rule": "code_quality.any_overuse",
                "title": f"Excessive use of `any` type ({count} occurrences)",
                "file": rel,
                "line": 0,
                "excerpt": f"({count} `any` usages)",
                "tell_cursor": (
                    f"Replace each `any` in {rel} with a proper TypeScript type. "
                    "If the type is genuinely unknown, use `unknown` and narrow with type guards "
                    "rather than `any`."
                ),
            })
    return findings


def _check_sensitive_logging(root: Path, sensitive_field_names):
    if not sensitive_field_names:
        return []
    field_alt = "|".join(re.escape(f) for f in sensitive_field_names)
    log_re = re.compile(
        rf"console\.(log|warn|error|info|debug|trace)\s*\([^)]*\b({field_alt})\b",
        re.IGNORECASE,
    )
    findings = []
    for path in _walk_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        for line_num, line in enumerate(text.splitlines(), start=1):
            m = log_re.search(line)
            if m:
                findings.append({
                    "severity": "HIGH",
                    "rule": "data_exposure.sensitive_log",
                    "title": f"Sensitive field `{m.group(2)}` written to console.{m.group(1)}",
                    "file": rel,
                    "line": line_num,
                    "excerpt": line.strip()[:200],
                    "tell_cursor": (
                        f"Remove or mask the sensitive value at {rel}:{line_num}. "
                        f"Sensitive fields must never reach console output, error reporters, or analytics. "
                        f"If logging is needed for debugging, log a redacted summary "
                        f"(e.g., `email.split('@')[1]` for domain-only) or remove entirely."
                    ),
                })
    return findings


URL_PATH_RE = re.compile(r"['\"]/(api|auth|admin|user)[^\s'\"]*['\"]")


def _check_sensitive_in_urls(root: Path, sensitive_field_names):
    if not sensitive_field_names:
        return []
    field_alt = "|".join(re.escape(f) for f in sensitive_field_names)
    sensitive_in_url_re = re.compile(
        rf"['\"][^'\"]*\b({field_alt})\b[^'\"]*['\"]",
        re.IGNORECASE,
    )
    findings = []
    for path in _walk_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        for line_num, line in enumerate(text.splitlines(), start=1):
            if not URL_PATH_RE.search(line):
                continue
            m = sensitive_in_url_re.search(line)
            if m:
                findings.append({
                    "severity": "HIGH",
                    "rule": "data_exposure.sensitive_in_url",
                    "title": f"Sensitive field `{m.group(1)}` appears in URL string",
                    "file": rel,
                    "line": line_num,
                    "excerpt": line.strip()[:200],
                    "tell_cursor": (
                        f"Move the sensitive parameter at {rel}:{line_num} out of the URL. "
                        "Sensitive data in URLs gets logged by servers, proxies, browser history, and "
                        "analytics. Pass it in the request body (POST) or as a header instead."
                    ),
                })
    return findings


# ====================================================================
# Pass 2 — project-context-driven checks
# ====================================================================

def _check_async_storage_for_tokens(root: Path, parsed_fields):
    """If project-context declares any field with rule containing 'SecureStore only'
    or 'never AsyncStorage' / 'Keychain only', flag every AsyncStorage call site that
    references that field name. This is a Breth-style check but generalizes well.
    """
    targets = []
    for entry in parsed_fields:
        rules_lower = entry["rules"].lower()
        if "securestore" in rules_lower or "keychain" in rules_lower or "never asyncstorage" in rules_lower:
            leaf = entry["field"].split(".")[-1]
            targets.append(leaf)
    if not targets:
        return []

    field_alt = "|".join(re.escape(t) for t in targets)
    pattern = re.compile(
        rf"AsyncStorage\.[a-zA-Z]+\s*\([^)]*\b({field_alt})\b|AsyncStorage[^)]*\b({field_alt})\b",
        re.IGNORECASE,
    )
    findings = []
    for path in _walk_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        for line_num, line in enumerate(text.splitlines(), start=1):
            m = pattern.search(line)
            if m:
                field_hit = m.group(1) or m.group(2)
                findings.append({
                    "severity": "CRITICAL",
                    "rule": "context.secure_storage_violation",
                    "title": f"`{field_hit}` accessed via AsyncStorage — project-context requires SecureStore/Keychain",
                    "file": rel,
                    "line": line_num,
                    "excerpt": line.strip()[:200],
                    "tell_cursor": (
                        f"Replace AsyncStorage with SecureStore (or platform Keychain/Keystore) for `{field_hit}` "
                        f"at {rel}:{line_num}. project-context.md explicitly requires secure storage for this field. "
                        "If the value was previously written to AsyncStorage, also write a one-time migration "
                        "to clear the AsyncStorage entry on next launch."
                    ),
                })
    return findings


def _check_analytics_scrubbing(root: Path, parsed_fields):
    """For fields with rule mentioning 'never in analytics' or 'scrub from breadcrumbs',
    flag analytics/error-reporter call sites that include the field. Targets PostHog,
    Sentry, Amplitude, Mixpanel, Firebase Analytics."""
    targets = []
    for entry in parsed_fields:
        rules_lower = entry["rules"].lower()
        if "analytics" in rules_lower or "breadcrumb" in rules_lower or "scrub" in rules_lower or "never logged" in rules_lower:
            leaf = entry["field"].split(".")[-1]
            targets.append(leaf)
    if not targets:
        return []

    field_alt = "|".join(re.escape(t) for t in targets)
    analytics_re = re.compile(
        rf"(posthog|sentry|amplitude|mixpanel|firebase\.analytics|analytics)\.[a-zA-Z]+\s*\([^)]*\b({field_alt})\b",
        re.IGNORECASE,
    )
    findings = []
    for path in _walk_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        for line_num, line in enumerate(text.splitlines(), start=1):
            m = analytics_re.search(line)
            if m:
                findings.append({
                    "severity": "HIGH",
                    "rule": "context.analytics_leak",
                    "title": f"`{m.group(2)}` passed to {m.group(1)} call — project-context requires scrubbing",
                    "file": rel,
                    "line": line_num,
                    "excerpt": line.strip()[:200],
                    "tell_cursor": (
                        f"Strip `{m.group(2)}` before sending to {m.group(1)} at {rel}:{line_num}. "
                        "project-context.md requires this field to be scrubbed from analytics/error-reporter "
                        "payloads. Use a hashed user_id or remove the field entirely from the event."
                    ),
                })
    return findings


# ====================================================================
# Pass 2 — injection & unsafe-pattern checks (OWASP Mobile Top 10 M4)
# ====================================================================
#
# Patterns are line-level regex. Each entry: (regex, severity, rule_id, title_template,
# tell_cursor_template). Tests files are skipped to reduce noise.

INJECTION_PATTERNS = [
    # ---- XSS / template injection ----
    (r"dangerouslySetInnerHTML\s*=", "CRITICAL", "xss.dangerously_set_inner_html",
     "Use of `dangerouslySetInnerHTML`",
     "Replace dangerouslySetInnerHTML with safe rendering primitives. If you absolutely must render HTML, sanitize with a library like DOMPurify and document the justification in a code comment."),

    # ---- eval family ----
    (r"(?<![A-Za-z0-9_])eval\s*\(", "CRITICAL", "injection.eval",
     "Use of `eval()`",
     "Remove eval(). There is virtually no legitimate use of eval() in app code. If you're parsing JSON or other structured data, use JSON.parse with validation."),
    (r"new\s+Function\s*\(", "CRITICAL", "injection.new_function",
     "Use of `new Function()` constructor",
     "Replace new Function() with explicit logic. Dynamically constructed functions are an injection vector and bypass strict mode."),
    (r"set(?:Timeout|Interval)\s*\(\s*['\"`]", "HIGH", "injection.timer_string",
     "setTimeout/setInterval called with a string argument (eval-like behavior)",
     "Pass a function reference instead of a string: setTimeout(() => myFn(), 1000)."),

    # ---- WebView injection surface ----
    (r"injectedJavaScript\s*=", "HIGH", "webview.injected_js",
     "WebView `injectedJavaScript` prop set",
     "Verify injectedJavaScript content is static and does not interpolate user data. If it does, treat the WebView as an XSS sink and sanitize the data or refactor to postMessage."),
    (r"source\s*=\s*\{\s*\{\s*html\s*:", "HIGH", "webview.source_html",
     "WebView `source={{ html: ... }}` renders HTML directly",
     "Confirm the HTML content does not contain user-provided data. If it does, sanitize it or render via the `uri` prop instead of `html`."),

    # ---- Command injection (rare in RN but check anyway) ----
    (r"child_process\.(exec|spawn|execFile)\s*\(\s*[`'\"][^`'\"]*\$\{", "CRITICAL", "injection.command",
     "child_process command built from template literal (likely with user input)",
     "Sanitize inputs and prefer execFile with an array of arguments. Never pass shell-interpreted strings built from user data."),

    # ---- SQL injection via string concat ----
    (r"\.(query|execute|raw)\s*\(\s*[`'\"][^`'\"]*\+[^`'\"]+[`'\"]", "CRITICAL", "injection.sql_concat",
     "SQL query built via string concatenation",
     "Use parameterized queries. String-concatenated SQL is a classic injection vector regardless of how trusted the input looks."),
    (r"\.(query|execute|raw)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`", "CRITICAL", "injection.sql_template_literal",
     "SQL query built via template literal interpolation",
     "Template-literal interpolation in SQL is equivalent to string concatenation — use the driver's parameterization API."),

    # ---- Open redirect / unsafe URL handling ----
    (r"Linking\.openURL\s*\(\s*(?!['\"`])[a-zA-Z_$][a-zA-Z0-9_$.]*\s*\)", "MEDIUM", "redirect.open_url_unvalidated",
     "`Linking.openURL` called with a variable — destination URL not visibly validated",
     "If the URL originates from user input or a remote response, validate it against a strict allowlist before opening. Untrusted URLs can phish or trigger malicious deep-link flows in other apps."),

    # ---- Weak cryptography ----
    (r"(?:createHash|crypto)\s*\(\s*['\"](md5|sha1)['\"]", "HIGH", "crypto.weak_algorithm",
     "Weak hash algorithm (MD5 or SHA1) used in a crypto context",
     "Replace with SHA-256 or SHA-3. MD5 and SHA1 are cryptographically broken for security purposes."),
    (r"Math\.random\s*\(\s*\)[^;]*(?:token|password|secret|key|nonce|salt)", "HIGH", "crypto.math_random_for_secret",
     "`Math.random()` used in a context that looks like security material",
     "Math.random() is not cryptographically secure. Use a CSPRNG: e.g., `expo-crypto` `getRandomBytesAsync`, or `crypto.randomUUID()` for IDs."),

    # ---- Insecure transport ----
    (r"['\"]\s*http://(?!localhost|127\.0\.0\.1)[a-zA-Z0-9.\-]+(?:[:/][^'\"]*)?['\"]", "HIGH", "communication.insecure_http",
     "Hardcoded `http://` URL (insecure transport)",
     "Replace http:// with https://. Plain HTTP traffic is readable and modifiable by anyone on the network path. iOS and Android also block plain HTTP by default — this likely doesn't work in production builds."),

    # ---- CORS misconfig ----
    (r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]", "HIGH", "misconfig.cors_wildcard",
     "CORS configured with wildcard origin (`*`)",
     "Replace `Access-Control-Allow-Origin: *` with an explicit allowlist of trusted origins. Wildcard CORS combined with credentialed requests = critical leak."),

    # ---- TLS / certificate-validation bypass (OWASP Mobile M5) ----
    (r"rejectUnauthorized\s*:\s*false", "CRITICAL", "tls.reject_unauthorized_false",
     "TLS certificate validation disabled (`rejectUnauthorized: false`)",
     "Remove `rejectUnauthorized: false`. This disables TLS certificate validation and allows any MITM attacker to intercept traffic. If you're hitting a server with a self-signed cert in development, gate the bypass behind `__DEV__` and add a comment, or import the cert into your trust store."),
    (r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0['\"]?", "CRITICAL", "tls.node_tls_reject_disabled",
     "`NODE_TLS_REJECT_UNAUTHORIZED=0` disables Node TLS validation globally",
     "Remove this environment variable. It disables TLS cert validation for every outbound request in the process, not just one client."),
    (r"(?:trustAllCerts|TrustAllSSL|TrustManager.*acceptAllIssuers|setHostnameVerifier.*ALLOW_ALL)", "CRITICAL", "tls.trust_all_certs",
     "Trust-all-certificates pattern detected",
     "Remove the trust-all-certs override. The presence of this pattern indicates TLS validation has been intentionally bypassed — that's a complete defeat of HTTPS protection."),

    # ---- WebView wildcard origin allowlist ----
    (r"originWhitelist\s*=\s*\{\s*\[\s*['\"]?\*['\"]?\s*\]", "HIGH", "webview.wildcard_origin_whitelist",
     "WebView `originWhitelist={['*']}` allows any origin",
     "Replace the wildcard with an explicit list of trusted origins (`originWhitelist={['https://your-domain.com']}`). Wildcard origin whitelist means a compromised page can call back into native code via the WebView bridge."),

    # ---- JWT decode without verify ----
    (r"\bjwt\.decode\s*\(", "HIGH", "auth.jwt_decode_without_verify",
     "`jwt.decode()` used — signature is NOT verified",
     "If this code path trusts the JWT claims for authorization, switch to `jwt.verify(token, secret, { algorithms: ['HS256' /* or your algorithm */] })`. `decode()` only base64-decodes the payload without checking the signature — anyone can forge a JWT and pass it through. Use `decode()` only for inspection on already-verified tokens."),

    # ---- JWT algorithm 'none' accepted ----
    (r"algorithms?\s*:\s*(?:\[[^\]]*['\"]none['\"][^\]]*\]|['\"]none['\"])", "CRITICAL", "auth.jwt_none_algorithm",
     "JWT verification configured to accept the `none` algorithm",
     "Remove `'none'` from accepted JWT algorithms. The `none` algorithm tells the verifier to skip signature checking entirely — attackers can craft tokens with any payload and the verifier accepts them. Pin to a specific signing algorithm: `algorithms: ['HS256']` or `['RS256']`."),

    # ---- KDF parameter strength (OWASP Mobile M10) ----
    (r"bcrypt\.(?:hash|hashSync|genSalt|genSaltSync)\s*\(\s*[^,)]*,\s*([0-9])\s*[,)]", "CRITICAL", "crypto.bcrypt_rounds_dangerous",
     "bcrypt rounds < 10 — password hash is too cheap to compute",
     "Increase bcrypt rounds (the cost/work factor) to at least 12 for new applications. Below 10 means a modern GPU can brute-force the hash. Format: `bcrypt.hash(password, 12)`."),
    (r"bcrypt\.(?:hash|hashSync|genSalt|genSaltSync)\s*\(\s*[^,)]*,\s*1[01]\s*[,)]", "HIGH", "crypto.bcrypt_rounds_low",
     "bcrypt rounds between 10 and 11 — below current recommended minimum",
     "Increase bcrypt rounds to 12 or higher. OWASP currently recommends 12 as a minimum, with periodic review as hardware improves. Format: `bcrypt.hash(password, 12)`."),
    (r"(?:pbkdf2(?:Sync)?|crypto\.pbkdf2)\s*\([^)]*,\s*[1-9][0-9]{0,4}\s*,", "HIGH", "crypto.pbkdf2_iterations_low",
     "PBKDF2 iteration count below 100,000",
     "Increase PBKDF2 iterations to at least 600,000 for SHA-256 (per OWASP 2023 guidance). Below 100k can be brute-forced in reasonable time on modern hardware."),

    # ---- Hardcoded encryption keys / IVs (extends secret coverage with crypto specificity) ----
    (r"(?:iv|initialization_?vector)\s*[:=]\s*Buffer\.from\s*\(\s*['\"][0-9a-fA-F]{16,}['\"]", "HIGH", "crypto.hardcoded_iv",
     "Hardcoded initialization vector (IV) — IV reuse breaks symmetric encryption",
     "Generate a fresh random IV for every encryption call: `crypto.randomBytes(16)` (for AES-CBC) or `crypto.randomBytes(12)` (for AES-GCM). A static IV makes the cipher deterministic — identical plaintexts produce identical ciphertexts, leaking information and (for some modes) enabling key recovery."),
    (r"(?:encryption_?key|aes_?key|cipher_?key)\s*[:=]\s*['\"][A-Fa-f0-9]{32,}['\"]", "CRITICAL", "crypto.hardcoded_key",
     "Hardcoded symmetric encryption key",
     "Remove the hardcoded encryption key from source. Encryption keys must come from a secure source: a secrets manager, environment variable (gitignored), platform keystore, or KMS. A key in source is recoverable by anyone with read access to the repo."),

    # ---- Insecure deserialization (OWASP A8) ----
    (r"JSON\.parse\s*\(\s*(?:req\.body|req\.query|req\.params|request\.body)", "HIGH", "deserialization.parse_request_unvalidated",
     "JSON.parse of request body/query/params without prior schema validation",
     "Validate the parsed object against a schema (Zod, Yup, Joi, AJV) BEFORE using its values. Untrusted JSON can include unexpected types or extra fields that break downstream assumptions or enable prototype pollution when merged."),
    (r"vm\.(?:runInNewContext|runInThisContext|runInContext)\s*\(", "CRITICAL", "deserialization.vm_run",
     "Node `vm` module used to execute code — code-injection sink",
     "Avoid the `vm` module for executing strings derived from any external input. If sandboxing is genuinely needed, use a dedicated sandbox like `isolated-vm` and never pass untrusted strings."),

    # ---- Path traversal — obvious in-line cases ----
    (r"fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|unlink|unlinkSync|appendFile|appendFileSync)\s*\(\s*(?:req\.params|req\.query|req\.body)\.", "CRITICAL", "injection.path_traversal_obvious",
     "File system operation with path taken directly from request — path traversal risk",
     "Never pass user-controlled paths to fs operations. Validate against an allowlist of permitted filenames, or hash/UUID the identifier so user input never reaches the filesystem. Even with sanitization, prefer indirect references: store an allowlist of allowed file IDs and look them up by ID."),
    (r"path\.(?:join|resolve)\s*\([^)]*(?:req\.params|req\.query|req\.body)\.[^)]*\)", "HIGH", "injection.path_traversal_join",
     "path.join / path.resolve called with request data — possible traversal",
     "Validate the user-supplied path component does not contain `..`, absolute paths, or null bytes BEFORE joining. Prefer indirect references (look up the real path from an allowlist by ID) over taking any path component from a request."),

    # ---- Prototype pollution — obvious in-line cases ----
    (r"Object\.assign\s*\(\s*[^,]+,\s*(?:req\.body|req\.query|req\.params)\s*\)", "HIGH", "injection.prototype_pollution_assign",
     "Object.assign merging request data into an object — prototype pollution risk",
     "Validate the source object with a schema first, or use a safe merge that ignores `__proto__`, `constructor`, and `prototype` keys (e.g., `Object.assign({}, structuredClone(req.body))` with key allowlist). Prototype pollution lets an attacker set properties on Object.prototype, affecting every object in the process."),
    (r"_\.(?:merge|mergeWith|defaults|defaultsDeep|set)\s*\(\s*[^,]+,\s*(?:req\.body|req\.query|req\.params)", "HIGH", "injection.prototype_pollution_lodash",
     "lodash merge/defaults/set called with request data — prototype pollution risk",
     "lodash has had multiple prototype-pollution CVEs in `merge`/`mergeWith`/`defaultsDeep`/`set`. Update to the latest lodash and validate input with a schema before merging. Alternatively, use a safer merge utility."),

    # ---- SSRF — obvious cases ----
    (r"(?:fetch|axios\.(?:get|post|put|delete|request)|http\.(?:get|request)|https\.(?:get|request))\s*\(\s*(?:req\.body|req\.query|req\.params)\.", "CRITICAL", "injection.ssrf_obvious",
     "HTTP request URL taken directly from request body/query/params — SSRF risk",
     "Validate the URL against an explicit allowlist of trusted external hosts before making the request. Otherwise an attacker can make your server fetch internal-only endpoints (cloud metadata, internal admin APIs, etc.) and exfiltrate the response. Block schemes other than http/https and disallow private IP ranges."),

    # ---- Hardcoded admin/test credentials in non-test source ----
    (r"(?:password|passwd|pwd|admin_?password)\s*[:=]\s*['\"](?:admin|password|123456|12345678|qwerty|letmein|welcome|test|test1234|changeme|default|root)['\"]", "HIGH", "credentials.hardcoded_default",
     "Hardcoded default/admin/test password in source",
     "Remove the hardcoded credential. Default credentials in source ship to production and are commonly tried by attackers. If this is a seed value for tests, move it into a test fixture directory (which Sentinel skips) and clearly name it as such."),

    # ---- Hardcoded string used as route access gate ----
    # Catches direct literal comparison: req.query.code !== 'ABC123'
    (r"req\.query\.\w+\s*!==?\s*['\"][A-Za-z0-9_\-]{4,30}['\"]", "HIGH", "auth.hardcoded_route_guard",
     "Hardcoded string used as route access gate (query param comparison)",
     "Replace the hardcoded access string with proper authentication. A literal string committed "
     "to source code is not a secret — anyone with repo read access has it. It also appears in "
     "plaintext in server access logs when passed as a query param. Use Supabase/JWT Bearer token "
     "auth and verify the caller's role instead."),
    # Catches indirect variable assignment: const ACCESS_CODE = 'ABC123'
    (r"(?:const|let|var)\s+[A-Z_]{4,30}\s*=\s*['\"][A-Za-z0-9_\-]{4,20}['\"]", "HIGH",
     "auth.hardcoded_route_guard_variable",
     "Short uppercase constant assigned a literal string — possible hardcoded access gate",
     "If this constant is used to gate route access (compared against req.query or req.body), "
     "replace it with proper authentication. Literal strings in source code are not secrets — "
     "anyone with repo read access can read the value. Use Supabase/JWT Bearer token auth instead."),

    # ---- Weak password minimum length policy ----
    (r"password\b.{0,30}\.length\s*<\s*([1-9]|1[01])\b", "HIGH", "auth.weak_password_minimum",
     "Password minimum length below 12 characters",
     "Increase the password minimum length to at least 12 characters for any app handling "
     "sensitive data. NIST SP 800-63B recommends 8 as an absolute minimum; healthcare and "
     "financial applications should use 12+. A 6-character minimum can be brute-forced offline "
     "in seconds with modern hardware. Update the validation check and communicate the new "
     "requirement to existing users."),

    # ---- Open redirect (CWE-601, OWASP A01) ----
    (r"res\.redirect\s*\(\s*(?:req\.(?:query|params|body))\.\w+", "HIGH", "injection.open_redirect",
     "Open redirect — redirect target taken directly from request input",
     "Validate the redirect URL against an explicit allowlist of trusted internal paths before "
     "calling res.redirect(). Open redirects let attackers craft phishing URLs that appear to "
     "originate from your domain (e.g. https://your-app.com/login?next=https://evil.com). "
     "Never redirect to a URL taken verbatim from request query/body/params. "
     "(CWE-601: URL Redirection to Untrusted Site)"),

    # ---- Stack trace / raw error object in API response (CWE-200, OWASP A05) ----
    (r"res\.(?:json|send)\s*\(\s*(?:err|error|e)\s*\)", "HIGH", "info_exposure.raw_error_in_response",
     "Raw error object passed directly to res.json() / res.send()",
     "Replace `res.json(err)` or `res.send(error)` with a sanitized error response. "
     "Log the full error server-side (Sentry/structured log), then return only a generic "
     "message: `res.status(500).json({ error: 'Internal server error' })`. "
     "Raw error objects expose file paths, dependency versions, and internal logic to attackers. "
     "(CWE-200: Exposure of Sensitive Information)"),
    (r"res\.(?:json|send)\s*\([^;]{0,150}\.stack\b", "CRITICAL", "info_exposure.stack_trace_in_response",
     "Stack trace (`.stack`) sent in API response to client",
     "Remove `.stack` from the response payload. Log stack traces server-side (Sentry or "
     "structured logger), then return only a sanitized message to the client: "
     "`res.status(500).json({ error: 'Internal server error' })`. "
     "A stack trace exposes your file system layout, library versions, and internal logic — "
     "directly useful to an attacker profiling your application. "
     "(CWE-200: Exposure of Sensitive Information, OWASP A05 Security Misconfiguration)"),
]
_compiled_injection = [
    (re.compile(pat), sev, rule, title, tell)
    for pat, sev, rule, title, tell in INJECTION_PATTERNS
]


def _check_injection_safety(root: Path):
    findings = []
    for path in _walk_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        for line_num, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("//", "#", "*", "/*", "<!--")):
                continue
            for regex, severity, rule, title, tell in _compiled_injection:
                if regex.search(line):
                    findings.append({
                        "severity": severity,
                        "rule": rule,
                        "title": title,
                        "file": rel,
                        "line": line_num,
                        "excerpt": stripped[:200],
                        "tell_cursor": tell,
                    })
    return findings


# ---- Misconfiguration / debug-flag checks (OWASP Mobile M8) ----

MISCONFIG_PATTERNS = [
    (r"['\"]https?://(?:localhost|127\.0\.0\.1)[:/]?[0-9]*['\"]", "MEDIUM", "misconfig.hardcoded_localhost",
     "Hardcoded `localhost` URL — likely a development artifact",
     "Replace hardcoded localhost with an environment-driven base URL. Shipped localhost references break in production builds and may indicate that the dev/prod config split is incomplete."),
    (r"(?:^|\s)(DEBUG|debug)\s*[:=]\s*true\b", "MEDIUM", "misconfig.debug_flag_true",
     "Debug flag explicitly set to `true`",
     "Gate debug flags behind `__DEV__` or `process.env.NODE_ENV === 'development'` so they don't ship to production. Hardcoded `debug: true` will leak verbose info and may disable security checks."),
    (r"NSAllowsArbitraryLoads\s*</?key>\s*<true/>", "HIGH", "misconfig.ats_disabled",
     "App Transport Security disabled (`NSAllowsArbitraryLoads`)",
     "Remove `NSAllowsArbitraryLoads` from Info.plist. This disables iOS App Transport Security and allows plain HTTP — Apple may reject the app and traffic becomes readable on-network."),
    (r"android:usesCleartextTraffic\s*=\s*['\"]true['\"]", "HIGH", "misconfig.cleartext_traffic",
     "Android cleartext traffic explicitly allowed",
     "Remove or set to `false`. `android:usesCleartextTraffic=\"true\"` disables Android's network security config protection against plain HTTP."),

    # ---- Next.js source maps in production (CWE-540, OWASP A05) ----
    (r"productionBrowserSourceMaps\s*:\s*true", "HIGH", "misconfig.source_maps_in_production",
     "Next.js `productionBrowserSourceMaps: true` — source code exposed in production bundle",
     "Remove `productionBrowserSourceMaps: true` from next.config.js. Source maps expose your "
     "original TypeScript/JSX source, file paths, and business logic to anyone who opens browser "
     "DevTools → Sources. If you need source maps for error tracking, upload them privately to "
     "Sentry/Datadog and exclude them from the deployed bundle. "
     "(CWE-540: Inclusion of Sensitive Information in Source Code)"),
]
_compiled_misconfig = [
    (re.compile(pat), sev, rule, title, tell)
    for pat, sev, rule, title, tell in MISCONFIG_PATTERNS
]

# Misconfig patterns also need to scan .plist / .xml — extend the walker for those.
MISCONFIG_EXTRA_EXTENSIONS = {".plist", ".xml", ".json"}


def _walk_misconfig_files(root: Path):
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in MISCONFIG_EXTRA_EXTENSIONS or path.suffix.lower() in SCAN_EXTENSIONS:
            yield path


def _check_misconfig(root: Path):
    findings = []
    for path in _walk_misconfig_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        for line_num, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("//", "#")):
                continue
            for regex, severity, rule, title, tell in _compiled_misconfig:
                if regex.search(line):
                    findings.append({
                        "severity": severity,
                        "rule": rule,
                        "title": title,
                        "file": rel,
                        "line": line_num,
                        "excerpt": stripped[:200],
                        "tell_cursor": tell,
                    })
    return findings


# ---- Supply-chain / dependency hygiene (OWASP Mobile M2) ----

def _check_lockfile_present(root: Path):
    """Flag if no lockfile is present — non-deterministic dependency resolution is a supply-chain risk."""
    candidates = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"]
    has_package_json = (root / "package.json").exists()
    if not has_package_json:
        return []
    if any((root / c).exists() for c in candidates):
        return []
    return [{
        "severity": "MEDIUM",
        "rule": "supply_chain.no_lockfile",
        "title": "No lockfile present — dependency versions are not pinned",
        "file": "package.json",
        "line": 0,
        "excerpt": "(no lockfile found)",
        "tell_cursor": (
            "Generate a lockfile by running `npm install` (creates package-lock.json), "
            "`yarn install` (creates yarn.lock), or your package manager's equivalent. "
            "Commit the lockfile. Without it, every install pulls latest-matching versions and you're "
            "exposed to malicious package version-bumps in transitive dependencies."
        ),
    }]


# Severity mapping from npm audit to Sentinel.
_NPM_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MEDIUM",
    "low": "MEDIUM",
    "info": "MEDIUM",
}


def _check_npm_audit(root: Path, timeout_seconds: int = 90):
    """Run `npm audit --json` and convert each vulnerability into a Sentinel finding.
    Returns empty list if npm isn't installed, package.json is missing, or npm audit times out
    (with a separate finding noting the timeout).
    """
    findings = []
    package_json = root / "package.json"
    if not package_json.exists():
        return findings

    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError:
        # npm not installed on this machine — supply-chain scanning unavailable.
        return [{
            "severity": "MEDIUM",
            "rule": "supply_chain.npm_unavailable",
            "title": "`npm` not available — supply-chain vulnerability scan skipped",
            "file": "package.json",
            "line": 0,
            "excerpt": "(npm command not found)",
            "tell_cursor": (
                "Install Node.js / npm so Sentinel can run `npm audit` on each scan. "
                "Without this, dependency vulnerabilities are not detected by the MCP."
            ),
        }]
    except subprocess.TimeoutExpired:
        return [{
            "severity": "MEDIUM",
            "rule": "supply_chain.audit_timeout",
            "title": f"`npm audit` did not complete within {timeout_seconds}s",
            "file": "package.json",
            "line": 0,
            "excerpt": f"timeout after {timeout_seconds}s",
            "tell_cursor": (
                "Run `npm audit` manually to investigate dependency vulnerabilities. "
                "If audit consistently times out, your dependency graph may need cleanup."
            ),
        }]

    # npm audit returns non-zero when vulnerabilities exist — that's expected.
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        # Probably an npm error (e.g., no lockfile). Surface it but don't fail the audit.
        return [{
            "severity": "MEDIUM",
            "rule": "supply_chain.audit_unparseable",
            "title": "`npm audit` output could not be parsed",
            "file": "package.json",
            "line": 0,
            "excerpt": (result.stderr or result.stdout)[:200],
            "tell_cursor": (
                "Run `npm audit` manually and resolve any blocking errors (often: missing "
                "lockfile or out-of-sync node_modules). Then re-run the Sentinel audit."
            ),
        }]

    # npm v7+ format: top-level `vulnerabilities` dict keyed by package name.
    vulns_dict = data.get("vulnerabilities", {})
    if not isinstance(vulns_dict, dict):
        return findings

    for pkg_name, info in vulns_dict.items():
        if not isinstance(info, dict):
            continue
        sev_lower = (info.get("severity") or "low").lower()
        severity = _NPM_SEVERITY_MAP.get(sev_lower, "MEDIUM")

        # `via` is the audit's chain — strings (transitive) or dicts (advisory entries).
        advisory_titles = []
        cwes = []
        urls = []
        for v in info.get("via", []) or []:
            if isinstance(v, dict):
                t = v.get("title")
                if t:
                    advisory_titles.append(t)
                cwes.extend(v.get("cwe") or [])
                u = v.get("url")
                if u:
                    urls.append(u)
        if not advisory_titles:
            advisory_titles = ["transitive dependency vulnerability"]

        fix_available = info.get("fixAvailable")
        if fix_available is True:
            fix_desc = "Auto-fix available via `npm audit fix`."
        elif isinstance(fix_available, dict):
            major = fix_available.get("isSemVerMajor")
            fix_desc = (
                f"Fix requires upgrading `{fix_available.get('name')}` to `{fix_available.get('version')}`"
                f" ({'POTENTIALLY BREAKING — major version bump' if major else 'non-breaking'})."
            )
        else:
            fix_desc = "No automatic fix available — manual upgrade or replacement required."

        cwe_str = (", ".join(sorted(set(cwes)))) if cwes else "no CWE recorded"
        title_advisory = advisory_titles[0][:120]

        findings.append({
            "severity": severity,
            "rule": f"supply_chain.npm_audit_{sev_lower}",
            "title": f"npm audit ({sev_lower}): `{pkg_name}` — {title_advisory}",
            "file": "package.json",
            "line": 0,
            "excerpt": f"package={pkg_name} severity={sev_lower} cwe={cwe_str}",
            "tell_cursor": (
                f"Address npm audit finding on `{pkg_name}` ({sev_lower} severity). "
                f"{fix_desc} "
                f"Advisories: {'; '.join(advisory_titles[:3])}. "
                f"References: {', '.join(urls[:3]) if urls else '(none)'}. "
                f"Re-run `npm audit` after the upgrade to confirm resolution."
            ),
        })

    return findings


# ---- CSRF middleware absence (web/backend projects) ----

CSRF_LIBRARY_HINTS = re.compile(
    r"\b(?:csurf|csrf-protection|csrf-csrf|@fastify/csrf-protection|@nestjs/csrf|lusca|koa-csrf|next-csrf)\b",
    re.IGNORECASE,
)
STATE_CHANGING_ROUTE_HINTS = re.compile(
    r"(?:app|router)\.(post|put|patch|delete)\s*\(|"
    r"export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\s*\(",
    re.IGNORECASE,
)


def _check_csrf_protection(root: Path):
    """Flag if state-changing HTTP routes exist (POST/PUT/PATCH/DELETE) without any
    CSRF middleware imported anywhere in the project. CSRF is relevant for any
    cookie-authenticated web/backend; not relevant for pure mobile-API JWT auth
    BUT the absence of CSRF in a project that has both web routes and cookies is
    a real gap that's worth surfacing for human review.
    """
    findings = []
    has_csrf_library = False
    has_state_changing_route = False
    first_route_file = None

    for path in _walk_source_files(root):
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if CSRF_LIBRARY_HINTS.search(text):
            has_csrf_library = True
        if not has_state_changing_route and STATE_CHANGING_ROUTE_HINTS.search(text):
            has_state_changing_route = True
            first_route_file = rel

    # Also check package.json
    pkg = root / "package.json"
    if pkg.exists():
        try:
            text = pkg.read_text(encoding="utf-8", errors="ignore")
            if CSRF_LIBRARY_HINTS.search(text):
                has_csrf_library = True
        except Exception:
            pass

    if has_state_changing_route and not has_csrf_library:
        findings.append({
            "severity": "MEDIUM",
            "rule": "csrf.middleware_absent",
            "title": "State-changing HTTP routes detected but no CSRF middleware found",
            "file": first_route_file or "(multiple)",
            "line": 0,
            "excerpt": "(no csurf / @fastify/csrf-protection / @nestjs/csrf / similar imported)",
            "tell_cursor": (
                "If the routes use cookie-based session authentication (browser clients), add CSRF "
                "protection. Recommended: `csurf` (Express), `@fastify/csrf-protection` (Fastify), "
                "`@nestjs/csrf` (NestJS), Next.js middleware with double-submit cookie pattern. "
                "If the routes are JWT-Bearer only (mobile / API), CSRF is not strictly required — "
                "in that case, document that fact in code/architecture notes so future contributors "
                "don't accidentally introduce cookie auth without CSRF. Severity is MEDIUM because "
                "this check cannot tell which auth model you're using."
            ),
        })
    return findings


# ---- Screen-recording / screenshot protection (mobile) ----

SCREEN_CAPTURE_PREVENTION_HINTS = re.compile(
    r"(?:FLAG_SECURE|setSecure|expo-screen-capture|react-native-screen-capture|usePreventScreenCapture|"
    r"preventScreenCaptureAsync|setWindowSecure)",
    re.IGNORECASE,
)


def _check_screen_capture_protection(root: Path, context: dict):
    """If the project declares any sensitive fields in project-context.md AND does NOT
    reference any screen-capture-prevention API anywhere in the codebase, flag MEDIUM.
    Only fires when project-context.md exists with sensitive fields — otherwise we
    don't know whether the app handles sensitive screens.
    """
    if not context.get("found"):
        return []
    if not context.get("sensitive_fields"):
        return []

    found_protection = False
    for path in _walk_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if SCREEN_CAPTURE_PREVENTION_HINTS.search(text):
            found_protection = True
            break

    # Also check AndroidManifest.xml and Info.plist for FLAG_SECURE / similar
    if not found_protection:
        for path in list(root.rglob("AndroidManifest.xml")) + list(root.rglob("Info.plist")):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
                if SCREEN_CAPTURE_PREVENTION_HINTS.search(text):
                    found_protection = True
                    break
            except Exception:
                continue

    if found_protection:
        return []

    return [{
        "severity": "MEDIUM",
        "rule": "privacy.no_screen_capture_protection",
        "title": "Sensitive fields declared but no screenshot/screen-recording protection found",
        "file": "(codebase-wide)",
        "line": 0,
        "excerpt": f"sensitive_fields_declared={len(context['sensitive_fields'])}; no FLAG_SECURE / expo-screen-capture / similar",
        "tell_cursor": (
            "Decide whether screens that render sensitive fields need screenshot/recording protection. "
            "On Android: set `WindowManager.LayoutParams.FLAG_SECURE` on Activities with sensitive views. "
            "On iOS: observe `UIApplication.userDidTakeScreenshotNotification` and/or use "
            "`expo-screen-capture` `preventScreenCaptureAsync()` while sensitive screens are mounted. "
            "If you've made a deliberate decision NOT to add this (e.g., not banking-grade app), document "
            "that decision in `project-context.md` so this finding can be dismissed in future audits."
        ),
    }]


# ---- Security headers absence check (Next.js / web projects) ----

_REQUIRED_SECURITY_HEADERS = [
    ("Content-Security-Policy", "HIGH", "headers.csp_missing",
     "Content-Security-Policy header not configured",
     "Add a Content-Security-Policy header in next.config.js headers() or middleware.ts. "
     "Without CSP, injected scripts execute freely in the browser. For Next.js, use a "
     "nonce-based policy via middleware.ts and pass the nonce to Script/style tags. "
     "At minimum: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'."),
    ("Strict-Transport-Security", "MEDIUM", "headers.hsts_missing",
     "Strict-Transport-Security (HSTS) header not configured",
     "Add `Strict-Transport-Security: max-age=63072000; includeSubDomains` to next.config.js "
     "headers(). Without HSTS, browsers do not enforce HTTPS on return visits and downgrade "
     "attacks are possible."),
    ("X-Frame-Options", "MEDIUM", "headers.xfo_missing",
     "X-Frame-Options header not configured",
     "Add `X-Frame-Options: DENY` to next.config.js headers(). Without it, the app can be "
     "embedded in an iframe on any domain — enabling clickjacking attacks that trick users "
     "into clicking UI elements (e.g., submitting forms) without realising it."),
    ("X-Content-Type-Options", "MEDIUM", "headers.xcto_missing",
     "X-Content-Type-Options header not configured",
     "Add `X-Content-Type-Options: nosniff` to next.config.js headers(). Without it, "
     "browsers may MIME-sniff responses and treat a plain-text file as JavaScript."),
    ("Referrer-Policy", "MEDIUM", "headers.referrer_missing",
     "Referrer-Policy header not configured",
     "Add `Referrer-Policy: strict-origin-when-cross-origin` to next.config.js headers(). "
     "Without it, the full URL of the current page (which may contain sensitive IDs) is sent "
     "as a Referer header to any external resource loaded by the page."),
    ("Permissions-Policy", "LOW", "headers.permissions_policy_missing",
     "Permissions-Policy header not configured",
     "Add `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` to "
     "next.config.js headers(). Without it, browser features are unrestricted — any script "
     "on the page can request camera, microphone, or location access. For a healthcare app, "
     "explicitly disabling unused features is a defense-in-depth measure."),
]

_HSTS_INCLUDE_SUBDOMAINS = re.compile(r"includeSubDomains", re.IGNORECASE)


def _check_security_headers(root: Path):
    """Flag missing security headers in Next.js projects.
    Checks next.config.js, next.config.ts, middleware.ts, and middleware.js.
    Only fires for Next.js projects (next.config.* must exist).
    Also checks that HSTS includes the includeSubDomains directive when present.
    """
    has_nextconfig = (root / "next.config.js").exists() or (root / "next.config.ts").exists()
    if not has_nextconfig:
        return []

    combined_text = ""
    for fname in ["next.config.js", "next.config.ts", "middleware.ts", "middleware.js"]:
        f = root / fname
        if f.exists():
            try:
                combined_text += f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

    findings = []
    for header_name, severity, rule, title, tell in _REQUIRED_SECURITY_HEADERS:
        if header_name.lower() not in combined_text.lower():
            findings.append({
                "severity": severity,
                "rule": rule,
                "title": title,
                "file": "next.config.js",
                "line": 0,
                "excerpt": f"('{header_name}' not found in next.config.js or middleware.ts)",
                "tell_cursor": tell,
            })

    # Check HSTS value quality — if HSTS is present but missing includeSubDomains, flag it
    if "strict-transport-security" in combined_text.lower():
        if not _HSTS_INCLUDE_SUBDOMAINS.search(combined_text):
            findings.append({
                "severity": "LOW",
                "rule": "headers.hsts_no_subdomains",
                "title": "Strict-Transport-Security present but missing `includeSubDomains`",
                "file": "next.config.js",
                "line": 0,
                "excerpt": "(Strict-Transport-Security found; includeSubDomains not present)",
                "tell_cursor": (
                    "Update your HSTS header to include `includeSubDomains`: "
                    "`Strict-Transport-Security: max-age=63072000; includeSubDomains`. "
                    "Without it, subdomains can still be accessed over plain HTTP, which "
                    "opens the door to cookie hijacking and protocol downgrade attacks on "
                    "those subdomains."
                ),
            })
    return findings


# ---- Rate limiting absence check (web API projects) ----

_RATE_LIMIT_HINTS = re.compile(
    r"\b(?:upstash/ratelimit|@upstash/ratelimit|express-rate-limit|rate-limiter-flexible|"
    r"bottleneck|p-limit|ratelimit|RateLimit|rateLimiter|rate_limit)\b",
    re.IGNORECASE,
)


def _check_rate_limiting(root: Path):
    """Flag if no rate limiting library is detected in a project with API routes.
    Checks package.json dependencies and middleware.ts/middleware.js for usage hints.
    Only fires when pages/api or app/api directories exist.
    """
    api_dir = root / "pages" / "api"
    app_api = root / "app" / "api"
    if not api_dir.exists() and not app_api.exists():
        return []

    pkg = root / "package.json"
    if pkg.exists():
        try:
            if _RATE_LIMIT_HINTS.search(pkg.read_text(encoding="utf-8", errors="ignore")):
                return []
        except Exception:
            pass

    for fname in ["middleware.ts", "middleware.js"]:
        f = root / fname
        if f.exists():
            try:
                if _RATE_LIMIT_HINTS.search(f.read_text(encoding="utf-8", errors="ignore")):
                    return []
            except Exception:
                pass

    return [{
        "severity": "HIGH",
        "rule": "security.rate_limiting_absent",
        "title": "No rate limiting library detected in API project",
        "file": "package.json",
        "line": 0,
        "excerpt": "(no @upstash/ratelimit / express-rate-limit / rate-limiter-flexible / similar found)",
        "tell_cursor": (
            "Add rate limiting to protect API routes from brute force, credential stuffing, "
            "email bombing, and database connection exhaustion. For Next.js on Vercel, "
            "@upstash/ratelimit with @upstash/redis is the standard approach — it runs at "
            "the edge and survives serverless cold starts. Apply stricter limits to auth and "
            "email-sending routes; more lenient limits to general data routes."
        ),
    }]


# ---- middleware.ts absence check (Next.js projects with API routes) ----

def _check_nextjs_middleware_absent(root: Path):
    """Flag if a Next.js project with API routes has no middleware.ts.
    middleware.ts is where security headers, rate limiting, and auth redirects live.
    Only fires for Next.js projects that also have an API route directory.
    """
    has_nextconfig = (root / "next.config.js").exists() or (root / "next.config.ts").exists()
    if not has_nextconfig:
        return []
    if (root / "middleware.ts").exists() or (root / "middleware.js").exists():
        return []
    api_dir = root / "pages" / "api"
    app_api = root / "app" / "api"
    if not api_dir.exists() and not app_api.exists():
        return []
    return [{
        "severity": "HIGH",
        "rule": "nextjs.middleware_absent",
        "title": "No middleware.ts found in Next.js project with API routes",
        "file": "(project root)",
        "line": 0,
        "excerpt": "(middleware.ts / middleware.js not found at project root)",
        "tell_cursor": (
            "Create middleware.ts at the project root. This is the standard Next.js location "
            "for security headers (CSP, HSTS, X-Frame-Options), rate limiting, and auth redirect "
            "logic that applies to all routes. Without it, these protections must be applied "
            "manually in every route handler — which is error-prone and easily missed. "
            "Note: middleware.ts is for routing/UX/headers — do NOT use it as your only auth "
            "gate. Re-verify authentication inside each route handler or data access layer."
        ),
    }]


# ---- Service role key used in routes that lack auth checks ----

_SERVICE_ROLE_HINTS = re.compile(
    r"SUPABASE_SERVICE_ROLE_KEY|supabase_service_role|serviceRoleKey|service_role_key",
    re.IGNORECASE,
)
_AUTH_CHECK_HINTS = re.compile(
    r"authorization|Bearer|req\.headers\.auth|getUser|verifyJWT|resolveCallerFromToken",
    re.IGNORECASE,
)


def _check_service_role_in_public_routes(root: Path):
    """Flag API route files that use the Supabase service role key without any
    Authorization header check. The service role key bypasses all RLS policies —
    using it in a route with no auth check means any unauthenticated caller can
    trigger that route with elevated database privileges.
    Only scans pages/api and app/api directories.
    """
    api_dirs = [root / "pages" / "api", root / "app" / "api"]
    findings = []

    for api_dir in api_dirs:
        if not api_dir.exists():
            continue
        for path in api_dir.rglob("*"):
            if path.is_dir():
                continue
            if path.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx"}:
                continue
            rel = str(path.relative_to(root))
            if _is_likely_test_file(rel):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if not _SERVICE_ROLE_HINTS.search(text):
                continue
            if _AUTH_CHECK_HINTS.search(text):
                continue
            findings.append({
                "severity": "HIGH",
                "rule": "auth.service_role_in_unauthed_route",
                "title": "Supabase service role key used in route with no auth check",
                "file": rel,
                "line": 0,
                "excerpt": "(service role key present; no Authorization/Bearer/getUser check found)",
                "tell_cursor": (
                    f"The file `{rel}` uses the Supabase service role key, which bypasses all "
                    "RLS policies, but has no Authorization header check or session verification. "
                    "Any unauthenticated caller can trigger this route with full database access. "
                    "Either add a Bearer token auth check and verify the caller's role, or replace "
                    "the service role key with the anon key if elevated privileges are not needed."
                ),
            })
    return findings


# ---- S3 presigned URLs without file size constraints ----

_PRESIGNED_URL_HINTS = re.compile(r"getSignedUrl\s*\(", re.IGNORECASE)
_CONTENT_LENGTH_HINTS = re.compile(r"ContentLengthRange|content.length.range", re.IGNORECASE)


def _check_presigned_url_no_size_limit(root: Path):
    """Flag files that generate S3 presigned upload URLs without a ContentLengthRange
    condition. Without a size constraint, any authenticated user can upload arbitrarily
    large files, causing unbounded S3 storage and transfer costs.
    """
    findings = []
    for path in _walk_source_files(root):
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if not _PRESIGNED_URL_HINTS.search(text):
            continue
        if _CONTENT_LENGTH_HINTS.search(text):
            continue
        findings.append({
            "severity": "MEDIUM",
            "rule": "storage.presigned_url_no_size_limit",
            "title": "S3 presigned upload URL generated without ContentLengthRange constraint",
            "file": rel,
            "line": 0,
            "excerpt": "(getSignedUrl found; no ContentLengthRange condition detected)",
            "tell_cursor": (
                f"`{rel}` generates a presigned S3 upload URL with no file size limit. "
                "An authenticated user can upload arbitrarily large files, causing unbounded "
                "storage costs and potential denial-of-service. Add a ContentLengthRange "
                "condition to the presigned POST policy (requires switching from presigned "
                "PUT to presigned POST). Example: `Conditions: [['content-length-range', 1, 10485760]]` "
                "limits uploads to 10MB. Set the limit appropriate to the field "
                "(e.g. 10MB for patient photos, 1MB for signatures)."
            ),
        })
    return findings


# ---- Debug / internal endpoints without auth (CWE-306, OWASP A07) ----

_DEBUG_ROUTE_NAME_RE = re.compile(
    r"(?:^|[/\\])(?:debug|test-?api|internal|health-?check|admin-?test|diag(?:nostic)?s?|"
    r"env-?(?:check|debug|info)|ping|whoami|info)\.[tj]sx?$",
    re.IGNORECASE,
)
_ROUTE_AUTH_GUARD_RE = re.compile(
    r"(?:authorization|Bearer|getUser|verifyJWT|resolveCallerFromToken|"
    r"getServerSession|session\s*\?\.|req\.user\b|authenticate|isAuthenticated)",
    re.IGNORECASE,
)


def _check_debug_endpoints(root: Path):
    """Flag API route files whose filename matches debug/internal patterns but contain
    no authentication check. These endpoints commonly expose environment state, stack
    traces, or internal data to unauthenticated callers.
    (CWE-306: Missing Authentication for Critical Function, OWASP A07)
    """
    api_dirs = [root / "pages" / "api", root / "app" / "api"]
    findings = []
    for api_dir in api_dirs:
        if not api_dir.exists():
            continue
        for path in api_dir.rglob("*"):
            if path.is_dir():
                continue
            if path.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx"}:
                continue
            rel = str(path.relative_to(root))
            if not _DEBUG_ROUTE_NAME_RE.search(rel.replace("\\", "/")):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if _ROUTE_AUTH_GUARD_RE.search(text):
                continue
            findings.append({
                "severity": "HIGH",
                "rule": "auth.debug_endpoint_no_auth",
                "title": f"Debug/internal endpoint `{rel}` has no authentication guard",
                "file": rel,
                "line": 0,
                "excerpt": "(route filename matches debug/internal pattern; no auth check detected)",
                "tell_cursor": (
                    f"`{rel}` appears to be a debug or internal diagnostic endpoint but has no "
                    "authentication check. These routes commonly expose environment variables, "
                    "stack traces, or internal state to any unauthenticated caller. "
                    "Either delete the endpoint if it is no longer needed (preferred), or add "
                    "authentication: verify a Bearer token or server session before returning any "
                    "information. Never ship debug endpoints to production without auth gates. "
                    "(CWE-306: Missing Authentication for Critical Function)"
                ),
            })
    return findings


# ---- Verbose error / stack trace in API response (CWE-200, OWASP A05) ----

_VERBOSE_ERROR_RE = re.compile(
    r"(?:json|send)\s*\(\s*\{[^}]{0,300}(?:stack|err\.stack|error\.stack)\s*:",
    re.IGNORECASE | re.DOTALL,
)
_RAW_ERROR_SEND_RE = re.compile(
    r"res\.(?:json|send)\s*\(\s*(?:err|error|exception|e)\s*\)",
    re.IGNORECASE,
)


def _check_verbose_error_responses(root: Path):
    """Flag API route files that appear to send stack traces or raw error objects
    back to HTTP clients. Stack traces expose file paths, dependency versions, and
    internal logic — all valuable to an attacker profiling the application.
    (CWE-200: Exposure of Sensitive Information, OWASP A05 Security Misconfiguration)
    """
    api_dirs = [root / "pages" / "api", root / "app" / "api"]
    findings = []
    for api_dir in api_dirs:
        if not api_dir.exists():
            continue
        for path in api_dir.rglob("*"):
            if path.is_dir():
                continue
            if path.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx"}:
                continue
            rel = str(path.relative_to(root))
            if _is_likely_test_file(rel):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            hit = _VERBOSE_ERROR_RE.search(text) or _RAW_ERROR_SEND_RE.search(text)
            if not hit:
                continue
            findings.append({
                "severity": "HIGH",
                "rule": "info_exposure.verbose_error_in_response",
                "title": f"Possible stack trace or raw error object sent in API response: `{rel}`",
                "file": rel,
                "line": 0,
                "excerpt": hit.group(0)[:200],
                "tell_cursor": (
                    f"`{rel}` appears to return a raw error object or stack trace to the HTTP client. "
                    "Log the full error server-side (Sentry or structured logger), then return "
                    "only a sanitized generic message: "
                    "`res.status(500).json({{ error: 'Internal server error' }})`. "
                    "Stack traces expose your file system layout, library versions, and internal "
                    "logic — directly useful to an attacker profiling your application. "
                    "(CWE-200: Exposure of Sensitive Information)"
                ),
            })
    return findings


# ---- Next.js version check — CVE-2025-29927 (CVSS 9.1 Critical) ----

def _check_nextjs_vulnerable_version(root: Path):
    """Check if the declared Next.js version is vulnerable to CVE-2025-29927,
    a critical middleware authorization bypass (CVSS 9.1). Adding a single header
    (`x-middleware-subrequest`) to any request causes middleware to be skipped entirely,
    bypassing all auth checks, HSTS, CSP, and other middleware-applied security.
    Affected: 11.1.4–13.5.8, 14.x < 14.2.25, 15.x < 15.2.3.
    Patched: 12.3.5, 13.5.9, 14.2.25, 15.2.3.
    """
    pkg = root / "package.json"
    if not pkg.exists():
        return []
    try:
        text = pkg.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(text)
    except Exception:
        return []

    next_version_str = (
        (data.get("dependencies") or {}).get("next") or
        (data.get("devDependencies") or {}).get("next")
    )
    if not next_version_str:
        return []

    clean = re.sub(r"^[^0-9]*", "", next_version_str).strip()
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", clean)
    if not m:
        return []

    try:
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    except ValueError:
        return []

    is_vulnerable = False
    if major == 15 and (minor, patch) < (2, 3):
        is_vulnerable = True
    elif major == 14 and (minor, patch) < (2, 25):
        is_vulnerable = True
    elif major == 13 and (minor, patch) < (5, 9):
        is_vulnerable = True
    elif major == 12 and (minor, patch) < (3, 5):
        is_vulnerable = True
    elif major <= 11:
        is_vulnerable = True

    if not is_vulnerable:
        return []

    patched_map = {15: "15.2.3", 14: "14.2.25", 13: "13.5.9", 12: "12.3.5"}
    patched = patched_map.get(major, "latest")

    return [{
        "severity": "CRITICAL",
        "rule": "cve.nextjs_cve_2025_29927",
        "title": f"Next.js {clean} is vulnerable to CVE-2025-29927 — middleware auth bypass (CVSS 9.1)",
        "file": "package.json",
        "line": 0,
        "excerpt": f'"next": "{next_version_str}" — patched version: {patched}',
        "tell_cursor": (
            f"Upgrade Next.js to {patched} or later immediately. "
            "CVE-2025-29927 (CVSS 9.1 Critical) allows an unauthenticated attacker to bypass "
            "ALL middleware-based authentication and authorization by adding a single request "
            "header (`x-middleware-subrequest`). Login walls, role checks, and security headers "
            "applied via middleware are completely bypassed with no logging or error. "
            f"Run: `npm install next@{patched}` "
            "Temporary mitigation if upgrade is not immediately possible: block the "
            "`x-middleware-subrequest` header at your WAF, CDN (Vercel Edge Config / Cloudflare "
            "WAF), or load balancer before it reaches your Next.js server."
        ),
    }]


# ---- Security logging / monitoring absent (OWASP A09, HIPAA §164.312(b)) ----

_LOGGING_LIB_RE = re.compile(
    r"\b(?:@sentry/nextjs|@sentry/node|@sentry/react|sentry|winston|pino|bunyan|morgan|"
    r"dd-trace|datadog|newrelic|new-relic|logtail|axiom|logflare|papertrail|rollbar|"
    r"@logtail|@axiom|@datadog/browser-logs|highlight\.run|betterstack)\b",
    re.IGNORECASE,
)


def _check_security_logging_absent(root: Path):
    """Flag if no structured logging or error-monitoring library is detected in a
    Next.js/web project. Security logging is required by OWASP A09:2021 and HIPAA
    §164.312(b) (Audit Controls) for any system touching ePHI.
    Only fires for Next.js projects (next.config.* or pages/ or app/ directory exists).
    """
    has_nextconfig = (root / "next.config.js").exists() or (root / "next.config.ts").exists()
    has_pages = (root / "pages").exists() or (root / "app").exists()
    if not has_nextconfig and not has_pages:
        return []

    pkg = root / "package.json"
    if pkg.exists():
        try:
            if _LOGGING_LIB_RE.search(pkg.read_text(encoding="utf-8", errors="ignore")):
                return []
        except Exception:
            pass

    # Also check common instrumentation / Sentry config file names
    for fname in [
        "instrumentation.ts", "instrumentation.js",
        "sentry.client.config.ts", "sentry.client.config.js",
        "sentry.server.config.ts", "sentry.server.config.js",
        "sentry.edge.config.ts", "sentry.edge.config.js",
    ]:
        if (root / fname).exists():
            return []

    return [{
        "severity": "HIGH",
        "rule": "monitoring.security_logging_absent",
        "title": "No security logging / error monitoring library detected (OWASP A09)",
        "file": "package.json",
        "line": 0,
        "excerpt": "(no Sentry, Winston, Pino, Datadog, New Relic, Rollbar, or equivalent found)",
        "tell_cursor": (
            "Add structured error logging and monitoring to capture security-relevant events. "
            "For Next.js on Vercel, Sentry is the standard choice: "
            "`npx @sentry/wizard@latest -i nextjs`. "
            "Without monitoring, security incidents — auth failures, injection attempts, "
            "unusual access patterns — are invisible until after damage occurs. "
            "OWASP A09:2021 (Security Logging and Monitoring Failures) cites the absence of "
            "logging as a top-10 risk. HIPAA §164.312(b) (Audit Controls) requires recording "
            "and examining activity in systems that handle ePHI. "
            "At minimum, log: failed auth attempts, authorization failures, input validation "
            "errors, and any access to PHI records."
        ),
    }]


# ---- Session cookie security flags (CWE-614, CWE-1004) ----

_COOKIE_SET_HINTS = re.compile(
    r"(?:res\.setHeader\s*\(\s*['\"]Set-Cookie['\"]|"
    r"\.cookie\s*\(['\"][^'\"]+['\"],\s*[^,]+,\s*\{|"
    r"serialize\s*\(['\"][^'\"]+['\"],\s*[^,]+,\s*\{)",
    re.IGNORECASE,
)
_COOKIE_HTTPONLY_RE = re.compile(r"httpOnly\s*:\s*true", re.IGNORECASE)
_COOKIE_SECURE_RE = re.compile(r"(?<!\w)secure\s*:\s*true", re.IGNORECASE)
_COOKIE_SAMESITE_RE = re.compile(r"sameSite\s*:", re.IGNORECASE)


def _check_session_cookie_flags(root: Path):
    """Flag files that set session/auth cookies without httpOnly, Secure, and SameSite
    flags. Missing flags are a leading cause of session hijacking and CSRF.
    (CWE-614: Sensitive Cookie Without Secure Attribute; CWE-1004: Missing HttpOnly)
    """
    findings = []
    for path in _walk_source_files(root):
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if not _COOKIE_SET_HINTS.search(text):
            continue
        missing = []
        if not _COOKIE_HTTPONLY_RE.search(text):
            missing.append("httpOnly: true")
        if not _COOKIE_SECURE_RE.search(text):
            missing.append("secure: true")
        if not _COOKIE_SAMESITE_RE.search(text):
            missing.append("sameSite: 'Lax'")
        if not missing:
            continue
        findings.append({
            "severity": "HIGH",
            "rule": "auth.cookie_missing_security_flags",
            "title": f"Session cookie set without security flags in `{rel}`",
            "file": rel,
            "line": 0,
            "excerpt": f"(cookie operation detected; missing flags: {', '.join(missing)})",
            "tell_cursor": (
                f"`{rel}` sets a cookie but is missing the following security flags: "
                f"{', '.join(missing)}. "
                "Missing `httpOnly` allows JavaScript to read the session cookie (XSS → session theft). "
                "Missing `secure` allows the cookie over plain HTTP (network interception). "
                "Missing `sameSite` leaves sessions vulnerable to CSRF. "
                "Correct example: `serialize('session', token, {{ httpOnly: true, secure: true, "
                "sameSite: 'Lax', path: '/', maxAge: 1800 }})`. "
                "(CWE-614: Sensitive Cookie Without Secure Attribute)"
            ),
        })
    return findings


# ---- HIPAA §164.312(a)(2)(iii): automatic logoff / session expiry absent ----

_SESSION_TIMEOUT_RE = re.compile(
    r"(?:maxAge|session_?max_?age|sessionTimeout|session_timeout|"
    r"MAX_AGE|SESSION_DURATION|idleTimeout|idle_timeout)\b",
    re.IGNORECASE,
)
_AUTH_RELATED_FILE_RE = re.compile(
    r"(?:auth|session|next-?auth|middleware|login|signin)\.[tj]sx?$",
    re.IGNORECASE,
)


def _check_auto_logoff_absent(root: Path, context: dict):
    """Flag HIPAA-declared projects with no session maxAge / expiry configuration.
    HIPAA §164.312(a)(2)(iii) requires automatic logoff after a defined inactivity period.
    Only fires if HIPAA is declared in project-context.md.
    """
    if not context.get("found"):
        return []
    if "hipaa" not in " ".join(context.get("compliance", [])).lower():
        return []

    for path in _walk_source_files(root):
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        if not _AUTH_RELATED_FILE_RE.search(rel.replace("\\", "/")):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if _SESSION_TIMEOUT_RE.search(text):
            return []

    return [{
        "severity": "HIGH",
        "rule": "hipaa.auto_logoff_absent",
        "title": "HIPAA project: no session expiry / automatic logoff configuration detected",
        "file": "(auth config files)",
        "line": 0,
        "excerpt": "(no maxAge / sessionTimeout / idleTimeout found in auth-related files)",
        "tell_cursor": (
            "HIPAA §164.312(a)(2)(iii) requires automatic logoff after a period of inactivity "
            "for systems handling ePHI. No session timeout was found in auth-related files. "
            "For NextAuth.js: add `session: {{ maxAge: 1800 }}` (30 minutes) in your auth config. "
            "For custom JWT: include an `exp` claim and validate it on every request. "
            "Also implement a client-side inactivity timer that logs out after 15–30 minutes "
            "of no interaction (standard for clinical systems). "
            "Document the chosen timeout in project-context.md under HIGH_RISK_FEATURES."
        ),
    }]


# ---- HIPAA §164.312(e)(1): Cache-Control: no-store absent on API routes ----

_CACHE_NOSTORE_RE = re.compile(r"no.?store", re.IGNORECASE)
_CACHE_HEADER_SET_RE = re.compile(
    r"(?:setHeader|headers)\s*\([^)]*Cache-Control",
    re.IGNORECASE,
)


def _check_phi_no_cache_control(root: Path, context: dict):
    """Flag HIPAA-declared projects where API routes do not set Cache-Control: no-store.
    PHI responses cached by proxies, CDNs, or browser disk caches violate data integrity
    and transmission security requirements.
    HIPAA §164.312(e)(1) — Transmission Security; §164.312(c)(1) — Integrity.
    Only fires if HIPAA is declared in project-context.md.
    """
    if not context.get("found"):
        return []
    if "hipaa" not in " ".join(context.get("compliance", [])).lower():
        return []

    api_dirs = [root / "pages" / "api", root / "app" / "api"]
    routes_checked = 0
    routes_missing = []

    for api_dir in api_dirs:
        if not api_dir.exists():
            continue
        for path in api_dir.rglob("*"):
            if path.is_dir():
                continue
            if path.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx"}:
                continue
            rel = str(path.relative_to(root))
            if _is_likely_test_file(rel):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            routes_checked += 1
            has_header = _CACHE_HEADER_SET_RE.search(text)
            has_nostore = _CACHE_NOSTORE_RE.search(text)
            if has_header and has_nostore:
                continue
            routes_missing.append(rel)

    if not routes_checked or not routes_missing:
        return []

    # Only fire if a meaningful fraction of routes are missing the header
    if len(routes_missing) < max(2, routes_checked // 3):
        return []

    return [{
        "severity": "HIGH",
        "rule": "hipaa.phi_no_cache_control",
        "title": "HIPAA project: API routes missing Cache-Control: no-store",
        "file": routes_missing[0] if len(routes_missing) == 1 else "(multiple API routes)",
        "line": 0,
        "excerpt": f"({len(routes_missing)} of {routes_checked} API routes lack Cache-Control: no-store)",
        "tell_cursor": (
            f"{len(routes_missing)} of {routes_checked} API routes do not set "
            "`Cache-Control: no-store`. For a HIPAA application, all API responses returning ePHI "
            "must prevent caching by proxies, CDNs, and browser disk caches. "
            "Add to every API route handler: "
            "`res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private')` "
            "or apply it globally in middleware.ts. "
            "(HIPAA §164.312(e)(1) — Transmission Security; §164.312(c)(1) — Integrity)"
        ),
    }]


# ---- Next.js: X-Powered-By header not suppressed ----

def _check_powered_by_header(root: Path):
    """Flag Next.js projects that do not disable the X-Powered-By: Next.js response header.
    This header reveals the framework name and version, enabling targeted attacks against
    known CVEs. Check for `poweredByHeader: false` in next.config.js / next.config.ts.
    """
    for fname in ["next.config.js", "next.config.ts"]:
        f = root / fname
        if not f.exists():
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
            if re.search(r"poweredByHeader\s*:\s*false", text):
                return []
        except Exception:
            pass
        # next.config.js exists but poweredByHeader: false not found
        return [{
            "severity": "LOW",
            "rule": "misconfig.powered_by_header_not_disabled",
            "title": "Next.js `poweredByHeader` not disabled — X-Powered-By header leaks framework identity",
            "file": fname,
            "line": 0,
            "excerpt": "(`poweredByHeader: false` not found in next.config.js)",
            "tell_cursor": (
                "Add `poweredByHeader: false` to the exported config object in next.config.js. "
                "This suppresses the `X-Powered-By: Next.js` response header, which reveals your "
                "framework and aids attackers in targeting known CVEs (e.g. CVE-2025-29927). "
                "Fix: `const nextConfig = {{ poweredByHeader: false, ... }}; export default nextConfig;`. "
                "Note: Vercel automatically removes this header on Pro/Enterprise plans, but "
                "disabling it at the framework level is a defense-in-depth best practice."
            ),
        }]
    return []


# ---- Permissions audit (OWASP Mobile M6 Privacy Controls) ----

DANGEROUS_IOS_USAGE_KEYS = [
    "NSCameraUsageDescription", "NSMicrophoneUsageDescription",
    "NSLocationWhenInUseUsageDescription", "NSLocationAlwaysAndWhenInUseUsageDescription",
    "NSLocationAlwaysUsageDescription",
    "NSContactsUsageDescription", "NSPhotoLibraryUsageDescription", "NSPhotoLibraryAddUsageDescription",
    "NSCalendarsUsageDescription", "NSRemindersUsageDescription",
    "NSAppleMusicUsageDescription", "NSMotionUsageDescription",
    "NSHealthShareUsageDescription", "NSHealthUpdateUsageDescription",
    "NSFaceIDUsageDescription", "NSBluetoothAlwaysUsageDescription", "NSBluetoothPeripheralUsageDescription",
    "NSSpeechRecognitionUsageDescription", "NSLocalNetworkUsageDescription",
    "NSUserTrackingUsageDescription",
]

DANGEROUS_ANDROID_PERMISSIONS = [
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS", "android.permission.GET_ACCOUNTS",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO", "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE",
    "android.permission.SEND_SMS", "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.BODY_SENSORS", "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.BLUETOOTH_SCAN", "android.permission.BLUETOOTH_ADVERTISE", "android.permission.BLUETOOTH_CONNECT",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.SYSTEM_ALERT_WINDOW",
]


def _check_permissions_audit(root: Path):
    """Scan Info.plist, AndroidManifest.xml, and Expo app.json for dangerous permissions.
    Each requested dangerous permission becomes a MEDIUM finding asking the developer to
    confirm justification in project-context.md HIGH_RISK_FEATURES and document for store
    privacy labels.
    """
    findings = []

    # Native iOS Info.plist
    for plist in root.rglob("Info.plist"):
        if any(part in SKIP_DIRS for part in plist.parts):
            continue
        try:
            text = plist.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(plist.relative_to(root))
        for key in DANGEROUS_IOS_USAGE_KEYS:
            if f"<key>{key}</key>" in text:
                findings.append({
                    "severity": "MEDIUM",
                    "rule": "privacy.dangerous_ios_permission",
                    "title": f"iOS dangerous permission requested: {key}",
                    "file": rel,
                    "line": 0,
                    "excerpt": f"<key>{key}</key>",
                    "tell_cursor": (
                        f"Confirm `{key}` is required by a declared feature in `project-context.md` → "
                        f"`HIGH_RISK_FEATURES`. Apple App Store review scrutinizes dangerous permissions; "
                        f"without a clear in-app justification, the submission can be rejected. Also surface "
                        f"this in the Apple App Store Privacy Labels before TestFlight submission."
                    ),
                })

    # Native Android manifest
    for manifest in root.rglob("AndroidManifest.xml"):
        if any(part in SKIP_DIRS for part in manifest.parts):
            continue
        try:
            text = manifest.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(manifest.relative_to(root))
        for perm in DANGEROUS_ANDROID_PERMISSIONS:
            if perm in text:
                findings.append({
                    "severity": "MEDIUM",
                    "rule": "privacy.dangerous_android_permission",
                    "title": f"Android dangerous permission requested: {perm.split('.')[-1]}",
                    "file": rel,
                    "line": 0,
                    "excerpt": f"<uses-permission android:name=\"{perm}\" />",
                    "tell_cursor": (
                        f"Confirm `{perm}` is required by a declared feature in `project-context.md` → "
                        f"`HIGH_RISK_FEATURES`. Document this permission in the Google Play Data Safety Form "
                        f"before Play Console submission."
                    ),
                })

    # Expo app.json (managed config)
    app_json = root / "app.json"
    if app_json.exists():
        try:
            data = json.loads(app_json.read_text(encoding="utf-8", errors="ignore"))
            expo = data.get("expo", {}) if isinstance(data, dict) else {}
            ios_keys = (expo.get("ios", {}) or {}).get("infoPlist", {}) or {}
            for key in ios_keys:
                if key in DANGEROUS_IOS_USAGE_KEYS:
                    findings.append({
                        "severity": "MEDIUM",
                        "rule": "privacy.dangerous_ios_permission",
                        "title": f"iOS dangerous permission declared in app.json: {key}",
                        "file": "app.json",
                        "line": 0,
                        "excerpt": f"{key}: {str(ios_keys[key])[:120]}",
                        "tell_cursor": (
                            f"Confirm `{key}` is required by a declared feature in `project-context.md` → "
                            f"`HIGH_RISK_FEATURES`. Document this in the Apple App Store Privacy Labels."
                        ),
                    })
            android_perms = (expo.get("android", {}) or {}).get("permissions", []) or []
            for perm in android_perms:
                if not isinstance(perm, str):
                    continue
                full_perm = perm if perm.startswith("android.permission.") else f"android.permission.{perm}"
                if full_perm in DANGEROUS_ANDROID_PERMISSIONS:
                    findings.append({
                        "severity": "MEDIUM",
                        "rule": "privacy.dangerous_android_permission",
                        "title": f"Android dangerous permission declared in app.json: {perm}",
                        "file": "app.json",
                        "line": 0,
                        "excerpt": f"android.permissions: {perm}",
                        "tell_cursor": (
                            f"Confirm `{perm}` is required by a declared feature in `project-context.md` → "
                            f"`HIGH_RISK_FEATURES`. Document this in the Google Play Data Safety Form."
                        ),
                    })
        except (json.JSONDecodeError, Exception):
            pass

    return findings


# ====================================================================
# Pass 2 — context gathering for LLM judgment
# ====================================================================

API_ROUTE_PATTERNS = [
    re.compile(r"app/api/.*\.(ts|tsx|js|jsx)$"),
    re.compile(r"pages/api/.*\.(ts|tsx|js|jsx)$"),
    re.compile(r"app\.(get|post|put|patch|delete)\s*\("),
    re.compile(r"router\.(get|post|put|patch|delete)\s*\("),
    re.compile(r"export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\b"),
]

DB_QUERY_HINTS = re.compile(
    r"\b(supabase|prisma|drizzle|mongoose|knex)\b\.\w+|\.from\(['\"][a-z_]+['\"]\)|\bfindMany\(|\bfindUnique\(",
    re.IGNORECASE,
)

UPLOAD_HINTS = re.compile(
    r"\b(multer|formidable|busboy|FormData|multipart/form-data|expo-image-picker|react-native-image-picker)\b",
    re.IGNORECASE,
)


def _gather_api_routes(root: Path, max_routes: int = 100, head_lines: int = 25):
    routes = []
    for path in _walk_source_files(root):
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        is_route_file = any(p.search(rel) for p in API_ROUTE_PATTERNS[:2])
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        has_route_handler = any(p.search(text) for p in API_ROUTE_PATTERNS[2:])
        if not (is_route_file or has_route_handler):
            continue
        head = "\n".join(text.splitlines()[:head_lines])
        routes.append({
            "file": rel,
            "head": head,
            "needs_judgment_on": [
                "auth_check_at_top_of_handler",
                "ownership_filter_on_db_queries",
                "server_side_input_validation",
                "no_user_id_accepted_from_request_body_without_session_match",
            ],
        })
        if len(routes) >= max_routes:
            break
    return routes


def _gather_db_query_sites(root: Path, max_sites: int = 30):
    sites = []
    for path in _walk_source_files(root):
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line_num, line in enumerate(text.splitlines(), start=1):
            if DB_QUERY_HINTS.search(line):
                sites.append({"file": rel, "line": line_num, "excerpt": line.strip()[:200]})
                if len(sites) >= max_sites:
                    return sites
    return sites


def _gather_upload_sites(root: Path):
    sites = []
    for path in _walk_source_files(root):
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line_num, line in enumerate(text.splitlines(), start=1):
            if UPLOAD_HINTS.search(line):
                sites.append({"file": rel, "line": line_num, "excerpt": line.strip()[:200]})
    return sites


# Form-handler discovery — surfaces files that handle user input via forms so the
# calling LLM can judge validation, sanitization, and downstream-sink safety.
FORM_HINTS = re.compile(
    r"\b(useForm|Formik|<Form\b|FormData|react-hook-form|@hookform|zodResolver|yupResolver|joi\.object|"
    r"validation\s*:\s*\{|schema\s*:\s*z\.|schema\s*:\s*Yup\.)",
    re.IGNORECASE,
)
TEXT_INPUT_HINT = re.compile(r"<TextInput\b|<Input\b", re.IGNORECASE)


def _gather_form_handlers(root: Path, max_sites: int = 30, head_lines: int = 30):
    sites = []
    for path in _walk_source_files(root):
        rel = str(path.relative_to(root))
        if _is_likely_test_file(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        has_form = bool(FORM_HINTS.search(text))
        has_input = bool(TEXT_INPUT_HINT.search(text))
        if not (has_form or has_input):
            continue
        head = "\n".join(text.splitlines()[:head_lines])
        sites.append({
            "file": rel,
            "head": head,
            "has_form_library": has_form,
            "has_text_input": has_input,
            "needs_judgment_on": [
                "client_side_schema_validation_present",
                "server_side_validation_on_submit_endpoint",
                "input_sanitization_before_render_or_storage",
                "no_dangerous_sink_for_unsanitized_input",
                "rate_limiting_or_captcha_on_public_endpoints (if any)",
            ],
        })
        if len(sites) >= max_sites:
            break
    return sites


# ====================================================================
# Pass 2 — carry-over detection (read prior reports)
# ====================================================================

def _list_prior_reports_for_project(audits_dir: Path, fingerprint: str):
    """List all prior audit reports in audits_dir whose embedded project fingerprint
    matches the current scan's fingerprint. Excludes verification reports.
    Returns list of dicts: {path, scanned, trigger, fingerprint_matches, raw_text}.
    """
    if not audits_dir.exists() or not audits_dir.is_dir():
        return []
    out = []
    for p in sorted(audits_dir.glob("*.md")):
        name = p.name
        if "-verification-" in name:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        prior_fp = _extract_fingerprint_from_report(text)
        # If a report has no fingerprint (legacy / external), don't auto-mix it.
        # We surface it but mark it as unverified.
        out.append({
            "path": str(p),
            "filename": name,
            "fingerprint": prior_fp,
            "fingerprint_matches": (prior_fp == fingerprint) if prior_fp else False,
            "is_legacy": prior_fp is None,
            "raw_text": text,
        })
    return out


def _detect_carry_over(prior_reports, current_findings, root: Path):
    """For each prior fingerprint-matched report, parse its findings, then check
    whether each finding's original excerpt is still present in the codebase. If yes,
    it's carry-over (still unresolved or reintroduced). If a verification report
    PASSED a finding, exclude it unless the original anti-pattern returned.

    Currently a best-effort check based on excerpt grep. Returns list of carry-over entries.
    """
    carry = []
    seen_titles = set()  # avoid surfacing same finding twice across multiple priors

    for r in prior_reports:
        if not r["fingerprint_matches"]:
            continue
        prior_findings = _parse_prior_report(r["raw_text"])
        for f in prior_findings:
            key = (f["title"], f.get("file") or "")
            if key in seen_titles:
                continue
            excerpt = f.get("excerpt")
            file_rel = f.get("file")
            if not file_rel or not excerpt:
                continue
            full = root / file_rel
            if not full.exists() or not full.is_file():
                continue
            try:
                text = full.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if excerpt in text:
                carry.append({
                    "from_report": r["filename"],
                    "severity": f.get("severity"),
                    "title": f.get("title"),
                    "file": file_rel,
                    "line": f.get("line"),
                    "excerpt": excerpt,
                })
                seen_titles.add(key)
    return carry


# ====================================================================
# Pass 2 — report writer
# ====================================================================

REPORT_TEMPLATE = """\
# CODE SLOP & SECURITY AUDIT REPORT

- **Project:** {project_name}
- **Project path:** `{project_path}`
- **Project fingerprint:** `{fingerprint}`
- **Scanned:** {scanned_at}
- **Trigger:** {trigger}
- **Git HEAD:** {git_head}{git_branch_note}{git_dirty_note}
- **Sensitive fields audited:** {fields_str}
- **Files scanned:** {files_scanned}
- **project-context.md:** {context_status}
- **Generated by:** Sentinel MCP (deterministic Pass 2 + LLM judgment layer)

---

## Summary
- CRITICAL: {n_critical}
- HIGH: {n_high}
- MEDIUM: {n_medium}
- LOW: {n_low}
- Carry-over from prior audits: {n_carry}
- Awaiting LLM judgment (see "Pending Manual Review" below): {n_pending}

---

## CARRY-OVER FROM PRIOR AUDITS

These findings appeared in earlier audits and are still present in the current codebase
(based on excerpt grep). The calling LLM should verify whether they are actually unresolved
or whether the excerpt match is a false positive (e.g., the line moved to a different file).

{carry_block}

---

## CRITICAL ISSUES
{critical_block}

## HIGH ISSUES
{high_block}

## MEDIUM ISSUES
{medium_block}

## LOW ISSUES
{low_block}

---

## CANNOT CHECK — requires runtime or infrastructure inspection

The following security properties are **outside the scope of static code analysis**.
Sentinel cannot detect them by reading source files alone.
They require live testing, infrastructure inspection, or runtime observation.

| # | Category | What to Check | How to Check |
|---|---|---|---|
| 1 | TLS certificate validity | Expired or mismatched certificate | `openssl s_client -connect your-domain.com:443` or SSL checker |
| 2 | Cipher suite / protocol strength | TLS 1.0/1.1 enabled; RC4, DES, export ciphers | Qualys SSL Labs — ssllabs.com/ssltest/ |
| 3 | Open ports / exposed services | Unexpected services reachable from internet | `nmap -sV` or Shodan |
| 4 | Runtime rate limit enforcement | Whether limits actually fire under burst traffic | Artillery / k6 load test on auth and data routes |
| 5 | Account lockout behavior | Lockout after N failed login attempts | Automated brute-force test (Hydra / custom script) |
| 6 | Actual MFA enforcement | Whether MFA prompts on all code paths | Manual QA walkthrough; bypass via direct API test |
| 7 | Session cookie flags at runtime | HttpOnly, Secure, SameSite headers on Set-Cookie | Browser DevTools → Network tab; `curl -I` |
| 8 | Session timeout actual behavior | Whether idle sessions expire server-side | Login, wait N minutes, attempt to use token |
| 9 | Business logic flaws | Workflow bypasses, replay attacks, IDOR via normal flows | Manual penetration test / threat modeling |
| 10 | Subdomain enumeration | Exposed staging / dev / internal subdomains | `subfinder`, `amass`, or equivalent |
| 11 | DNS security (SPF, DMARC, DNSSEC) | Email spoofing, DNS hijacking | MXToolbox / DMARC Analyzer |
| 12 | Actual secret values in CI/CD | Live key leakage in CI logs or environment | truffleHog on logs; CI/CD settings audit |
| 13 | CDN / WAF edge configuration | Security headers applied at Vercel edge | Vercel Dashboard → Project Settings → Security |
| 14 | Third-party BaaS security config | Supabase RLS actually ON; public bucket policies | Supabase Dashboard → Auth / Storage; AWS S3 console |
| 15 | HTTP response body PHI leakage | Whether real PHI appears in actual API responses | Manual API test with real session; DAST scan |
| 16 | Content-Security-Policy effectiveness | Whether CSP actually blocks injection in browser | CSP Evaluator — csp-evaluator.withgoogle.com |
| 17 | Dependency license compliance | GPL/AGPL conflicts in commercial product | `npx license-checker` or FOSSA |

---

## PENDING MANUAL REVIEW (judgment-laden checks)

The deterministic scanner identifies *where* judgment is needed but cannot make the call alone.
The calling LLM should review the items below and append findings to this report under the
appropriate severity heading above. Items requiring runtime verification (actual HTTP requests,
real device testing, dashboard checks) should be called out separately.

### API routes detected ({n_routes} files)
For each route, judge:
- Auth/session check at the top of the handler?
- Admin-only routes verifying user role (not just login)?
- DB queries inside the handler filtering by current user's ID?
- Handler accepting a user ID from request body / URL without verifying session match?
- Server-side input validation present?

{routes_block}

### Database query sites ({n_db})
For each, judge whether ownership filtering (user_id / org_id / etc.) is applied.

{db_block}

### File-upload sites ({n_upload})
For each, judge whether server-side MIME type and size validation exists.

{upload_block}

### Form handlers ({n_forms})
For each, judge: client-side schema validation present? Server-side validation on the submit
endpoint? Input sanitization before any rendering or storage? No dangerous sink (eval, dangerouslySetInnerHTML,
SQL concat, deep-link constructed from input) for unsanitized input? Rate limiting / captcha on public-facing
forms (signup, password reset, contact)?

{forms_block}

---

## PASSED CHECKS (deterministic)
{passed_block}

---

## PROJECT-CONTEXT REMINDERS

These are declared in project-context.md and are not statically verifiable. Surface them
to the developer as items needing manual / runtime confirmation per audit.

### USER_ROLES
{roles_block}

### COMPLIANCE_REQUIREMENTS
{compliance_block}

### HIGH_RISK_FEATURES
{high_risk_block}

---

## SUGGESTED AUDIT HISTORY ENTRY for project-context.md

Append this line to the AUDIT HISTORY table in project-context.md once findings are triaged:

| {today} | {trigger} | {n_critical} Critical · {n_high} High · {n_medium} Medium | _(pending verdict)_ |
"""


def _format_finding_block(findings):
    if not findings:
        return "_None._\n"
    lines = []
    for f in findings:
        lines.append(f"### {f['title']}")
        lines.append(f"- **File:** `{f['file']}`" + (f" (line {f['line']})" if f.get("line") else ""))
        lines.append(f"- **Rule:** `{f['rule']}`")
        if f.get("excerpt"):
            lines.append(f"- **Excerpt:** `{f['excerpt']}`")
        lines.append(f"- **Tell Cursor:** {f['tell_cursor']}")
        lines.append("")
    return "\n".join(lines)


def _format_routes_block(routes):
    if not routes:
        return "_No API route files detected._\n"
    parts = []
    for r in routes:
        parts.append(f"#### `{r['file']}`")
        parts.append("```")
        parts.append(r["head"])
        parts.append("```")
        parts.append("")
    return "\n".join(parts)


def _format_forms_block(forms):
    if not forms:
        return "_No form handlers detected._\n"
    parts = []
    for f in forms:
        flags = []
        if f.get("has_form_library"):
            flags.append("form-library")
        if f.get("has_text_input"):
            flags.append("text-input")
        flag_str = f" — {', '.join(flags)}" if flags else ""
        parts.append(f"#### `{f['file']}`{flag_str}")
        parts.append("```")
        parts.append(f["head"])
        parts.append("```")
        parts.append("")
    return "\n".join(parts)


def _format_simple_sites_block(sites):
    if not sites:
        return "_None detected._\n"
    parts = []
    for s in sites:
        parts.append(f"- `{s['file']}:{s['line']}` — `{s['excerpt']}`")
    return "\n".join(parts) + "\n"


def _format_carry_block(carry):
    if not carry:
        return "_No carry-over detected._\n"
    parts = []
    for c in carry:
        parts.append(f"### [{c['severity']}] {c['title']}")
        parts.append(f"- **File:** `{c['file']}`" + (f" (line {c['line']})" if c.get("line") else ""))
        parts.append(f"- **From prior report:** `{c['from_report']}`")
        parts.append(f"- **Excerpt still present:** `{c['excerpt']}`")
        parts.append("")
    return "\n".join(parts)


def _format_list_block(items):
    if not items:
        return "_None declared._\n"
    return "\n".join(f"- {item}" for item in items) + "\n"


def _build_passed_block(passed_checks):
    if not passed_checks:
        return "_No deterministic checks passed cleanly._\n"
    return "\n".join(f"- {p}" for p in passed_checks) + "\n"


# ====================================================================
# Pass 2 — main tool
# ====================================================================

@mcp.tool()
def sentinel_pass2_audit(
    project_path: str,
    confirmed_fields: list[str] = [],
    trigger_label: str = "ad-hoc",
    audits_dir: str = "",
) -> str:
    """Run the full Sentinel Pass 2 audit. Performs deterministic checks (hardcoded
    secrets, .gitignore coverage, file size, TS `any` overuse, sensitive-field logging,
    sensitive-fields-in-URLs), plus project-context-driven checks (AsyncStorage usage
    of fields requiring SecureStore, sensitive fields in analytics/error-reporter calls).
    Gathers context (API routes, DB queries, upload sites) for the calling LLM to apply
    judgment-laden checks. Detects carry-over by scanning prior audit reports in audits_dir
    for findings whose excerpt is still present in the current codebase.

    Embeds a project fingerprint (derived from project_path + project-context.md hash) in
    every report. Pass 3 verifies the fingerprint match before operating, preventing audit
    history from one project being applied to another.

    Auto-loads project-context.md from {project_path}/project-context.md when present.
    Declared SENSITIVE_FIELDS are merged with confirmed_fields. USER_ROLES,
    COMPLIANCE_REQUIREMENTS, and HIGH_RISK_FEATURES are surfaced in the report as
    project-context reminders.

    Args:
        project_path: Absolute path to the project root being audited.
        confirmed_fields: Sensitive field names confirmed in Pass 1, merged with
            project-context.md SENSITIVE_FIELDS. Pass [] to use only project-context.
        trigger_label: Short label for this audit. Recommended values:
            'baseline', 'auth-touched', 'secrets-touched', 'storage-touched',
            'networking-touched', 'permissions-touched', 'deeplink-touched',
            'webview-touched', 'sdk-added', 'pre-push', 'pre-release', 'weekly-cadence',
            'ad-hoc'. Free-form strings are accepted.
        audits_dir: Optional absolute path to where the report should be saved.
            Defaults to {project_path}/audits/. The carry-over scan reads prior reports
            from this directory.
    """
    root = Path(project_path).expanduser().resolve()
    if not root.exists():
        return json.dumps({"error": f"Path does not exist: {root}"}, indent=2)
    if not root.is_dir():
        return json.dumps({"error": f"Path is not a directory: {root}"}, indent=2)

    audits_root = Path(audits_dir).expanduser().resolve() if audits_dir else (root / "audits")

    # --- Load project context ---
    context = _load_project_context(root)
    declared_field_names = _sensitive_field_short_names(context["sensitive_fields"]) if context["found"] else []
    merged_fields = sorted(set(list(confirmed_fields or []) + declared_field_names))

    # --- Compute project fingerprint ---
    fingerprint = _compute_project_fingerprint(root, context)

    # --- Capture git state ---
    git = _capture_git_state(root)

    # --- Run deterministic checks ---
    findings = []
    passed = []

    sec = _check_hardcoded_secrets(root)
    findings.extend(sec)
    if not sec:
        passed.append("No hardcoded secrets matched known provider patterns or generic credential assignments.")

    env_check = _check_env_in_gitignore(root)
    findings.extend(env_check)
    if not env_check:
        passed.append(".gitignore covers .env, .env.local, .env.production.")

    size = _check_file_size(root)
    findings.extend(size)
    if not size:
        passed.append("No source files exceed 200 lines.")

    any_overuse = _check_any_overuse(root)
    findings.extend(any_overuse)
    if not any_overuse:
        passed.append("No TypeScript files have excessive `any` usage (threshold: 5).")

    log_leak = _check_sensitive_logging(root, merged_fields)
    findings.extend(log_leak)
    if not log_leak and merged_fields:
        passed.append("No console.log/warn/error/info/debug calls reference confirmed/declared sensitive fields.")

    url_leak = _check_sensitive_in_urls(root, merged_fields)
    findings.extend(url_leak)
    if not url_leak and merged_fields:
        passed.append("No URL strings contain confirmed/declared sensitive field names.")

    # --- Project-context-driven checks (only when project-context.md exists) ---
    ctx_findings_count = 0
    if context["found"]:
        secure_storage = _check_async_storage_for_tokens(root, context["sensitive_fields"])
        findings.extend(secure_storage)
        ctx_findings_count += len(secure_storage)
        if not secure_storage:
            passed.append("No AsyncStorage usage of fields requiring SecureStore/Keychain (per project-context).")

        analytics = _check_analytics_scrubbing(root, context["sensitive_fields"])
        findings.extend(analytics)
        ctx_findings_count += len(analytics)
        if not analytics:
            passed.append("No analytics/error-reporter calls leak fields requiring scrubbing (per project-context).")

    # --- Injection-safety & unsafe patterns (OWASP Mobile M4) ---
    injection_hits = _check_injection_safety(root)
    findings.extend(injection_hits)
    if not injection_hits:
        passed.append(
            "No injection / unsafe-pattern hits: no dangerouslySetInnerHTML, eval, new Function, "
            "string-arg timers, WebView injected JS / HTML source, command-injection patterns, "
            "SQL string-concat or template-literal interpolation, unvalidated Linking.openURL, "
            "weak crypto (MD5/SHA1), Math.random for security material, hardcoded http://, "
            "or wildcard CORS."
        )

    # --- Misconfiguration / debug-flag (OWASP Mobile M8) ---
    misconfig_hits = _check_misconfig(root)
    findings.extend(misconfig_hits)
    if not misconfig_hits:
        passed.append(
            "No misconfiguration hits: no hardcoded localhost URLs, no `debug: true` flags outside "
            "__DEV__ gates, no NSAllowsArbitraryLoads, no Android cleartext traffic enabled."
        )

    # --- Supply chain (OWASP Mobile M2) ---
    supply_hits = _check_lockfile_present(root)
    findings.extend(supply_hits)
    if not supply_hits:
        passed.append("Lockfile present — dependency versions are pinned.")

    # --- npm audit — actual CVE scan of installed dependencies ---
    npm_hits = _check_npm_audit(root)
    findings.extend(npm_hits)
    if not npm_hits:
        passed.append("`npm audit` ran clean — no known vulnerable dependencies.")

    # --- Permissions audit (OWASP Mobile M6) ---
    permission_hits = _check_permissions_audit(root)
    findings.extend(permission_hits)
    if not permission_hits:
        passed.append("No dangerous platform permissions requested (Info.plist, AndroidManifest.xml, app.json).")

    # --- CSRF middleware presence (for projects with state-changing HTTP routes) ---
    csrf_hits = _check_csrf_protection(root)
    findings.extend(csrf_hits)
    if not csrf_hits:
        passed.append("Either no state-changing HTTP routes detected, or CSRF middleware is imported.")

    # --- Screen-capture protection (for projects with sensitive fields) ---
    screen_hits = _check_screen_capture_protection(root, context)
    findings.extend(screen_hits)
    if not screen_hits and context.get("found") and context.get("sensitive_fields"):
        passed.append("Screen-capture/recording protection found in code (sensitive screens can opt in).")

    # --- Security headers (Next.js / web projects) ---
    header_hits = _check_security_headers(root)
    findings.extend(header_hits)
    if not header_hits and ((root / "next.config.js").exists() or (root / "next.config.ts").exists()):
        passed.append("Required security headers (CSP, HSTS, X-Frame-Options, etc.) found in config.")

    # --- Rate limiting ---
    rate_hits = _check_rate_limiting(root)
    findings.extend(rate_hits)
    if not rate_hits:
        passed.append("Rate limiting library detected.")

    # --- middleware.ts presence (Next.js) ---
    mw_hits = _check_nextjs_middleware_absent(root)
    findings.extend(mw_hits)
    if not mw_hits and ((root / "middleware.ts").exists() or (root / "middleware.js").exists()):
        passed.append("middleware.ts present — security headers and rate limiting can be applied globally.")

    # --- Service role key in unauthenticated routes ---
    svc_hits = _check_service_role_in_public_routes(root)
    findings.extend(svc_hits)
    if not svc_hits:
        passed.append("No service role key usage detected in unauthenticated API routes.")

    # --- S3 presigned URLs without size constraints ---
    presigned_hits = _check_presigned_url_no_size_limit(root)
    findings.extend(presigned_hits)
    if not presigned_hits:
        passed.append("S3 presigned URL size constraints detected or no presigned URLs in use.")

    # --- Debug endpoints without authentication (CWE-306) ---
    debug_hits = _check_debug_endpoints(root)
    findings.extend(debug_hits)
    if not debug_hits:
        passed.append("No unauthenticated debug/internal API endpoints detected.")

    # --- Verbose error / stack trace in API responses (CWE-200) ---
    verbose_err_hits = _check_verbose_error_responses(root)
    findings.extend(verbose_err_hits)
    if not verbose_err_hits:
        passed.append("No obvious stack trace or raw error object exposure in API responses.")

    # --- Next.js CVE-2025-29927 (middleware auth bypass, CVSS 9.1) ---
    cve_hits = _check_nextjs_vulnerable_version(root)
    findings.extend(cve_hits)
    if not cve_hits:
        passed.append("Next.js version not vulnerable to CVE-2025-29927 (or not a Next.js project).")

    # --- Security logging / monitoring absent (OWASP A09, HIPAA §164.312(b)) ---
    logging_hits = _check_security_logging_absent(root)
    findings.extend(logging_hits)
    if not logging_hits:
        passed.append("Security logging / monitoring library detected.")

    # --- Session cookie security flags (CWE-614, CWE-1004) ---
    cookie_hits = _check_session_cookie_flags(root)
    findings.extend(cookie_hits)
    if not cookie_hits:
        passed.append("No cookie operations found missing httpOnly/Secure/SameSite flags.")

    # --- HIPAA: automatic logoff / session expiry (§164.312(a)(2)(iii)) ---
    logoff_hits = _check_auto_logoff_absent(root, context)
    findings.extend(logoff_hits)
    if not logoff_hits:
        passed.append("Session expiry / auto-logoff config detected (or HIPAA not declared).")

    # --- HIPAA: Cache-Control no-store on API routes (§164.312(e)(1)) ---
    cache_hits = _check_phi_no_cache_control(root, context)
    findings.extend(cache_hits)
    if not cache_hits:
        passed.append("Cache-Control: no-store present on API routes (or HIPAA not declared).")

    # --- Next.js powered-by header not suppressed ---
    powered_by_hits = _check_powered_by_header(root)
    findings.extend(powered_by_hits)
    if not powered_by_hits:
        passed.append("Next.js poweredByHeader disabled or not a Next.js project.")

    # --- Gather context for LLM judgment ---
    routes = _gather_api_routes(root)
    db_sites = _gather_db_query_sites(root)
    upload_sites = _gather_upload_sites(root)
    form_sites = _gather_form_handlers(root)

    # --- Carry-over detection ---
    prior_reports = _list_prior_reports_for_project(audits_root, fingerprint)
    carry_over = _detect_carry_over(prior_reports, findings, root)

    # --- File count ---
    files_scanned = sum(1 for _ in _walk_source_files(root))

    # --- Sort findings by severity ---
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": []}
    for f in findings:
        by_severity.setdefault(f["severity"], []).append(f)

    # --- Compose git note strings for header ---
    git_head_str = git.get("short") or "(git unavailable)"
    git_branch_note = f" (branch: `{git['branch']}`)" if git.get("branch") else ""
    git_dirty_note = ""
    if git.get("dirty") is True:
        git_dirty_note = " · ⚠️ uncommitted changes present"
    elif git.get("dirty") is False:
        git_dirty_note = " · clean working tree"

    # --- Write report ---
    today = datetime.now().strftime("%Y-%m-%d")
    audits_root.mkdir(parents=True, exist_ok=True)
    report_filename = f"{today}-{trigger_label}.md"
    report_path = audits_root / report_filename
    suffix_n = 2
    while report_path.exists():
        report_filename = f"{today}-{trigger_label}-v{suffix_n}.md"
        report_path = audits_root / report_filename
        suffix_n += 1

    fields_str = ", ".join(merged_fields) if merged_fields else "_(none confirmed or declared)_"
    context_status = (
        f"loaded from `{context['source_path']}` ({len(context['sensitive_fields'])} fields, "
        f"{len(context['user_roles'])} roles, {len(context['compliance'])} compliance items, "
        f"{len(context['high_risk'])} high-risk features)"
        if context["found"]
        else "not found — project-context-driven checks skipped"
    )

    report_md = REPORT_TEMPLATE.format(
        project_name=root.name,
        project_path=str(root),
        fingerprint=fingerprint,
        scanned_at=datetime.now().isoformat(timespec="seconds"),
        trigger=trigger_label,
        git_head=git_head_str,
        git_branch_note=git_branch_note,
        git_dirty_note=git_dirty_note,
        fields_str=fields_str,
        files_scanned=files_scanned,
        context_status=context_status,
        n_critical=len(by_severity["CRITICAL"]),
        n_high=len(by_severity["HIGH"]),
        n_medium=len(by_severity["MEDIUM"]),
        n_carry=len(carry_over),
        n_pending=len(routes) + len(db_sites) + len(upload_sites) + len(form_sites),
        carry_block=_format_carry_block(carry_over),
        critical_block=_format_finding_block(by_severity["CRITICAL"]),
        high_block=_format_finding_block(by_severity["HIGH"]),
        medium_block=_format_finding_block(by_severity["MEDIUM"]),
        low_block=_format_finding_block(by_severity.get("LOW", [])),
        n_low=len(by_severity.get("LOW", [])),
        n_routes=len(routes),
        routes_block=_format_routes_block(routes),
        n_db=len(db_sites),
        db_block=_format_simple_sites_block(db_sites),
        n_upload=len(upload_sites),
        upload_block=_format_simple_sites_block(upload_sites),
        n_forms=len(form_sites),
        forms_block=_format_forms_block(form_sites),
        passed_block=_build_passed_block(passed),
        roles_block=_format_list_block(context["user_roles"]) if context["found"] else "_(no project-context.md loaded)_\n",
        compliance_block=_format_list_block(context["compliance"]) if context["found"] else "_(no project-context.md loaded)_\n",
        high_risk_block=_format_list_block(context["high_risk"]) if context["found"] else "_(no project-context.md loaded)_\n",
        today=today,
    )
    report_path.write_text(report_md, encoding="utf-8")

    return json.dumps({
        "project_path": str(root),
        "project_fingerprint": fingerprint,
        "trigger": trigger_label,
        "git_state": git,
        "files_scanned": files_scanned,
        "report_path": str(report_path),
        "project_context_loaded": context["found"],
        "merged_sensitive_fields": merged_fields,
        "deterministic_findings_summary": {
            "CRITICAL": len(by_severity["CRITICAL"]),
            "HIGH": len(by_severity["HIGH"]),
            "MEDIUM": len(by_severity["MEDIUM"]),
            "LOW": len(by_severity.get("LOW", [])),
        },
        "carry_over_count": len(carry_over),
        "carry_over": carry_over,
        "deterministic_findings": by_severity,
        "context_for_judgment": {
            "api_routes": routes,
            "db_query_sites": db_sites,
            "upload_sites": upload_sites,
            "form_handlers": form_sites,
        },
        "passed_checks": passed,
        "project_context": {
            "user_roles": context["user_roles"],
            "compliance": context["compliance"],
            "high_risk": context["high_risk"],
        } if context["found"] else None,
        "instructions_for_caller": (
            "A draft report has been written to report_path. It contains: deterministic findings "
            "with 'Tell Cursor' instructions, carry-over from prior audits, gathered context for "
            "judgment-laden checks, and project-context reminders. As the calling LLM, you should "
            "now: (1) review carry-over entries — confirm whether each is truly unresolved or a "
            "false-positive excerpt match; (2) read each API route's head and judge auth coverage; "
            "(3) judge ownership filtering on DB query sites; (4) judge server-side validation on "
            "uploads; (5) append your judgment findings under the appropriate severity heading in "
            "the report file. Surface CRITICAL/HIGH issues to the user prominently in your reply."
        ),
    }, indent=2)


# ====================================================================
# Pass 3 — fix verification
# ====================================================================

def _parse_prior_report(report_text: str):
    """Parse a Sentinel report (markdown) into structured findings."""
    findings = []
    sections = re.split(r"^##\s+", report_text, flags=re.MULTILINE)
    for section in sections:
        first_line = section.split("\n", 1)[0].strip()
        severity = None
        for sev in ("CRITICAL", "HIGH", "MEDIUM"):
            if first_line.startswith(f"{sev} ISSUES"):
                severity = sev
                break
        if not severity:
            continue

        finding_blocks = re.split(r"^###\s+", section, flags=re.MULTILINE)[1:]
        for block in finding_blocks:
            lines = block.split("\n")
            if not lines:
                continue
            title = lines[0].strip()
            finding = {
                "severity": severity, "title": title, "file": None, "line": None,
                "rule": None, "excerpt": None, "tell_cursor": None,
            }
            for raw in lines[1:]:
                line = raw.strip()
                if not line.startswith("- "):
                    continue
                content = line[2:].strip()
                m = re.match(r"\*\*(\w[\w\s]*?):\*\*\s*(.+)$", content)
                if not m:
                    continue
                key = m.group(1).lower().replace(" ", "_")
                value = m.group(2).strip()
                value = re.sub(r"^`(.+)`$", r"\1", value)
                if key == "file":
                    fm = re.match(r"`?(.+?)`?\s*(?:\(line\s+(\d+)\))?$", value)
                    if fm:
                        finding["file"] = fm.group(1).strip().strip("`")
                        if fm.group(2):
                            finding["line"] = int(fm.group(2))
                elif key in ("rule", "excerpt", "tell_cursor"):
                    finding[key] = value
            if finding["title"]:
                findings.append(finding)
    return findings


def _grep_codebase(root: Path, literal: str, max_hits: int = 10):
    hits = []
    for path in _walk_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line_num, line in enumerate(text.splitlines(), start=1):
            if literal in line:
                hits.append({"file": str(path.relative_to(root)), "line": line_num})
                if len(hits) >= max_hits:
                    return hits
    return hits


def _try_extract_literal(excerpt: str):
    if not excerpt:
        return None
    m = re.search(r"['\"]([A-Za-z0-9_\-/+=]{12,})['\"]", excerpt)
    return m.group(1) if m else None


def _collect_finding_evidence(finding: dict, root: Path):
    evidence = {"checks_run": []}
    file_rel = finding.get("file")
    if not file_rel:
        evidence["error"] = "Finding has no file recorded — verdict requires LLM judgment."
        return evidence
    full = root / file_rel
    evidence["file_exists"] = full.exists()
    evidence["checks_run"].append("file_exists")
    excerpt = finding.get("excerpt")
    if excerpt and full.exists() and full.is_file() and len(excerpt) < 300:
        try:
            text = full.read_text(encoding="utf-8", errors="ignore")
            evidence["original_excerpt_still_present"] = excerpt in text
            evidence["checks_run"].append("original_excerpt_still_present")
        except Exception as e:
            evidence["excerpt_check_error"] = str(e)
    rule = finding.get("rule") or ""
    if rule == "secrets.hardcoded":
        literal = _try_extract_literal(excerpt or "")
        if literal:
            hits = _grep_codebase(root, literal)
            evidence["literal_present_anywhere"] = hits
            evidence["literal_count"] = len(hits)
            evidence["checks_run"].append("literal_present_anywhere")
    elif rule == "secrets.env_not_ignored":
        gitignore = root / ".gitignore"
        if gitignore.exists():
            contents = gitignore.read_text(encoding="utf-8", errors="ignore")
            still_missing = []
            for entry in [".env", ".env.local", ".env.production"]:
                pattern = rf"(?m)^\s*({re.escape(entry)}|\.env\*|\.env\.\*|\*\.env)\s*$"
                if not re.search(pattern, contents):
                    still_missing.append(entry)
            evidence["still_missing_from_gitignore"] = still_missing
            evidence["checks_run"].append("still_missing_from_gitignore")
        else:
            evidence["gitignore_exists"] = False
            evidence["checks_run"].append("gitignore_exists")
    elif rule == "code_quality.file_too_long":
        if full.exists() and full.is_file():
            line_count = sum(1 for _ in full.read_text(encoding="utf-8", errors="ignore").splitlines())
            evidence["current_line_count"] = line_count
            evidence["still_over_threshold"] = line_count > 200
            evidence["checks_run"].append("current_line_count")
    elif rule == "code_quality.any_overuse":
        if full.exists() and full.is_file():
            text = full.read_text(encoding="utf-8", errors="ignore")
            count = len(ANY_PATTERN.findall(text))
            evidence["current_any_count"] = count
            evidence["still_over_threshold"] = count >= 5
            evidence["checks_run"].append("current_any_count")
    elif rule in ("data_exposure.sensitive_log", "data_exposure.sensitive_in_url",
                  "context.secure_storage_violation", "context.analytics_leak",
                  "xss.dangerously_set_inner_html", "injection.eval", "injection.new_function",
                  "injection.timer_string", "webview.injected_js", "webview.source_html",
                  "injection.command", "injection.sql_concat", "injection.sql_template_literal",
                  "redirect.open_url_unvalidated", "crypto.weak_algorithm",
                  "crypto.math_random_for_secret", "communication.insecure_http",
                  "misconfig.cors_wildcard", "misconfig.hardcoded_localhost",
                  "misconfig.debug_flag_true", "misconfig.ats_disabled",
                  "misconfig.cleartext_traffic",
                  "tls.reject_unauthorized_false", "tls.node_tls_reject_disabled",
                  "tls.trust_all_certs", "webview.wildcard_origin_whitelist",
                  "auth.jwt_decode_without_verify", "auth.jwt_none_algorithm",
                  "crypto.bcrypt_rounds_dangerous", "crypto.bcrypt_rounds_low",
                  "crypto.pbkdf2_iterations_low", "crypto.hardcoded_iv", "crypto.hardcoded_key",
                  "deserialization.parse_request_unvalidated", "deserialization.vm_run",
                  "injection.path_traversal_obvious", "injection.path_traversal_join",
                  "injection.prototype_pollution_assign", "injection.prototype_pollution_lodash",
                  "injection.ssrf_obvious", "credentials.hardcoded_default",
                  "privacy.dangerous_ios_permission", "privacy.dangerous_android_permission",
                  "csrf.middleware_absent", "privacy.no_screen_capture_protection"):
        if excerpt and full.exists() and full.is_file():
            text = full.read_text(encoding="utf-8", errors="ignore")
            evidence["original_pattern_still_in_file"] = excerpt in text
            evidence["checks_run"].append("original_pattern_still_in_file")
    elif rule == "supply_chain.no_lockfile":
        lockfiles = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"]
        evidence["lockfile_now_present"] = any((root / lf).exists() for lf in lockfiles)
        evidence["checks_run"].append("lockfile_now_present")
    elif rule.startswith("supply_chain.npm_audit_"):
        # Re-run npm audit and check whether the same package still appears.
        # Cheaper than re-running full check — just spawn and look for the package name.
        pkg_match = re.search(r"`([^`]+)`", finding.get("title") or "")
        if pkg_match:
            pkg_name = pkg_match.group(1)
            try:
                result = subprocess.run(
                    ["npm", "audit", "--json"],
                    cwd=str(root),
                    capture_output=True,
                    text=True,
                    timeout=90,
                )
                try:
                    data = json.loads(result.stdout)
                    still_vulnerable = pkg_name in (data.get("vulnerabilities") or {})
                    evidence["still_in_npm_audit"] = still_vulnerable
                    evidence["checks_run"].append("still_in_npm_audit")
                except json.JSONDecodeError:
                    evidence["npm_audit_unparseable"] = True
                    evidence["checks_run"].append("npm_audit_unparseable")
            except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
                evidence["npm_audit_error"] = str(e)
                evidence["checks_run"].append("npm_audit_error")
    return evidence


def _regression_scan(root: Path, all_prior_findings: list):
    """Re-grep the entire codebase for prior anti-patterns to detect reintroduction."""
    regressions = []
    for f in all_prior_findings:
        rule = f.get("rule") or ""
        original_file = f.get("file")
        if rule == "secrets.hardcoded":
            literal = _try_extract_literal(f.get("excerpt") or "")
            if not literal:
                continue
            hits = _grep_codebase(root, literal)
            elsewhere = [h for h in hits if h["file"] != original_file]
            if elsewhere:
                regressions.append({
                    "from_finding": f.get("title"),
                    "from_severity": f.get("severity"),
                    "regression_type": "literal_reappeared_in_different_file",
                    "hits": elsewhere,
                })
        elif rule in ("data_exposure.sensitive_log", "data_exposure.sensitive_in_url",
                      "context.secure_storage_violation", "context.analytics_leak",
                      "xss.dangerously_set_inner_html", "injection.eval", "injection.new_function",
                      "injection.timer_string", "webview.injected_js", "webview.source_html",
                      "injection.command", "injection.sql_concat", "injection.sql_template_literal",
                      "redirect.open_url_unvalidated", "crypto.weak_algorithm",
                      "crypto.math_random_for_secret", "communication.insecure_http",
                      "misconfig.cors_wildcard", "misconfig.hardcoded_localhost",
                      "misconfig.debug_flag_true", "misconfig.ats_disabled",
                      "misconfig.cleartext_traffic",
                      "tls.reject_unauthorized_false", "tls.node_tls_reject_disabled",
                      "tls.trust_all_certs", "webview.wildcard_origin_whitelist",
                      "auth.jwt_decode_without_verify", "auth.jwt_none_algorithm",
                      "crypto.bcrypt_rounds_dangerous", "crypto.bcrypt_rounds_low",
                      "crypto.pbkdf2_iterations_low", "crypto.hardcoded_iv", "crypto.hardcoded_key",
                      "deserialization.parse_request_unvalidated", "deserialization.vm_run",
                      "injection.path_traversal_obvious", "injection.path_traversal_join",
                      "injection.prototype_pollution_assign", "injection.prototype_pollution_lodash",
                      "injection.ssrf_obvious", "credentials.hardcoded_default"):
            # For these, the excerpt itself is the anti-pattern. Re-grep for it elsewhere.
            excerpt = f.get("excerpt") or ""
            if not excerpt or len(excerpt) < 10:
                continue
            hits = _grep_codebase(root, excerpt)
            elsewhere = [h for h in hits if h["file"] != original_file]
            if elsewhere:
                regressions.append({
                    "from_finding": f.get("title"),
                    "from_severity": f.get("severity"),
                    "regression_type": f"excerpt_reappeared_elsewhere ({rule})",
                    "hits": elsewhere,
                })
    return regressions


VERIFICATION_TEMPLATE = """\
# SENTINEL VERIFICATION REPORT

- **Scope:** verification of fixes claimed against `{source_report}`
- **Project fingerprint:** `{fingerprint}`
- **Source report fingerprint:** `{source_fingerprint}`
- **Fingerprint match:** {fingerprint_match}
- **Scanned:** {scanned_at}
- **Repo path:** `{project_path}`
- **Git HEAD:** {git_head}{git_branch_note}{git_dirty_note}
- **Prior findings parsed:** {n_findings}
- **In scope this run:** {n_in_scope}
- **Regressions flagged:** {n_regressions}
- **Generated by:** Sentinel MCP (deterministic Pass 3)

---

## Per-finding evidence (deterministic)

The calling LLM should review each finding's evidence below, optionally read the
relevant files for context, and assign a final verdict by editing this file.

{findings_block}

---

## Regression scan

Prior findings re-checked across the entire codebase to detect reintroduction of
their original anti-patterns elsewhere.

{regression_block}

---

## Findings NOT verified by this run

(Calling LLM: list the runtime / device / dashboard / network checks the user
or Cursor must perform manually. Static inspection cannot prove these.)

---

## Pending verdict assignment

(Calling LLM: for each finding above, replace the placeholder verdict line with
`**Verdict:** PASS | FAIL | PARTIAL — <one-line justification grounded in evidence>`)
"""


def _format_evidence_block(findings_with_evidence):
    if not findings_with_evidence:
        return "_No findings to verify._\n"
    parts = []
    for entry in findings_with_evidence:
        f = entry["finding"]
        e = entry["evidence"]
        parts.append(f"### [{f['severity']}] {f['title']}")
        parts.append(f"- **File:** `{f.get('file', '?')}`" + (f" (line {f['line']})" if f.get("line") else ""))
        if f.get("rule"):
            parts.append(f"- **Rule:** `{f['rule']}`")
        if f.get("tell_cursor"):
            parts.append(f"- **Original instruction:** {f['tell_cursor']}")
        parts.append("")
        parts.append("**Deterministic evidence:**")
        for check in e.get("checks_run", []):
            val = e.get(check)
            parts.append(f"- `{check}` → `{val}`")
        if e.get("file_exists") is False:
            parts.append("- ⚠️ Reported file does not exist — may have been renamed or deleted.")
        if e.get("original_excerpt_still_present") is True:
            parts.append("- ⚠️ Original excerpt still present in file — fix likely incomplete or absent.")
        if e.get("original_excerpt_still_present") is False:
            parts.append("- ✓ Original excerpt no longer in file.")
        if e.get("error"):
            parts.append(f"- ⚠️ {e['error']}")
        parts.append("")
        parts.append("**Verdict:** _(calling LLM: write PASS / FAIL / PARTIAL with one-line justification)_")
        parts.append("")
    return "\n".join(parts)


def _format_regression_block(regressions):
    if not regressions:
        return "_No regressions detected by deterministic scan._\n"
    parts = []
    for r in regressions:
        parts.append(f"### Regression — original finding: {r['from_finding']} (was {r['from_severity']})")
        parts.append(f"- **Type:** {r['regression_type']}")
        parts.append("- **Hits:**")
        for h in r["hits"]:
            parts.append(f"  - `{h['file']}:{h['line']}`")
        parts.append("")
    return "\n".join(parts)


@mcp.tool()
def sentinel_pass3_verify(
    project_path: str,
    report_path: str,
    claimed_fixes: list[str] = [],
    audits_dir: str = "",
) -> str:
    """Verify claimed fixes against a prior Sentinel audit report. Validates the
    project fingerprint matches before operating (refuses to verify against a report
    from a different project). Parses the report, collects deterministic evidence
    per finding, runs a regression scan, and writes a draft verification report.

    Args:
        project_path: Absolute path to the project being verified.
        report_path: Absolute path to the prior Sentinel audit report.
        claimed_fixes: Finding titles or file paths to verify. Pass ["all"] or empty
            list to verify every CRITICAL/HIGH/MEDIUM finding from the prior report.
        audits_dir: Where to write the verification report. Defaults to the source
            report's directory.
    """
    root = Path(project_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        return json.dumps({"error": f"Invalid project_path: {root}"}, indent=2)

    source = Path(report_path).expanduser().resolve()
    if not source.exists() or not source.is_file():
        return json.dumps({"error": f"Prior report not found: {source}"}, indent=2)

    audits_root = Path(audits_dir).expanduser().resolve() if audits_dir else source.parent

    # --- Fingerprint validation (project isolation guarantee) ---
    context = _load_project_context(root)
    current_fingerprint = _compute_project_fingerprint(root, context)
    report_text = source.read_text(encoding="utf-8", errors="ignore")
    source_fingerprint = _extract_fingerprint_from_report(report_text)

    fingerprint_match = (source_fingerprint == current_fingerprint) if source_fingerprint else None
    if source_fingerprint and not fingerprint_match:
        return json.dumps({
            "error": "Project fingerprint mismatch — refusing to verify.",
            "current_fingerprint": current_fingerprint,
            "source_report_fingerprint": source_fingerprint,
            "explanation": (
                "The report you supplied was generated against a different project (or a "
                "different project-context.md). Verifying it against the current project "
                "would mix audit histories. Re-run Pass 2 against the correct project, or "
                "supply a report whose fingerprint matches."
            ),
        }, indent=2)

    # Parse the prior report.
    prior_findings = _parse_prior_report(report_text)

    # Resolve scope.
    if not claimed_fixes or any(c.lower() == "all" for c in claimed_fixes):
        in_scope = prior_findings
    else:
        wanted_lower = [c.lower() for c in claimed_fixes]
        def matches(f):
            tl = f["title"].lower()
            fl = (f.get("file") or "").lower()
            return any(w == tl or w in tl or w == fl or w in fl for w in wanted_lower)
        in_scope = [f for f in prior_findings if matches(f)]

    findings_with_evidence = []
    for f in in_scope:
        evidence = _collect_finding_evidence(f, root)
        findings_with_evidence.append({"finding": f, "evidence": evidence})

    regressions = _regression_scan(root, prior_findings)
    git = _capture_git_state(root)

    # --- Output filename ---
    today = datetime.now().strftime("%Y-%m-%d")
    src_stem = source.stem
    trigger_match = re.match(r"\d{4}-\d{2}-\d{2}-(.+)", src_stem)
    original_trigger = trigger_match.group(1) if trigger_match else "unknown"
    output_filename = f"{today}-verification-{original_trigger}.md"
    audits_root.mkdir(parents=True, exist_ok=True)
    output_path = audits_root / output_filename
    suffix_n = 2
    while output_path.exists():
        output_filename = f"{today}-verification-{original_trigger}-v{suffix_n}.md"
        output_path = audits_root / output_filename
        suffix_n += 1

    git_head_str = git.get("short") or "(git unavailable)"
    git_branch_note = f" (branch: `{git['branch']}`)" if git.get("branch") else ""
    git_dirty_note = ""
    if git.get("dirty") is True:
        git_dirty_note = " · ⚠️ uncommitted changes present"
    elif git.get("dirty") is False:
        git_dirty_note = " · clean working tree"

    report_md = VERIFICATION_TEMPLATE.format(
        source_report=str(source),
        fingerprint=current_fingerprint,
        source_fingerprint=source_fingerprint or "(none — legacy report)",
        fingerprint_match="✓ match" if fingerprint_match else ("(legacy — no source fingerprint)" if not source_fingerprint else "✗ mismatch"),
        scanned_at=datetime.now().isoformat(timespec="seconds"),
        project_path=str(root),
        git_head=git_head_str,
        git_branch_note=git_branch_note,
        git_dirty_note=git_dirty_note,
        n_findings=len(prior_findings),
        n_in_scope=len(in_scope),
        n_regressions=len(regressions),
        findings_block=_format_evidence_block(findings_with_evidence),
        regression_block=_format_regression_block(regressions),
    )
    output_path.write_text(report_md, encoding="utf-8")

    return json.dumps({
        "project_path": str(root),
        "current_fingerprint": current_fingerprint,
        "source_fingerprint": source_fingerprint,
        "fingerprint_match": fingerprint_match,
        "source_report": str(source),
        "verification_report_path": str(output_path),
        "git_state": git,
        "prior_findings_parsed": len(prior_findings),
        "in_scope_count": len(in_scope),
        "regressions_detected": len(regressions),
        "findings_with_evidence": findings_with_evidence,
        "regressions": regressions,
        "instructions_for_caller": (
            "A draft verification report has been written. For each finding the deterministic "
            "evidence is provided; the final PASS/FAIL/PARTIAL verdict is your call. Read each "
            "finding's original 'Tell Cursor' instruction, compare against the deterministic "
            "evidence, optionally read the relevant source files for context, then edit the "
            "verification report file to fill in each verdict line. Also fill in the 'Findings "
            "NOT verified' section with any runtime / device / dashboard checks the user must "
            "perform manually. If the regression scan flagged anything, treat those as new "
            "CRITICAL/HIGH findings that reset the audit cycle."
        ),
    }, indent=2)


# ====================================================================
# sentinel_init — scaffold Sentinel for a new project
# ====================================================================

_PROJECT_CONTEXT_TEMPLATE = """# __PROJECT_NAME__ — Project Context (Sentinel)

> Read by Sentinel on every audit pass. Update this file when sensitive fields,
> roles, compliance requirements, or high-risk features change.
> Last updated: __TODAY__ (initialized via sentinel_init)

---

## SENSITIVE_FIELDS

<!-- List fields that contain sensitive data. Format:
     `qualified.field_name` — category — rules

Replace these examples with the real fields in this project. The MCP auto-loads
declared fields and adds project-specific checks (AsyncStorage misuse for fields
requiring SecureStore; sensitive fields appearing in analytics/error reporters; etc.).

Examples:
- `users.email` — GDPR/PII — never logged, never in analytics events, never in a URL
- `users.password` — credential — server-side hash only, never returned in API responses
- `session.access_token` — auth credential — SecureStore only, never AsyncStorage, never logged
- `payments.card_number` — FINANCIAL — never logged, must be tokenized via Stripe.js or equivalent
- `analytics.event_payloads` — PII risk — scrub email/display_name before send
- `sentry.error_context` — PII risk — scrub PII from breadcrumbs and error messages
-->

---

## USER_ROLES

<!-- List user roles and what each can do. Examples:
- `user` — default, self-data access only (Row-Level Security enforced)
- `admin` — full data access, audit log access
- `support` — read-only access to user data for support tickets
-->

---

## COMPLIANCE_REQUIREMENTS

<!-- List compliance frameworks that apply. Examples:
- GDPR — EU users have right to export and right to deletion
- Apple App Store Privacy Labels — must be completed before first TestFlight
- Google Play Data Safety Form — must be completed before first Play Console
- PCI-DSS — if handling card data
- HIPAA — if handling health data
- SOC 2 — if handling enterprise customer data
-->

---

## HIGH_RISK_FEATURES

<!-- List features requiring extra scrutiny. Examples:
- Auth flow — login, signup, password reset, OAuth, SSO
- Payment processing
- File uploads from users
- Deep links / URL schemes / Universal Links
- WebView usage
- Third-party SDK integrations (analytics, crash reporters, payment processors)
- Background location, camera, microphone, contacts access
-->

---

## AUDIT HISTORY

| Date | Trigger | Findings | Status |
|---|---|---|---|
| __TODAY__ | initialized | _(pending first Sentinel scan)_ | _(pending verdict)_ |
"""


_CURSOR_RULES_TEMPLATE = """---
description: Prompts the user to run the Sentinel security audit at meaningful checkpoints. Always active.
alwaysApply: true
---

# Sentinel Audit Checkpoints

Sentinel is a security/code-quality auditor for this project, available as a local MCP server (server name: `sentinel`; tools: `sentinel_pass1_discover`, `sentinel_pass2_audit`, `sentinel_pass3_verify`, `sentinel_init`).

Your job: **detect when work has crossed a Sentinel-worthy checkpoint and prompt the user with their options.** When the user opts in, you may invoke the MCP directly. The MCP writes a dated report to `audits/`; that file is the handoff to Cowork — no copy-paste needed.

---

## First-time setup detection

When the user says "run Sentinel" (or equivalent) for the first time in a project:

1. Call `sentinel_pass1_discover` first.
2. If the response includes `"first_time_setup_recommended": true`, the project has not been set up for Sentinel. STOP and ask the user:
   > This project hasn't been set up for Sentinel yet. Want me to initialize it?
   > That creates `project-context.md` (a template you'll fill in), an `audits/` folder, and Cursor checkpoint rules.
   > Or would you prefer to run a minimal audit now without project-specific context?
3. If yes → call `sentinel_init` with the args from `suggested_init_call`. Then tell the user to edit `project-context.md` (specifically: SENSITIVE_FIELDS, USER_ROLES, COMPLIANCE_REQUIREMENTS, HIGH_RISK_FEATURES). After they confirm the edits are done, re-run `sentinel_pass1_discover`.
4. If they want a minimal audit anyway → skip init and proceed with Pass 1 results as returned. Project-specific checks will be skipped but the deterministic layer still runs.

---

## Auditor/builder discipline

You write the code in this repo. That makes you a biased auditor of judgment-laden security questions about it. The MCP's deterministic checks are unbiased; the judgment-laden checks are not.

When you call `sentinel_pass2_audit`:
- **Act on deterministic findings** — severity already assigned by the MCP. Surface them, propose fixes.
- **Do NOT fill in the "Pending Manual Review" sections of the report** for code you wrote. Leave `_(awaiting Cowork auditor judgment)_` placeholders.
- **Tell the user** when the report is ready for Cowork to review independently.

When you call `sentinel_pass3_verify`:
- **Surface the deterministic evidence**.
- **Do NOT assign final PASS/FAIL/PARTIAL verdicts to your own fixes** — that's Cowork's call.
- For deterministic-only findings, you may preview a verdict but mark it `(preliminary — Cowork to confirm)`.
- **If the regression scan flags reintroduced anti-patterns, surface those CRITICALLY.**

---

## Checkpoint Triggers — when to prompt

Prompt the user immediately after any of:

1. **Initial scaffold complete** — trigger label `baseline`.
2. **Auth touched** — login, signup, password reset, OAuth, biometrics, session/refresh tokens, JWT. Label: `auth-touched`.
3. **Secrets/credentials handled** — new env vars, API keys, signing configs, certificate pinning, third-party SDK init with keys. Label: `secrets-touched`.
4. **Networking changes** — new API client, base URL changes, headers/interceptors, TLS config, WebSocket setup, GraphQL client. Label: `networking-touched`.
5. **Local data storage changes** — Keychain, Keystore, SecureStore, AsyncStorage, SharedPreferences, SwiftData/CoreData, Room, SQLite, Realm. Label: `storage-touched`.
6. **Permissions added** — `Info.plist` (`NS*UsageDescription`) or `AndroidManifest.xml` (`<uses-permission>`). Label: `permissions-touched`.
7. **Deep links / URL schemes / app links** added or modified. Label: `deeplink-touched`.
8. **WebView introduced or modified.** Label: `webview-touched`.
9. **Third-party SDK added** — analytics, crash reporting, ads, payments, auth. Label: `sdk-added`.
10. **Before any push to a remote.** Label: `pre-push`.
11. **Before any release candidate** (TestFlight, Play Console, store submission). Label: `pre-release`.
12. **Weekly cadence fallback.** Label: `weekly-cadence`.

---

## How to prompt

When a checkpoint triggers, stop the current flow and surface this shape:

> ⚠ **Sentinel checkpoint reached: [trigger reason]**
>
> Recommend running a Pass 2 audit before continuing. How would you like to handle it?
>
> &nbsp;&nbsp;**a) Run Sentinel now via the MCP** — I'll call it directly. Deterministic findings come back to this chat; judgment-laden sections will be left for Cowork to review.
> &nbsp;&nbsp;**b) Pause — you'll run it manually in Cowork** for fully independent judgment.
> &nbsp;&nbsp;**c) Continue and run it at the next natural break** — I'll remind you.
> &nbsp;&nbsp;**d) Skip this checkpoint** (not recommended — tell me why so I can note it).

Then **wait** for the user's answer.

### If the user picks (a) — run via MCP

Call `sentinel_pass2_audit` with:
- `project_path` = `__PROJECT_PATH__`
- `confirmed_fields` = `[]`  *(auto-loaded from project-context.md)*
- `trigger_label` = the matching label
- `audits_dir` = `__AUDITS_DIR__`

After it returns:
1. Read the report file at the returned `report_path`.
2. Report deterministic findings to the user grouped by severity (CRITICAL → HIGH → MEDIUM). For each, restate file/line and the "Tell Cursor" instruction.
3. Report carry-over findings if any — old issues still present.
4. For the "Pending Manual Review" section, do NOT review yourself. Append `_(awaiting Cowork auditor judgment)_` placeholders in the report file using your edit tools.
5. End with: *"Report saved to `[report_path]`. Ready for Cowork to apply judgment to the Pending Manual Review section. Want me to start fixing the deterministic findings now, or wait for Cowork's review first?"*

### Other options

(b) defer to Cowork — note the deferral, do not proceed past hard blockers.
(c) defer to next break — note in next response.
(d) skip — record reason in a comment in the most relevant file.

---

## After fixes — verification flow

When fixes are claimed:

1. Ask: *"Want me to call `sentinel_pass3_verify` to collect deterministic evidence? Cowork will assign final verdicts."*
2. If yes, call with:
   - `project_path` = `__PROJECT_PATH__`
   - `report_path` = absolute path to the audit being verified
   - `claimed_fixes` = `["all"]` (or specific finding titles)
   - `audits_dir` = `__AUDITS_DIR__`
3. Surface deterministic evidence. State preliminary verdicts on deterministic-only findings, mark them `(preliminary — Cowork to confirm)`.
4. **Do NOT mark your own findings PASS.** Tell the user the verification draft is ready for Cowork.
5. If `regressions_detected > 0`, surface CRITICALLY.

---

## Hard blockers

Two non-negotiable checkpoints — do not proceed without confirmation Sentinel was run AND triaged AND Cowork judgment review complete:

1. **Before any push to a remote** that includes auth, secrets, networking, or storage changes since the last audit.
2. **Before any release-candidate build** (TestFlight, Play Console, store submission).

If the user insists on bypassing, require an explicit override phrase ("override Sentinel block") and log the bypass in the commit message.

---

## File-level tripwires — trigger immediately when these are created or modified

Do not wait until end of turn. Trigger the checkpoint before writing the next file when any of these are touched:

| File / pattern | Checkpoint | Trigger label |
|---|---|---|
| Any file importing a Supabase/Firebase/auth-provider client | Networking + Secrets | `networking-touched` |
| `.env` or `.env.*` | Secrets/credentials | `secrets-touched` |
| `app.json` / native config with new plugin or permission | Permissions / SDK | `permissions-touched` |
| Any file with `SecureStore`, `Keychain`, `Keystore`, `AsyncStorage` | Local data storage | `storage-touched` |
| Any file with `signIn`, `signUp`, `signOut`, `resetPassword`, `verifyOtp` | Auth | `auth-touched` |
| Any file with OAuth / SSO imports | Auth + SSO | `auth-touched` |
| Any file adding a deep link route or URL scheme | Deep links | `deeplink-touched` |
| `package.json` adding a new third-party SDK | Third-party SDK | `sdk-added` |

---

## What you do not do

- Do not assign PASS/FAIL/PARTIAL verdicts to your own fixes.
- Do not fill in judgment-laden sections of a Pass 2 report for code you wrote.
- Do not invoke the MCP without first prompting the user with options a/b/c/d.
- Do not nag mid-edit.
- Do not block trivial UI-only or copy/style changes that don't touch any trigger category.
- Do not modify the report's project fingerprint or git-state header — those are integrity fields.
"""


def _generate_project_context(project_name: str) -> str:
    today = datetime.now().strftime("%Y-%m-%d")
    return (_PROJECT_CONTEXT_TEMPLATE
            .replace("__PROJECT_NAME__", project_name)
            .replace("__TODAY__", today))


def _generate_cursor_rules(project_path: str, audits_dir: str) -> str:
    return (_CURSOR_RULES_TEMPLATE
            .replace("__PROJECT_PATH__", project_path)
            .replace("__AUDITS_DIR__", audits_dir))


@mcp.tool()
def sentinel_init(
    project_path: str,
    audits_dir: str = "",
    include_cursor_rules: bool = True,
    overwrite: bool = False,
) -> str:
    """Scaffold Sentinel for a new project. Safe by default — does NOT overwrite
    existing files unless overwrite=True.

    Creates:
      - {project_path}/project-context.md — template with SENSITIVE_FIELDS,
        USER_ROLES, COMPLIANCE_REQUIREMENTS, HIGH_RISK_FEATURES, AUDIT HISTORY sections.
        The developer fills in the project-specific values.
      - {audits_dir}/ — folder for audit reports. Defaults to {project_path}/audits/.
      - {project_path}/.cursor/rules/sentinel-checkpoints.mdc — Cursor rules so the
        Cursor agent proactively prompts for Sentinel audits on this project. Skip
        with include_cursor_rules=False if you don't use Cursor.

    Args:
        project_path: Absolute path to the new project's root.
        audits_dir: Where audit reports should be saved. Defaults to {project_path}/audits/.
            Pass a separate audit-tracking folder if you want audits isolated from source.
        include_cursor_rules: If True (default), writes Cursor rules. Set False to skip.
        overwrite: If True, overwrites existing files. Default False (safe).
    """
    root = Path(project_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        return json.dumps({"error": f"Invalid project_path: {root}"}, indent=2)

    audits_root = Path(audits_dir).expanduser().resolve() if audits_dir else (root / "audits")

    files_created = []
    files_skipped = []
    errors = []

    # 1. project-context.md
    pc_path = root / "project-context.md"
    if pc_path.exists() and not overwrite:
        files_skipped.append(str(pc_path))
    else:
        try:
            pc_path.write_text(_generate_project_context(root.name), encoding="utf-8")
            files_created.append(str(pc_path))
        except Exception as e:
            errors.append(f"Failed to write {pc_path}: {e}")

    # 2. audits/ folder
    try:
        if audits_root.exists():
            if not audits_root.is_dir():
                errors.append(f"audits_dir exists but is not a directory: {audits_root}")
            else:
                files_skipped.append(str(audits_root) + " (already existed)")
        else:
            audits_root.mkdir(parents=True, exist_ok=True)
            files_created.append(str(audits_root) + " (folder)")
    except Exception as e:
        errors.append(f"Failed to ensure {audits_root}: {e}")

    # 3. Cursor rules (optional)
    mdc_path = None
    if include_cursor_rules:
        mdc_path = root / ".cursor" / "rules" / "sentinel-checkpoints.mdc"
        if mdc_path.exists() and not overwrite:
            files_skipped.append(str(mdc_path))
        else:
            try:
                mdc_path.parent.mkdir(parents=True, exist_ok=True)
                mdc_path.write_text(
                    _generate_cursor_rules(str(root), str(audits_root)),
                    encoding="utf-8",
                )
                files_created.append(str(mdc_path))
            except Exception as e:
                errors.append(f"Failed to write {mdc_path}: {e}")

    next_steps = [
        f"1. Edit {pc_path} — fill in SENSITIVE_FIELDS, USER_ROLES, COMPLIANCE_REQUIREMENTS, HIGH_RISK_FEATURES for this project.",
        f"2. Run sentinel_pass1_discover with project_path='{root}' to surface candidate sensitive fields.",
        f"3. After Pass 1, run sentinel_pass2_audit with trigger_label='baseline' and audits_dir='{audits_root}' to produce the initial audit report.",
        "4. Commit project-context.md to git so future audits remain consistent.",
    ]
    if include_cursor_rules and mdc_path:
        next_steps.append(
            f"5. Open the project in Cursor and confirm `.cursor/rules/sentinel-checkpoints.mdc` is loaded (Cursor reads .mdc files automatically on the next chat turn)."
        )

    return json.dumps({
        "project_path": str(root),
        "audits_dir": str(audits_root),
        "files_created": files_created,
        "files_skipped": files_skipped,
        "errors": errors,
        "next_steps": next_steps,
        "instructions_for_caller": (
            "Sentinel scaffolding done. The project-context.md template needs human editing — "
            "tell the user to fill in the project-specific SENSITIVE_FIELDS, USER_ROLES, "
            "COMPLIANCE_REQUIREMENTS, HIGH_RISK_FEATURES before the first Pass 2 audit. "
            "If you call Pass 2 immediately with the template unedited, Sentinel will still run "
            "but the project-context-driven checks won't fire meaningfully."
        ),
    }, indent=2)


if __name__ == "__main__":
    mcp.run()
