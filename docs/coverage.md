# Sentinel — Coverage Reference

Full rule-by-rule listing of what `sentinel_mcp.py` checks deterministically, grouped by category. Mapped to OWASP Mobile Top 10 2024 + OWASP API/ASVS where relevant.

For the source of truth, read `sentinel_mcp.py` directly — every pattern is documented inline with severity, rule ID, and a `tell_cursor` instruction template.

---

## OWASP Mobile Top 10 2024 — coverage state

| Risk | Coverage | Notes |
|---|---|---|
| **M1 Improper Credential Usage** | **Strong** | Hardcoded secret patterns, `.gitignore` coverage of `.env*`, default-password detection, SecureStore enforcement, secrets scanned in `.plist` / `.xml` / `.json` / `.yml` / `.yaml` |
| **M2 Inadequate Supply Chain Security** | **Strong** | Lockfile presence check; `npm audit --json` subprocess integration (one finding per vulnerable package) |
| **M3 Insecure Authentication/Authorization** | **Partial** | `jwt.decode()` without verify; JWT `none` algorithm acceptance. Auth correctness (which role for which route) is judgment-only — surfaced via gathered context |
| **M4 Insufficient Input/Output Validation** | **Strong** | Full injection coverage; form-handler discovery in judgment-layer context |
| **M5 Insecure Communication** | **Strong** | Hardcoded `http://`, full TLS-bypass family, ATS-disabled, cleartext traffic, wildcard CORS |
| **M6 Inadequate Privacy Controls** | **Strong** | Permissions audit (iOS + Android + Expo); analytics scrubbing (project-context driven); screen-capture protection check |
| **M7 Insufficient Binary Protections** | **None** | Out of scope for static source analysis — happens at build time |
| **M8 Security Misconfiguration** | **Strong** | CORS, ATS, cleartext, debug flags, hardcoded localhost, CSRF middleware absence |
| **M9 Insecure Data Storage** | **Partial** | SecureStore enforcement (project-context driven); AsyncStorage misuse detection. Full encryption-at-rest verification beyond declarations is judgment-only |
| **M10 Insufficient Cryptography** | **Partial** | MD5/SHA1, `Math.random()` for secrets, weak bcrypt rounds, low PBKDF2 iterations, hardcoded IVs, hardcoded encryption keys. Missing: KDF parameter strength beyond bcrypt/PBKDF2; IV-reuse detection beyond hardcoded literals |

---

## Rules by category

### Secrets / credentials (`SECRET_PATTERNS`)

| Rule ID | Severity | Catches |
|---|---|---|
| `secrets.hardcoded` (provider-specific) | CRITICAL | AWS access keys (`AKIA…`), AWS secret keys, Google API keys (`AIza…`), Stripe live/test/restricted keys (`sk_live_`, `sk_test_`, `rk_live_`, `pk_live_`), GitHub PATs (`ghp_`, `gho_`, `ghs_`), Slack tokens (`xox[abprs]-…`), private key blocks (`-----BEGIN … PRIVATE KEY-----`), JWT-shaped literals |
| `secrets.hardcoded` (generic) | CRITICAL | `api_key = "…"`, `password: "…"`, `access_token = "…"` with 12+ char literal |
| `secrets.no_gitignore` | HIGH | No `.gitignore` at repo root |
| `secrets.env_not_ignored` | CRITICAL | `.env`, `.env.local`, `.env.production` not covered by `.gitignore` |
| `credentials.hardcoded_default` | HIGH | `password = "admin"` / `"password"` / `"123456"` / `"test"` / `"changeme"` / `"default"` / `"root"` etc. in non-test files |

Secret scanner runs over: `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.py`, `.swift`, `.kt`, `.java`, `.dart`, `.go`, `.rs`, `.rb`, `.php`, `.sql`, `.prisma`, `.graphql`, `.gql`, `.plist`, `.xml`, `.json`, `.yml`, `.yaml`. Lockfiles excluded to avoid integrity-hash false positives.

### Injection sinks (`INJECTION_PATTERNS`)

| Rule ID | Severity | Catches |
|---|---|---|
| `xss.dangerously_set_inner_html` | CRITICAL | React `dangerouslySetInnerHTML` usage |
| `injection.eval` | CRITICAL | `eval(…)` call |
| `injection.new_function` | CRITICAL | `new Function(…)` constructor |
| `injection.timer_string` | HIGH | `setTimeout("…")` / `setInterval("…")` with string argument |
| `webview.injected_js` | HIGH | WebView `injectedJavaScript=` prop |
| `webview.source_html` | HIGH | WebView `source={{ html: … }}` |
| `webview.wildcard_origin_whitelist` | HIGH | WebView `originWhitelist={['*']}` |
| `injection.command` | CRITICAL | `child_process.exec/spawn/execFile` with template-literal containing `${…}` |
| `injection.sql_concat` | CRITICAL | `.query(/.execute/.raw)` with string concatenation |
| `injection.sql_template_literal` | CRITICAL | Same with template-literal interpolation |
| `injection.path_traversal_obvious` | CRITICAL | `fs.readFile/writeFile/…(req.params.X)`, `(req.query.X)`, `(req.body.X)` |
| `injection.path_traversal_join` | HIGH | `path.join/resolve(…, req.X.…, …)` |
| `injection.prototype_pollution_assign` | HIGH | `Object.assign(target, req.body / req.query / req.params)` |
| `injection.prototype_pollution_lodash` | HIGH | `_.merge / .mergeWith / .defaultsDeep / .set / .defaults(target, req.…)` |
| `injection.ssrf_obvious` | CRITICAL | `fetch / axios / http.get(req.body.url / req.params.url / req.query.url)` |
| `deserialization.parse_request_unvalidated` | HIGH | `JSON.parse(req.body / req.query / req.params / request.body)` without prior validation |
| `deserialization.vm_run` | CRITICAL | Node `vm.runInNewContext / runInThisContext / runInContext` |
| `redirect.open_url_unvalidated` | MEDIUM | `Linking.openURL(<variable>)` — needs allowlist review |

### Authentication / authorization

| Rule ID | Severity | Catches |
|---|---|---|
| `auth.jwt_decode_without_verify` | HIGH | `jwt.decode(…)` — signature not verified |
| `auth.jwt_none_algorithm` | CRITICAL | JWT verifier configured to accept `'none'` algorithm |

### Communication / transport

| Rule ID | Severity | Catches |
|---|---|---|
| `communication.insecure_http` | HIGH | Hardcoded `http://` URL (non-localhost) |
| `tls.reject_unauthorized_false` | CRITICAL | `rejectUnauthorized: false` in TLS client config |
| `tls.node_tls_reject_disabled` | CRITICAL | `NODE_TLS_REJECT_UNAUTHORIZED=0` env var |
| `tls.trust_all_certs` | CRITICAL | `trustAllCerts` / `TrustAllSSL` / `TrustManager.acceptAllIssuers` / `setHostnameVerifier(ALLOW_ALL)` patterns |
| `misconfig.cors_wildcard` | HIGH | `Access-Control-Allow-Origin: *` |
| `csrf.middleware_absent` | MEDIUM | State-changing HTTP routes detected without `csurf` / `@fastify/csrf-protection` / `@nestjs/csrf` / `lusca` / `koa-csrf` / `next-csrf` imported |

### Cryptography

| Rule ID | Severity | Catches |
|---|---|---|
| `crypto.weak_algorithm` | HIGH | `createHash("md5")` / `createHash("sha1")` |
| `crypto.math_random_for_secret` | HIGH | `Math.random()` near identifiers like `token` / `password` / `secret` / `key` / `nonce` / `salt` |
| `crypto.bcrypt_rounds_dangerous` | CRITICAL | `bcrypt.hash(…, N)` where N is a single digit (1-9) |
| `crypto.bcrypt_rounds_low` | HIGH | `bcrypt.hash(…, 10)` or `bcrypt.hash(…, 11)` |
| `crypto.pbkdf2_iterations_low` | HIGH | PBKDF2 iteration count below 100,000 |
| `crypto.hardcoded_iv` | HIGH | `iv: Buffer.from("[hex]…")` static IV |
| `crypto.hardcoded_key` | CRITICAL | `encryption_key = "[hex 32+]"` patterns |

### Privacy / data exposure

| Rule ID | Severity | Catches |
|---|---|---|
| `data_exposure.sensitive_log` | HIGH | `console.log/warn/error/info/debug/trace` containing a confirmed/declared sensitive field name |
| `data_exposure.sensitive_in_url` | HIGH | URL string in a route definition containing a sensitive field name |
| `context.secure_storage_violation` | CRITICAL | `AsyncStorage.<method>(…field…)` where the field is declared in project-context as requiring SecureStore/Keychain |
| `context.analytics_leak` | HIGH | `posthog/sentry/amplitude/mixpanel/firebase.analytics/analytics.<method>(…field…)` where the field requires scrubbing |
| `privacy.dangerous_ios_permission` | MEDIUM | Each dangerous `NS*UsageDescription` in Info.plist or Expo app.json |
| `privacy.dangerous_android_permission` | MEDIUM | Each dangerous `<uses-permission android:name="…" />` or Expo app.json android.permission |
| `privacy.no_screen_capture_protection` | MEDIUM | Sensitive fields declared in project-context but no `FLAG_SECURE` / `expo-screen-capture` / `preventScreenCaptureAsync` / `setSecure` references found |

### Misconfiguration / platform

| Rule ID | Severity | Catches |
|---|---|---|
| `misconfig.hardcoded_localhost` | MEDIUM | Hardcoded `localhost` / `127.0.0.1` URLs in shipped code |
| `misconfig.debug_flag_true` | MEDIUM | `debug: true` or `DEBUG: true` not gated by `__DEV__` |
| `misconfig.ats_disabled` | HIGH | iOS `NSAllowsArbitraryLoads` in Info.plist |
| `misconfig.cleartext_traffic` | HIGH | Android `android:usesCleartextTraffic="true"` |

### Supply chain

| Rule ID | Severity | Catches |
|---|---|---|
| `supply_chain.no_lockfile` | MEDIUM | `package.json` present but no `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` / `bun.lockb` |
| `supply_chain.npm_audit_critical` | CRITICAL | Each package flagged critical by `npm audit --json` |
| `supply_chain.npm_audit_high` | HIGH | Each package flagged high |
| `supply_chain.npm_audit_moderate` | MEDIUM | Each package flagged moderate |
| `supply_chain.npm_audit_low` | MEDIUM | Each package flagged low or info |
| `supply_chain.npm_unavailable` | MEDIUM | `npm` command not on PATH — supply-chain scan skipped |
| `supply_chain.audit_timeout` | MEDIUM | `npm audit` did not complete within timeout (default 90s) |
| `supply_chain.audit_unparseable` | MEDIUM | `npm audit` JSON output could not be parsed |

### Code quality

| Rule ID | Severity | Catches |
|---|---|---|
| `code_quality.file_too_long` | MEDIUM | Source files exceeding 200 lines |
| `code_quality.any_overuse` | MEDIUM | TypeScript files with 5+ `any` usages (`: any`, `as any`, `<any>`) |

---

## Judgment-layer context gathering

These are NOT deterministic findings — Sentinel gathers them as context for the calling LLM to apply judgment.

| Gathered context | What the LLM judges |
|---|---|
| **API routes** (Next.js app router, Pages router, Express/Fastify route handlers; first 25 lines each) | Auth check at handler top; admin-only routes verify role (not just login); DB queries filter by current user; no user ID accepted from request body / URL without session match; server-side input validation |
| **DB query call sites** (Supabase, Prisma, Drizzle, Mongoose, Knex; `.from('table')`, `.findMany`, `.findUnique`) | Ownership filtering (user_id / org_id) applied |
| **Upload sites** (Multer, Formidable, Busboy, FormData, multipart/form-data, expo-image-picker, react-native-image-picker) | Server-side MIME type and size validation present |
| **Form handlers** (`useForm`, `Formik`, `<TextInput>`, `react-hook-form`, `zodResolver`/`yupResolver`, validation schemas; first 30 lines each) | Client-side schema validation; server-side validation on submit; sanitization before render/storage; no dangerous sink for unsanitized input; rate-limiting/captcha on public forms |

---

## What Sentinel does NOT check

### Structural limits (no static source scanner can do these)

- **Authorization correctness** — "does this admin route check the right role?" requires understanding intent.
- **M7 Binary Protections** — anti-tamper, obfuscation, root/jailbreak detection. Build-time concerns.
- **Race conditions / TOCTOU** — concurrent-execution bugs need runtime analysis.
- **Multi-file data flow** — path traversal / prototype pollution / SSRF *beyond* in-line obvious cases require following data across many files (abstract interpretation). Sentinel catches the obvious cases; it can't catch the subtle ones.
- **ReDoS** — catastrophic regex backtracking detection requires regex AST analysis.
- **Privacy policy / compliance documents** — written content, not code.

### Engineering — could be added with careful design

- **Auth-bypass TODO markers** (`// TODO: add auth check`) — every codebase has TODOs; needs smart context awareness to avoid noise.
- **`__DEV__`-gated production leaks** — patterns need careful design to avoid false positives.
- **`tsc --noEmit` integration in Pass 3** — wiring exists in the spec, not built yet.
- **Test-script runner integration in Pass 3** — same.

If you spot a category you think should be added, open an issue or send a PR.

---

## How severity is assigned

- **CRITICAL** — exploitable defect with high impact (account takeover, full data leak, secret exfiltration, RCE-class). Fix before next deploy.
- **HIGH** — security issue with significant impact but mitigated by other layers, or requires specific attacker conditions. Fix before launch / release.
- **MEDIUM** — code quality, hardening, or compliance hygiene. Fix when possible; track in audit history.

Severity is technical risk in current code. Developer comments (`// TODO: harden later`, `// deferred to scope.md`) do NOT downgrade severity. If you intend to ship a known-risky pattern, document the acceptance in `project-context.md` rather than relying on inline comments to suppress findings.
