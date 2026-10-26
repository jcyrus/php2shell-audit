# php2shell-audit

[![PHP 7.0–8.5](https://img.shields.io/badge/PHP-7.0%E2%80%938.5-777BB4?logo=php&logoColor=white)](#compatibility)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](composer.json)
[![CI](https://github.com/jcyrus/php2shell-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/jcyrus/php2shell-audit/actions/workflows/ci.yml)

**A read-only, zero-dependency auditor for php2shell exposure.** php2shell is the pair
CVE-2026-109618 and CVE-2026-109619 (CVSS 9.2, pre-authentication RCE), patched in PHP 8.2.35,
8.3.36, 8.4.27 and 8.5.12 on 2026-10-21. The tool also measures how far your Composer
dependencies are from PHP 8.3/8.4.

It's a single PHP file that runs on the server you're worried about, including EOL PHP 7.0 –
8.1 boxes. It reads `php.ini`, PHP-FPM pool files and `composer.lock`. It **never** makes
network calls, writes files, executes shell commands or sends payloads.

---

## Quickstart

```bash
# Download, read, run (works on PHP 7.0 – 8.5)
curl -fsSLo php2shell-audit https://raw.githubusercontent.com/jcyrus/php2shell-audit/main/bin/php2shell-audit
less php2shell-audit
php php2shell-audit --path=/var/www/app
```

Point it at the configuration that actually serves HTTP traffic:

```bash
php php2shell-audit --path=/var/www/app \
    --ini=/etc/php/7.4/fpm/php.ini \
    --fpm-conf=/etc/php/7.4/fpm/pool.d/www.conf
```

Export an anonymized report you can share with an external architect:

```bash
php php2shell-audit --path=/var/www/app --json > audit-summary.json
```

Gate a pipeline. The command exits `1` on any CRITICAL/HIGH finding:

```bash
php php2shell-audit --path=. --ci --no-color
```

Other ways to run it:

```bash
# From a clone
git clone https://github.com/jcyrus/php2shell-audit && cd php2shell-audit
php bin/php2shell-audit --path=/var/www/app

# Composer (global)
composer global require jcyrus/php2shell-audit
php2shell-audit --path=/var/www/app

# Piped (PHP 7.4+; PHP 7.0–7.3 echo the shebang line when reading a script from stdin)
curl -fsSL https://raw.githubusercontent.com/jcyrus/php2shell-audit/main/bin/php2shell-audit | php -- --json
```

## Example output

```text
$ php bin/php2shell-audit --ini=tests/fixtures/vulnerable-php74.ini \
    --fpm-conf=tests/fixtures/vulnerable-www.conf \
    --path=tests/fixtures/legacy-composer.lock --php-version=7.4.33

╭────────────────────────────────────────────────────────────────────────────╮
│ php2shell-audit 1.0.0 · CVE-2026-109618 / CVE-2026-109619                  │
│ Read-only exposure & PHP 8.3/8.4 upgrade-readiness audit                   │
├────────────────────────────────────────────────────────────────────────────┤
│ Overall risk    CRITICAL                                                   │
│ PHP runtime    7.4.33 (cli) · EOL - no upstream patch                      │
│ Sources        ini=provided · fpm=provided · composer.lock=found           │
│ Findings       1 critical · 3 high · 6 warning · 2 info · 0 pass           │
│ OOM headroom   2.00x (memory_limit 128M / post_max_size 64M)               │
│ Migration      HIGH - STRANGLER FIG RECOMMENDED · 15 blocker item(s)       │
╰────────────────────────────────────────────────────────────────────────────╯

── CRITICAL (1) ──────────────────────────────────────────────────────────────
 ✖ [CRITICAL] PHP 7.4.33 is EOL - No Upstream Patch Available
      runtime.eol
      php2shell (CVE-2026-109618 OOM longjmp state corruption, CVE-2026-109619
      stale multipart request state; CVSS 9.2) affects every branch back to
      PHP 5.4. Upstream fixed only 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 on
      2026-10-21; the 7.4 branch will not receive a fix.

── HIGH (3) ──────────────────────────────────────────────────────────────────
 ✖ [HIGH] OOM headroom ratio 2.00 < 4.0
 ✖ [HIGH] session.upload_progress.enabled = On
 ✖ [HIGH] Infinite or long-lived FPM workers: [www] (vulnerable-www.conf) = 0

── WARNING (6) ───────────────────────────────────────────────────────────────
 ▲ [WARNING] max_input_vars = 5000 (recommended <= 1000)
 ▲ [WARNING] max_input_nesting_level = 64 (recommended <= 32)
 ▲ [WARNING] max_multipart_body_parts unavailable on PHP 7.4.33
 ▲ [WARNING] 9 package(s) pin PHP below 8.3/8.4
 ▲ [WARNING] 4 abandoned package(s) locked
 ▲ [WARNING] 2 problematic C-extension requirement(s)

── COMPOSER BLOCKERS ─────────────────────────────────────────────────────────
 Package                        Locked       require.php          8.3   8.4
 ------------------------------ ------------ -------------------- ----- -----
 (root project)                 -            ^7.2                 NO    NO
 acme/billing-core              4.2.0        >=7.4 <8.4           ok    NO
 acme/legacy-auth               3.4.0        ~7.4                 NO    NO
 acme/payment-gateway-sdk       2.3.1        >=5.6 <8.0           NO    NO
 phpoffice/phpexcel             1.8.2        ^5.2|^7.0            NO    NO
 ...
 abandoned  swiftmailer/swiftmailer v6.3.0  ->  symfony/mailer
 extension  acme/payment-gateway-sdk requires ext-mcrypt [removed]

 Complexity: HIGH - STRANGLER FIG RECOMMENDED · Estimated effort: 3-6+ months

╭────────────────────────────────────────────────────────────────────────────╮
│ Next steps                                                                 │
├────────────────────────────────────────────────────────────────────────────┤
│ 1. Patch: PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later, then reload FPM. │
│ 2. Contain at the edge: configs/nginx-multipart-guard.conf,                │
│    configs/cloudflare-waf-rules.json                                       │
│ 3. Harden FPM: configs/php-fpm-hardening.ini                               │
│ 4. Can't upgrade overnight? docs/STRANGLER_FIG_RFC_TEMPLATE.md             │
│ 5. Share safely: php2shell-audit --json > audit-summary.json               │
╰────────────────────────────────────────────────────────────────────────────╯
```

(Finding details and fixes are abbreviated here. The real report prints them for every
non-PASS finding.)

## What it checks

| Module | Check | Severity |
|---|---|---|
| Runtime | PHP < 8.2 (7.0 – 8.1, any 5.x) | **CRITICAL**: EOL, no upstream patch |
| Runtime | 8.2.x – 8.5.x below 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | **HIGH**: unpatched runtime |
| Runtime | CLI scan without `--ini` | WARNING; auto-discovers the sibling FPM `php.ini` (+ `conf.d`) and reports CLI ↔ FPM drift |
| CVE-2026-109618 | `memory_limit = -1`, `post_max_size = 0`, or `post_max_size >= memory_limit` | **CRITICAL** |
| CVE-2026-109618 | OOM headroom ratio `memory_limit / post_max_size < 4.0` | **HIGH** |
| CVE-2026-109618 | `max_input_vars > 1000`, `max_input_nesting_level > 32`, `upload_max_filesize > post_max_size` | WARNING |
| CVE-2026-109619 | `session.upload_progress.enabled = On` | **HIGH** |
| CVE-2026-109619 | `max_multipart_body_parts` unset, `> 150`, or unsupported by the runtime | WARNING |
| CVE-2026-109619 | FPM `pm.max_requests` = 0 / unset / `> 1000` in any pool | **HIGH** |
| FPM | Pool `php_admin_value[...]` overrides applied; diverging overrides across pools | WARNING |
| Composer | Packages whose `require.php` excludes PHP 8.3 or 8.4 (incl. root `platform`) | WARNING + blocker table |
| Composer | `"abandoned"` packages, with replacement | WARNING |
| Composer | `ext-mcrypt`, `ext-mysql`, `ext-ereg`, `ext-wddx`, `ext-interbase`, `ext-recode` (removed); `ext-imap`, `ext-pspell`, `ext-oci8` (unbundled in 8.4); ionCube / SourceGuardian loaders | WARNING |
| Composer | Migration complexity score + effort range | INFO |

Pool files are parsed per section, `include=` globs are followed, and per-pool
`php_value`/`php_admin_value`/`php_flag`/`php_admin_flag` overrides are applied when every
pool agrees.

## The math behind the findings

### CVE-2026-109618: OOM headroom ratio

PHP turns a request body into Zend HashTables (`$_POST`, `$_FILES`, nested `a[b][c]` arrays)
**before your code runs**. Each variable is a bucket, each nesting level a new table, and
each multipart part carries parser state. In practice that representation is **3×–8× larger
than the raw payload**. When the parse crosses `memory_limit`, the Zend engine bails out with
a `longjmp()` out of the middle of parsing. CVE-2026-109618 is the class of bug where that
jump leaves HashTable and request state half-initialized, and later code trusts it.

The auditor measures how close a maximum-size request can push a worker to that cliff:

```text
OOM headroom ratio = memory_limit / post_max_size

  128M / 64M  = 2.0   → HIGH      (a 64M body expanding 3x needs 192M)
  128M / 128M = 1.0   → CRITICAL  (post_max_size >= memory_limit)
   -1  / any  = n/a   → CRITICAL  (no ceiling at all)
  256M / 8M   = 32.0  → PASS      (configs/php-fpm-hardening.ini)
```

A ratio of 4 or more keeps a full-size body inside the expected expansion band with room left
for the application. It's a **containment heuristic, not a fix**. The patched runtimes remove
the corruption itself.

### CVE-2026-109619: stale multipart state and FPM worker recycling

CVE-2026-109619 lets request-owned multipart and upload-progress state outlive its request.
The next request handled by **the same FPM worker** can then use it. Two settings decide how
long that can happen:

- `session.upload_progress.enabled = On` keeps the reported upload-progress trigger path
  live. Turn it off. That's necessary but **not sufficient**, because the multipart parser
  itself runs before PHP code. That's why the edge guard in `configs/` rejects multipart on
  routes that don't need it.
- `pm.max_requests = 0` (the FPM default) means a worker **never exits**, so any corrupted
  heap or request state can serve unrelated users for days. Setting
  `pm.max_requests = 300` (250–500) bounds every worker's lifetime. The audit flags `0`,
  unset, and anything above 1000.

## JSON report and privacy model

`--json` output is built so a CTO can forward it without a security review of its own:

- **Deterministic:** no timestamps, stable key order, stable finding order. Diff two runs
  directly.
- **No hostnames:** `gethostname()`, `php_uname('n')` and `$HOSTNAME` are redacted wherever
  they appear.
- **No absolute paths:** inputs are reported as `provided`, `runtime`, `autodiscovered` or
  `none`. Any remaining path under `/Users`, `/home`, `/root`, `/var/www`, `/srv`, `/opt`,
  `/private` or `/tmp` is redacted.
- **No environment values:** environment variable values are never emitted. The test suite
  plants a canary secret to prove it.
- **FPM pool names** become `pool-1`, `pool-2`, … because they often contain customer
  domains.
- **Kept on purpose:** Composer package names and versions, because blockers can't be
  assessed without them. Private vendor names (for example `acme/*`) will be visible. Remove
  them before sharing if they're sensitive.

Top-level keys: `schema_version`, `tool`, `cves`, `anonymized`, `runtime`, `sources`, `metrics`,
`findings[]`, `composer`, `summary`. Each finding has `id`, `severity`, `module`, `title`,
`detail` and `remediation`.

## Flags

| Flag | Description |
|---|---|
| `--path=<dir\|file>` | Project root containing `composer.lock`, or a lock file path (default: cwd) |
| `--ini=<file>` | Audit this `php.ini` instead of the running SAPI's `ini_get()` values |
| `--fpm-conf=<file>` | `php-fpm.conf` or a pool file. Auto-discovered from common Debian/Ubuntu, RHEL/Remi, Docker and Homebrew paths when omitted |
| `--php-version=<ver>` | Audit a specific version string (default: `PHP_VERSION`) |
| `--json` | Anonymized, deterministic JSON |
| `--ci` | Exit `1` on CRITICAL/HIGH, else `0` |
| `--no-color` | Disable ANSI colours (also `NO_COLOR=1`, and off automatically when stdout isn't a TTY) |
| `--no-discover` | Skip FPM `php.ini`/pool auto-discovery (reproducible CI runs) |
| `--version`, `-h/--help` | Version / usage |

Exit codes: `0` success · `1` CRITICAL/HIGH with `--ci` · `2` usage error or unreadable input.

## Containment configs

| File | Purpose |
|---|---|
| [`configs/nginx-multipart-guard.conf`](configs/nginx-multipart-guard.conf) | Server-wide 415 for multipart outside `/api/v1/upload`, `client_max_body_size 1m` on public routes, `auth_request` session check and fully buffered proxying for uploads. Validated with `nginx -t` and curl (415/413/403) on nginx 1.27. |
| [`configs/cloudflare-waf-rules.json`](configs/cloudflare-waf-rules.json) | Rulesets-API custom rules (multipart outside uploads, cookie-less uploads, oversized query/body) and rate limits, with export-first deploy commands. |
| [`configs/php-fpm-hardening.ini`](configs/php-fpm-hardening.ini) | `conf.d/99-php2shell-hardening.ini` drop-in (ratio 32, upload progress off, input caps) plus pool settings (`pm.max_requests = 300`, `php_admin_*`). The test suite audits it. |

## Compatibility

`bin/php2shell-audit` uses only core, `json` and `pcre`. CI runs the full suite on PHP **7.0,
7.1, 7.4, 8.0, 8.1, 8.2, 8.3, 8.4 and 8.5**. The script refuses to run under a web SAPI, so a
copy accidentally left in a docroot returns 404 instead of a report.

Audit the auditor. This returns nothing:

```bash
grep -nE '\b(curl_[a-z_]+|fsockopen|stream_socket_client|file_put_contents|fputcsv|unlink|rename|mkdir|exec|shell_exec|system|passthru|proc_open|popen|mail)\s*\(' bin/php2shell-audit
```

## Development

```bash
make test         # lint + 113 assertions (fixtures, JSON schema, anonymization, exit codes, read-only guarantee)
make lint         # php -l on the CLI and the test runner
make audit-local  # audit the current directory (APP=/var/www/app to override)
make audit-json   # write audit-summary.json
make test-matrix  # run the suite on PHP 7.0 / 7.4 / 8.1 / 8.3 / 8.5 containers (OrbStack)
```

`make test-matrix` uses the `docker` CLI that OrbStack provides. No Docker Desktop is required.

## Limitations

- Distribution packages (Ubuntu/Debian security updates, RHEL) and commercial EOL support
  (for example TuxCare ELS) can backport fixes without changing the upstream version. A
  version with a vendor suffix is flagged with a note to confirm against your vendor's
  advisory.
- Configuration checks reduce exposure. They don't make an unpatched runtime safe.
- Apache `mod_php` / `php_admin_value` in vhosts and `.user.ini` files aren't parsed. Pass the
  effective `php.ini` with `--ini`.
- The Composer constraint evaluator covers the operators used in `require.php` in practice
  (`^ ~ >= > <= < = != || | , -` ranges, wildcards, stability flags). It doesn't cover all of
  composer/semver.

## References

- PHP 8 ChangeLog (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12): <https://www.php.net/ChangeLog-8.php>
- php-src security advisories (GHSA-6wmf-4rv5-p3rp): <https://github.com/php/php-src/security/advisories>
- NVD: [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618) · [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)

---

## When You Can't Upgrade Overnight (Architecture Sprint CTA)

Most teams on PHP 7.x or 8.1 can't just bump the runtime. A payment SDK pinned to `<8.0`, an
`ext-mcrypt` dependency or an abandoned framework turns "upgrade PHP" into a quarter-long
project, while php2shell is exploitable today.

The **[72-Hour php2shell Containment & Strangler Fig Readiness Sprint](docs/SPRINT_OVERVIEW.md)**
($3,000 flat fee) gets you from audit to a defensible plan in three days:

| Day | Outcome |
|---|---|
| **1: Containment** | Edge multipart guard, WAF rules and FPM hardening tailored to your routes, with tests and rollbacks |
| **2: AST & dependency matrix** | Static analysis plus a `composer.lock` blocker matrix with an effort estimate per item |
| **3: Strangler Fig RFC** | An architecture RFC (see the [template](docs/STRANGLER_FIG_RFC_TEMPLATE.md)) for carving high-risk routes into Laravel 11 / PHP 8.4 or Next.js behind a routing layer, with a 60-minute walkthrough |

**To start:**

```bash
php bin/php2shell-audit --path=/var/www/app \
    --ini=/etc/php/7.4/fpm/php.ini --fpm-conf=/etc/php/7.4/fpm/pool.d/www.conf \
    --json > audit-summary.json
```

Review the file. It contains no hostnames, paths or environment values. Then send it to
**Cyrus Espiritu ([@jcyrus](https://github.com/jcyrus))**, Principal Systems & Platform
Modernization Architect.

## License

[BSD 3-Clause](LICENSE) © 2026 John Cyrus Mantec Espiritu (@jcyrus)
