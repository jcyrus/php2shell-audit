# 72-Hour php2shell Containment & Strangler Fig Readiness Sprint

**Fixed scope · $3,000 flat fee · Delivered by Cyrus Espiritu ([@jcyrus](https://github.com/jcyrus)),
Principal Systems & Platform Modernization Architect**

---

## Who this is for

CTOs, VPs of Engineering and DevOps leads who:
- run PHP 7.x, 8.0 or 8.1 in production, or 8.2+ that they can't patch to 8.2.35 / 8.3.36 /
  8.4.27 / 8.5.12 right away;
- got CRITICAL or HIGH findings from `php2shell-audit`; and
- need php2shell (CVE-2026-109618 / CVE-2026-109619) contained this week, plus a credible
  modernization plan their board and auditors will accept.

## What you get in 72 hours

### Day 1: Edge and FPM containment

Goal: no unauthenticated multipart body reaches your PHP runtime.

- Review of your anonymized `audit-summary.json`, nginx/Apache vhosts, Cloudflare (or other
  CDN/WAF) setup, and PHP-FPM pools.
- A tailored multipart guard. Uploads are isolated to authenticated routes, bodies are capped
  on public routes, and the auth sub-request runs before any body reaches PHP. Based on
  `configs/nginx-multipart-guard.conf`, adapted to your real routes.
- Cloudflare custom rules and rate limits matched to your plan's capabilities.
- FPM hardening:
  - `pm.max_requests` recycling;
  - a `memory_limit / post_max_size` ratio of 4 or more;
  - upload progress off;
  - `max_input_vars`, nesting and multipart part caps; and
  - a split upload pool where needed.
- A validation run: before/after `php2shell-audit --ci` results, plus a curl test matrix your
  team can rerun.
- Rollback steps for every change.

**Deliverable:** a pull request (or config bundle) with the containment changes, a test
matrix, and a rollout and rollback runbook.

### Day 2: AST and dependency matrix

Goal: know exactly what blocks PHP 8.3/8.4 and what it will cost.

- A static analysis pass over a read-only copy of your codebase, run locally in an isolated
  OrbStack container (never on your servers):
  - PHPCompatibility (phpcs) for 8.3/8.4;
  - a Rector dry-run; and
  - an AST scan for removed functions and extensions (`mcrypt_*`, `mysql_*`, `each()`,
    `create_function()`, dynamic properties, and others).
- A dependency matrix built from `composer.lock`. For every package: the constraint blocking
  8.3/8.4, abandonment status, the upgrade or replacement path, and the expected
  breaking-change surface.
- A C-extension and loader inventory (mcrypt, imap, ionCube/SourceGuardian, oci8) with a port
  strategy.
- A route risk inventory from 14 days of access logs: which endpoints accept bodies, which
  need multipart, and who is anonymous.

**Deliverable:** an upgrade-readiness matrix (spreadsheet + markdown) with an effort estimate
per blocker and an overall complexity rating.

### Day 3: Strangler Fig RFC and a 60-minute walkthrough

Goal: a reviewed, decision-ready architecture plan.

- An architecture RFC in the format of `docs/STRANGLER_FIG_RFC_TEMPLATE.md`, written for your
  system. It covers:
  - the routing layer (nginx or a Cloudflare Worker);
  - route tiers;
  - the session bridge that keeps your existing auth authoritative;
  - the first carve-out service (Laravel 11 on PHP 8.4, or Next.js for anonymous pages);
  - rollout stages with SLO gates and rollbacks; and
  - risks and the decisions you need to make.
- A 60-minute live walkthrough with your engineering leadership, recorded for the team.
- A prioritized 90-day roadmap: what to do in-house, what to buy (for example an EOL
  backport), and what to sequence.

**Deliverable:** the RFC, the roadmap, and the walkthrough recording.

## How it works

1. **Run the audit yourself.** Nothing leaves your network until you decide it should.
   ```bash
   php bin/php2shell-audit --path=/var/www/app \
       --ini=/etc/php/7.4/fpm/php.ini \
       --fpm-conf=/etc/php/7.4/fpm/pool.d/www.conf \
       --json > audit-summary.json
   ```
   The JSON is anonymized: no hostnames, absolute paths or environment values. Package names
   are kept so blockers can be assessed. Read it before you send it.
2. **Send `audit-summary.json` to [@jcyrus](https://github.com/jcyrus)** with your
   preferred start date. You'll get a scoped confirmation within one business day.
3. **Kick off.** We hold a 30-minute call, you grant read-only access (config exports and a
   code snapshot), and the 72-hour clock starts.

## Engagement principles

- **Read-only by default.** I never run anything against production. Every change ships as a
  reviewable diff your team applies.
- **No exploit testing on your systems.** Validation uses configuration analysis and benign
  request-shape tests (415/413/401 checks) that your team runs.
- **Your data stays yours.** Code snapshots are analyzed in an isolated container and deleted
  at the end of the sprint. NDA available on request.
- **Fixed scope, fixed fee.** $3,000 for the three days above. No hourly billing and no
  open-ended retainer.

## Out of scope (available as follow-on work)

- Implementing the carve-out services or the full PHP 8.4 migration.
- Penetration testing or exploit development.
- 24/7 incident response.

## Why this sprint

php2shell is pre-authentication RCE in PHP's request parsing. EOL branches will not get an
upstream fix. Your realistic options are:
1. contain the attack surface at the edge and in FPM now;
2. buy time with a vendor backport if one exists for your branch; and
3. move the riskiest routes onto a patched runtime without a big-bang rewrite.

This sprint delivers the first and the plan for the third in three days, with artifacts your
team owns.

---

**Start here:** `php bin/php2shell-audit --json > audit-summary.json`, then contact
[@jcyrus](https://github.com/jcyrus).
