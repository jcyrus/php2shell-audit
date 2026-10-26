# RFC-0042: Contain php2shell and Strangle the Legacy PHP 7.4 Monolith

> **How to use this template.** This is a complete, worked RFC for a fictional but
> representative company ("Acme Commerce"). Every value is concrete so the document can be
> reviewed as-is. To adapt it, replace Acme's route names, hostnames, sockets and numbers with
> the ones from your `php2shell-audit --json` report and your access logs. Keep the structure:
> reviewers rely on it.

| Field | Value |
|---|---|
| RFC | 0042 |
| Title | Contain php2shell and strangle the legacy PHP 7.4 monolith |
| Status | Draft, for architecture review |
| Date | 2026-10-26 |
| Author | Platform Engineering |
| Reviewers | CTO, Head of Security, Payments lead, SRE on-call lead |
| Related | CVE-2026-109618, CVE-2026-109619, `audit-summary.json` (php2shell-audit 1.0.0) |
| Decision deadline | 2026-11-06 |

---

## 1. Summary

Acme's customer-facing monolith runs PHP 7.4.33. That branch is end-of-life and will not receive
upstream fixes for **php2shell**. php2shell covers CVE-2026-109618, which corrupts state through an
out-of-memory `longjmp()` during request parsing. It also covers CVE-2026-109619, where stale
multipart and upload-progress state is reused across requests on the same worker. Both are
CVSS 9.2 and allow unauthenticated remote code execution.

An in-place upgrade to PHP 8.4 is blocked by 15 dependency items:
- 9 packages whose `require.php` pins PHP below 8.3/8.4.
- 4 abandoned packages.
- 2 C-extension requirements, including `ext-mcrypt`, which PHP no longer ships.

This RFC proposes three moves:

1. **Contain now (72 hours).** Put an edge routing layer in front of the monolith. It rejects
   multipart bodies on every public route, caps body sizes, and recycles FPM workers.
2. **Carve out the high-risk surface (weeks 1–6).** Move the only legitimate upload flow to a
   **Laravel 11 / PHP 8.4.27+** service behind the same router. Move anonymous catalogue and
   marketing pages to **Next.js**.
3. **Strangle incrementally (months 2–6).** Migrate remaining routes by risk tier while the
   legacy session stays authoritative through a signed session bridge.

## 2. Context

### 2.1 Audit findings (from `audit-summary.json`)

| Area | Finding | Severity |
|---|---|---|
| Runtime | PHP 7.4.33, EOL, no upstream patch | CRITICAL |
| OOM math | `memory_limit` 128M / `post_max_size` 64M = **2.0** headroom ratio (min 4.0) | HIGH |
| Multipart | `session.upload_progress.enabled = On` | HIGH |
| FPM | `pm.max_requests = 0` (workers never recycled) | HIGH |
| Input | `max_input_vars = 5000`, `max_input_nesting_level = 64` | WARNING |
| Composer | 9 PHP blockers, 4 abandoned, `ext-mcrypt` + `ext-imap` | HIGH migration complexity |

### 2.2 Why patching alone is not available

- `acme/payment-gateway-sdk` 2.3.1 requires `php >=5.6 <8.0` and `ext-mcrypt`. A replacement
  needs the card processor to certify a new client, which is 6–10 weeks on their side.
- `acme/legacy-auth` (`~7.4`) owns sessions and SSO. Rewriting it is a multi-month project.
- `zendframework/zend-diactoros`, `phpoffice/phpexcel` and `fzaninotto/faker` are abandoned
  and each has a different replacement path.

A commercial EOL backport (for example TuxCare ELS for PHP 7.4) is a valid **parallel**
stopgap. It does not remove the dependency debt, so this RFC treats it as complementary.

### 2.3 Why the routing layer is the right lever

php2shell is reached through **request parsing**: PHP's RFC1867 multipart parser and the
HashTables built for `$_POST`/`$_FILES` before any application code runs. An edge layer that:
- refuses `multipart/form-data` on routes that never need it,
- caps body and query sizes, and
- authenticates the single upload route before the body reaches PHP

removes nearly all of the unauthenticated attack surface without touching application code.
The same layer then becomes the Strangler Fig façade.

## 3. Goals and non-goals

**Goals**
- G1: No unauthenticated multipart body reaches PHP 7.4 within 72 hours of approval.
- G2: Every FPM worker serving PHP 7.4 is recycled after ≤ 300 requests.
- G3: The upload flow runs on a patched PHP 8.4 runtime within 6 weeks.
- G4: Users never re-authenticate because of the migration. One session stays authoritative.
- G5: Any routing change can be rolled back in under 5 minutes with one config flip.

**Non-goals**
- Rewriting checkout, payments or SSO in this phase. Those are tier 3 (see §6).
- Changing the database engine or schema beyond the `uploads` table.
- Big-bang framework migration.

## 4. Current architecture

```text
             ┌──────────────┐
 Internet ──▶│  Cloudflare  │  (DNS + CDN, no WAF rules for multipart)
             └──────┬───────┘
                    ▼
             ┌──────────────┐      unix socket      ┌──────────────────────────┐
             │ nginx 1.24   │──────────────────────▶│ php7.4-fpm  [www] pool    │
             │ (single vhost│                       │ pm.max_requests = 0      │
             │  1 location) │                       │ memory 128M / post 64M   │
             └──────────────┘                       └───────────┬──────────────┘
                                                                ▼
                                                  MySQL 8 · Redis (cache) · local disk uploads
```

## 5. Target architecture

```text
             ┌───────────────────────────────────────────────────────────────┐
 Internet ──▶│ Cloudflare: WAF custom rules + rate limits (configs/*.json)   │
             └──────────────────────────────┬────────────────────────────────┘
                                            ▼
             ┌───────────────────────────────────────────────────────────────┐
             │ nginx router (the Strangler Fig façade)                       │
             │  • map: multipart only on /api/v1/upload (else 415)           │
             │  • auth_request → legacy session-check (signed identity)      │
             │  • split_clients canary per carved route                      │
             └───────┬────────────────────┬─────────────────────┬────────────┘
                     │ fastcgi            │ http                │ http
                     ▼                    ▼                     ▼
          ┌──────────────────┐  ┌─────────────────────┐  ┌──────────────────┐
          │ php7.4-fpm [www] │  │ upload-svc          │  │ web-next         │
          │ legacy monolith  │  │ Laravel 11, PHP 8.4 │  │ Next.js (public  │
          │ no multipart     │  │ pm.max_requests=300 │  │ GET pages only)  │
          │ max_requests=300 │  └─────────┬───────────┘  └────────┬─────────┘
          └────────┬─────────┘            │ S3 + uploads table    │ read API
                   ▼                      ▼                       ▼
                     MySQL 8 (shared) · Redis (sessions) · S3 (objects)
```

## 6. Route inventory and risk tiers

Build the inventory from 14 days of access logs. With the default `combined` log format:

```bash
# Requests per route and method, with the share of multipart bodies.
# Requires $content_type in the log format (see §11.1); without it, rank by method only.
zcat -f /var/log/nginx/access.log* \
  | awk '{print $6, $7}' | sed -E 's/"//g; s/\?.*$//' \
  | sort | uniq -c | sort -rn | head -50
```

| Tier | Routes (Acme) | Traffic | Auth | Multipart today | Target | Phase |
|---|---|---|---|---|---|---|
| 0: block | `POST /` and any route that never accepted uploads | n/a | none | attacker-only | 415 at edge | Day 1 |
| 1: upload | `POST /account/documents`, `POST /admin/import` | 0.4% | session | yes | `POST /api/v1/upload` on upload-svc | Weeks 1–6 |
| 2: anonymous read | `/`, `/catalog/*`, `/blog/*`, `/help/*` | 71% | none | no | Next.js `web-next` | Weeks 4–12 |
| 2: JSON API | `/api/v1/orders`, `/api/v1/me` | 9% | session | no | Laravel 11 | Months 2–4 |
| 3: critical | `/checkout/*`, `/payments/*`, `/sso/*` | 6% | session | no | stays on legacy until payment SDK is recertified | Months 4–6+ |

Tier 0 ships with containment. Each later tier moves only after the previous one meets its
SLOs (see §12) for 7 consecutive days.

## 7. Routing layer

### 7.1 Option A (chosen): nginx router

The router is the `configs/nginx-multipart-guard.conf` from php2shell-audit plus the canary
block below. nginx is already in the request path, the team operates it daily, and
`auth_request` gives a body-free session check before upload bytes reach any backend.

```nginx
# http {} — choose the upload backend per client, deterministically.
split_clients "${remote_addr}${http_user_agent}" $p2s_upload_pool {
    10%  p2s_upload_modern;   # Stage 1; raise to 50% then 100% (see §10)
    *    p2s_upload_legacy;
}

upstream p2s_upload_modern { server 10.0.20.11:8081; server 10.0.20.12:8081; keepalive 16; }
upstream p2s_upload_legacy { server 127.0.0.1:8082; keepalive 8; }

# Legacy upload handler, isolated in its own FPM pool, reachable only via the router.
server {
    listen 127.0.0.1:8082;
    root /var/www/app/public;
    client_max_body_size 20m;
    location = /api/v1/upload {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/app/public/upload.php;
        fastcgi_request_buffering on;
        fastcgi_pass unix:/run/php/php7.4-fpm-uploads.sock;
    }
}
```

In the public `server {}`, the upload location changes `proxy_pass http://p2s_upload_backend;` to:

```nginx
proxy_pass http://$p2s_upload_pool;
```

**Rollback:** set the canary line to `0%` (or remove it), run `nginx -t && systemctl reload nginx`.
This takes under 60 seconds and drops no connections.

### 7.2 Option B (alternative): Cloudflare Worker router

Use this when origin nginx is managed by a hosting provider and can't be changed. The Worker
enforces the same contract at the edge:

```js
// worker.js — deployed with: pnpm dlx wrangler@3 deploy
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const contentType = (request.headers.get("content-type") || "").toLowerCase();
    const isMultipart = contentType.includes("multipart/");

    if (url.pathname === "/api/v1/upload") {
      if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
      if (!(request.headers.get("cookie") || "").includes("PHPSESSID=")) {
        return new Response("Unauthorized", { status: 401 });
      }
      const target = new URL(url.pathname + url.search, env.UPLOAD_ORIGIN);
      return fetch(new Request(target, request));
    }

    if (isMultipart) return new Response("Unsupported Media Type", { status: 415 });

    const len = Number(request.headers.get("content-length") || "0");
    if (len > 1_048_576) return new Response("Payload Too Large", { status: 413 });

    if (env.NEXT_PREFIXES.split(",").some((p) => url.pathname === p || url.pathname.startsWith(p + "/"))) {
      return fetch(new Request(new URL(url.pathname + url.search, env.NEXT_ORIGIN), request));
    }
    return fetch(request);
  },
};
```

```toml
# wrangler.toml
name = "acme-strangler-router"
main = "worker.js"
compatibility_date = "2026-10-01"
routes = [{ pattern = "app.acme-commerce.example/*", zone_name = "acme-commerce.example" }]

[vars]
UPLOAD_ORIGIN = "https://upload-svc.internal.acme-commerce.example"
NEXT_ORIGIN   = "https://web-next.internal.acme-commerce.example"
NEXT_PREFIXES = "/catalog,/blog,/help"
```

The Worker cookie check is a pre-filter. Real session validation still happens at the origin
through the session bridge.

## 8. Shared session and auth: the session bridge

The legacy app stays the **single source of truth** for sessions until tier 3 migrates. New
services never parse PHP session files. They trust a short-lived, HMAC-signed identity that
the router obtains through `auth_request`.

**Flow**
1. The browser sends `POST /api/v1/upload` with its `PHPSESSID` cookie.
2. nginx issues an internal sub-request to `/_p2s_auth`, with no request body.
3. `session-check.php` (PHP 7.4, legacy pool) loads the session read-only. It returns `204`
   with `X-Auth-User-Id` and `X-Auth-Signature = <unix-ts>.<hmac>`, or `401`.
4. nginx copies both headers onto the proxied request and overwrites any client-supplied
   values.
5. Laravel middleware verifies the HMAC and the ±60 s timestamp window, then serves the
   request.

### 8.1 Legacy endpoint: `/var/www/app/internal/session-check.php`

This file lives outside the public docroot and is reachable only through the `internal`
nginx location.

```php
<?php
// Runs on PHP 7.0+. Returns 204 + signed identity, or 401. Never reads a request body.
$secret = getenv('P2S_BRIDGE_SECRET');
if (!is_string($secret) || strlen($secret) < 32) {
    http_response_code(500);
    exit;
}

$cookieName = session_name();
$sid = isset($_COOKIE[$cookieName]) ? (string) $_COOKIE[$cookieName] : '';
if (!preg_match('/^[A-Za-z0-9,-]{22,256}$/', $sid)) {
    http_response_code(401);
    exit;
}

ini_set('session.use_strict_mode', '1');
session_start(array('read_and_close' => true));

// Acme's acme/legacy-auth stores the authenticated user id under this key.
$userId = isset($_SESSION['auth_user_id']) ? (string) $_SESSION['auth_user_id'] : '';
if ($userId === '' || !ctype_digit($userId)) {
    http_response_code(401);
    exit;
}

$ts = (string) time();
header('X-Auth-User-Id: ' . $userId);
header('X-Auth-Signature: ' . $ts . '.' . hash_hmac('sha256', $userId . '|' . $ts, $secret));
http_response_code(204);
```

Provide the secret to the legacy FPM pool with `env[P2S_BRIDGE_SECRET] = <value from your
secret manager>` in the pool file. Provide the same secret to Laravel as
`LEGACY_BRIDGE_SECRET`. Generate it with `openssl rand -hex 32`. Rotate it quarterly: deploy
the new secret to Laravel first (accept old + new), then to the legacy pool, then remove the
old one.

### 8.2 Laravel 11 middleware: `app/Http/Middleware/VerifyLegacySession.php`

```php
<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class VerifyLegacySession
{
    private const MAX_SKEW_SECONDS = 60;

    public function handle(Request $request, Closure $next): Response
    {
        $userId = (string) $request->header('X-Auth-User-Id', '');
        $signature = (string) $request->header('X-Auth-Signature', '');
        $secrets = array_filter([
            (string) config('services.legacy_bridge.secret'),
            (string) config('services.legacy_bridge.previous_secret'),
        ]);

        if ($userId === '' || ! ctype_digit($userId) || ! str_contains($signature, '.') || $secrets === []) {
            abort(401);
        }

        [$timestamp, $mac] = explode('.', $signature, 2);
        if (! ctype_digit($timestamp) || abs(time() - (int) $timestamp) > self::MAX_SKEW_SECONDS) {
            abort(401);
        }

        foreach ($secrets as $secret) {
            if (hash_equals(hash_hmac('sha256', $userId.'|'.$timestamp, $secret), $mac)) {
                $request->attributes->set('legacy_user_id', (int) $userId);

                return $next($request);
            }
        }

        abort(401);
    }
}
```

```php
// config/services.php
'legacy_bridge' => [
    'secret' => env('LEGACY_BRIDGE_SECRET'),
    'previous_secret' => env('LEGACY_BRIDGE_PREVIOUS_SECRET'),
],
```

```php
// bootstrap/app.php (Laravel 11)
->withMiddleware(function (Middleware $middleware) {
    $middleware->alias(['legacy.session' => \App\Http\Middleware\VerifyLegacySession::class]);
    $middleware->trustProxies(at: ['10.0.10.0/24']); // the nginx router subnet
})
```

Only the router subnet can reach upload-svc, enforced by security group or firewall. That
stops anyone from bypassing nginx and forging headers. The HMAC is the second layer.

### 8.3 Next.js pages

Tier 2 Next.js pages are anonymous. For "logged-in" UI chrome they call `GET /api/v1/me`,
which goes through the same bridge to Laravel. Next.js never sees `PHPSESSID` contents.

## 9. Upload service (Laravel 11, PHP 8.4)

```bash
composer create-project laravel/laravel:^11.0 upload-svc
cd upload-svc && php artisan install:api
composer require league/flysystem-aws-s3-v3:^3.0
```

```php
// routes/api.php  →  POST /api/v1/upload
use App\Http\Controllers\UploadController;
use Illuminate\Support\Facades\Route;

Route::post('/v1/upload', UploadController::class)
    ->middleware(['legacy.session', 'throttle:uploads']);
```

```php
// app/Http/Controllers/UploadController.php
<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final class UploadController
{
    public function __invoke(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'document' => ['required', 'file', 'max:20480', 'mimes:pdf,png,jpg,jpeg,csv,xlsx'],
            'kind' => ['required', 'in:invoice,id_document,catalogue_import'],
        ]);

        $userId = (int) $request->attributes->get('legacy_user_id');
        $path = $validated['document']->store("uploads/{$userId}", 's3');

        // The legacy app reads this table; schema unchanged from the PHP 7.4 implementation.
        $id = DB::table('uploads')->insertGetId([
            'user_id' => $userId,
            'kind' => $validated['kind'],
            'storage_path' => $path,
            'original_name' => mb_substr($validated['document']->getClientOriginalName(), 0, 255),
            'size_bytes' => $validated['document']->getSize(),
            'created_at' => now(),
        ]);

        return response()->json(['id' => $id, 'path' => $path], 201);
    }
}
```

```php
// app/Providers/AppServiceProvider.php → boot()
RateLimiter::for('uploads', fn (Request $request) => Limit::perMinute(20)
    ->by((string) ($request->attributes->get('legacy_user_id') ?? $request->ip())));
```

**Runtime contract for upload-svc**
- PHP 8.4.27 or later, which includes the php2shell fixes. CI runs `php2shell-audit --ci` against
  the image.
- FPM: `pm.max_requests = 300`, `memory_limit = 256M`, `post_max_size = 20M` (ratio 12.8),
  `max_multipart_body_parts = 50`, `session.upload_progress.enabled = 0`.
- Image built and tested locally with OrbStack:
  `docker build -t upload-svc:dev . && docker run --rm upload-svc:dev php bin/php2shell-audit --ci`.

## 10. Rollout

| Stage | Change | Exit criteria (7 days unless noted) | Rollback |
|---|---|---|---|
| 0 (Day 1–3) | Edge + FPM containment: guard config, WAF rules, `pm.max_requests = 300`, ratio ≥ 4, upload progress off | No legit 415s in logs for 72 h; 5xx rate unchanged | Remove the `if ($p2s_block_multipart)` line; reload |
| 1 (Week 2) | upload-svc at 10% via `split_clients` | Upload success ≥ 99.5%, p95 ≤ 800 ms (≤ 5 MB), bridge 401 rate ≤ legacy baseline | Canary to 0% |
| 2 (Week 3) | 50% | Same | Canary to 0% |
| 3 (Week 4) | 100%; legacy upload pool kept warm | 14 days clean | Canary to 0% |
| 4 (Week 6) | Delete legacy upload code path and pool; turn multipart off globally on the legacy pool (`enable_post_data_reading = Off` where routes allow) | php2shell-audit on legacy shows no multipart surface | Restore pool from config management |
| 5 (Weeks 4–12) | Next.js for `/catalog`, `/blog`, `/help` via router prefixes | Core Web Vitals ≥ legacy; SEO crawl parity | Remove prefix from router map |

## 11. Observability

### 11.1 Log format

```nginx
log_format p2s '$remote_addr [$time_local] "$request" $status $body_bytes_sent '
               'ct="$content_type" len=$content_length rt=$request_time '
               'up="$upstream_addr" ust=$upstream_status blk=$p2s_block_multipart';
access_log /var/log/nginx/app.p2s.log p2s;
```

### 11.2 Signals and alerts

- `415` rate per route. A spike on a route that has legitimate traffic means a missed
  exemption; page on-call.
- PHP-FPM `exited on signal` / `SIGSEGV` lines and `Allowed memory size ... exhausted` errors.
  Any increase after Stage 0 is a probe or exploitation indicator; page Security.
- Bridge `/_p2s_auth` latency p95 (target ≤ 15 ms) and 5xx rate (target < 0.1%).
- Upload-svc success rate, p95 latency, and S3 put errors.

## 12. SLOs

| SLO | Target | Window |
|---|---|---|
| Upload availability (2xx/4xx-user vs 5xx) | 99.5% | 28 days |
| Upload latency p95 (≤ 5 MB) | ≤ 800 ms | 28 days |
| Session bridge availability | 99.9% | 28 days |
| Legitimate requests blocked by containment | < 0.01% of sessions | 7 days |

## 13. Security considerations

- **Header spoofing:** the router overwrites `X-Auth-*`, upload-svc accepts traffic only from
  the router subnet, and the HMAC binds user ID and timestamp.
- **Replay:** the 60-second window bounds replays. Signed identity is never exposed to
  browsers.
- **Bridge availability:** `auth_request` fails closed (500/401). Uploads stop but no
  unauthenticated body reaches PHP.
- **Residual risk:** authenticated users can still send multipart to the legacy upload pool
  until Stage 3. Mitigations: per-user rate limit, 20 MB cap, ratio ≥ 4, `pm.max_requests = 100`
  on the uploads pool, and a vendor backport if available.
- **Supply chain:** upload-svc dependencies are pinned in `composer.lock` and audited with
  `composer audit` in CI.

## 14. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| A legacy page still posts multipart (unknown form) | Medium | Users see 415 | 72 h log review with `blk=1`; per-route exemption in the map |
| Session key differs across legacy code paths | Low | Bridge returns 401 | Integration test logs in via the legacy UI and calls `/api/v1/upload` |
| Card-processor recertification slips | High | Tier 3 delayed | Tier 3 stays on legacy behind containment; vendor backport contract |
| Recycling (`pm.max_requests = 300`) raises latency | Low | p99 +5–20 ms | `pm = dynamic` with spare servers ≥ 4; observe for 72 h |

## 15. Alternatives considered

1. **In-place upgrade to PHP 8.4.** Rejected for now. It is blocked by `ext-mcrypt`, `~7.4`
   pins and abandoned packages, and is estimated at 3–6 months before it could ship.
2. **WAF rules only.** Rejected as the sole control. Edge rules can't see every encoding of a
   body, and they leave worker state unbounded. Kept as layer 1.
3. **Commercial EOL backport only.** Accepted as a parallel stopgap. It doesn't reduce
   dependency debt, so it isn't a substitute for the carve-out.
4. **Full rewrite.** Rejected. It would take 12+ months with no risk reduction until cutover.

## 16. Decisions requested

| Decision | Recommendation | Owner |
|---|---|---|
| Approve Stage 0 containment for immediate rollout | Approve | CTO |
| Router option | Option A (nginx) | Platform |
| Purchase vendor backport for PHP 7.4 during migration | Approve for 6 months | CTO + Security |
| Upload-svc hosting | Same VPC, two instances behind the router | SRE |

## Appendix A: Stage 0 checklist

- [ ] `configs/php-fpm-hardening.ini` copied to `conf.d/99-php2shell-hardening.ini`. Pool has `pm.max_requests = 300`.
- [ ] `php bin/php2shell-audit --ini=<fpm php.ini> --fpm-conf=<pool> --ci` exits 0 except the runtime CRITICAL.
- [ ] `configs/nginx-multipart-guard.conf` deployed. All three curl checks from its header return 415 / 401 / 413.
- [ ] Cloudflare rules deployed after exporting the existing rule set.
- [ ] `p2s` log format live. Alert on 415 spikes and FPM memory-exhausted errors.
- [ ] Anonymized `audit-summary.json` attached to this RFC.
