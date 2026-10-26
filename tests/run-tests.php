<?php
declare(strict_types=1);

/*
 * Zero-dependency test runner for php2shell-audit (PHP 7.0 – 8.5).
 * Usage: php tests/run-tests.php
 *
 * Copyright (c) 2026, John Cyrus Mantec Espiritu (@jcyrus28)
 * SPDX-License-Identifier: BSD-3-Clause
 */

$root = dirname(__DIR__);
$bin = $root . '/bin/php2shell-audit';
$fixtures = $root . '/tests/fixtures';

$GLOBALS['p2s_pass'] = 0;
$GLOBALS['p2s_fail'] = 0;

function check($condition, $label)
{
    if ($condition) {
        $GLOBALS['p2s_pass']++;
        fwrite(STDOUT, "  ok    $label" . PHP_EOL);
    } else {
        $GLOBALS['p2s_fail']++;
        fwrite(STDOUT, "  FAIL  $label" . PHP_EOL);
    }
}

function section($name)
{
    fwrite(STDOUT, PHP_EOL . "# $name" . PHP_EOL);
}

function run_cli($bin, array $args)
{
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($bin);
    foreach ($args as $a) {
        $cmd .= ' ' . escapeshellarg($a);
    }
    $spec = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
    $proc = proc_open($cmd, $spec, $pipes);
    if (!is_resource($proc)) {
        return array(-1, '', 'proc_open failed');
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    return array($code, (string) $stdout, (string) $stderr);
}

function finding_ids(array $report, $severity = null)
{
    $ids = array();
    foreach ($report['findings'] as $f) {
        if ($severity === null || $f['severity'] === $severity) {
            $ids[] = $f['id'];
        }
    }
    return $ids;
}

function contains_token($haystack, $needle)
{
    if (strlen($needle) < 4) {
        return false;
    }
    return preg_match('/(?<![A-Za-z0-9_])' . preg_quote($needle, '/') . '(?![A-Za-z0-9_])/', $haystack) === 1;
}

// Canary: must never appear in any output.
$canary = 'p2s-canary-' . bin2hex(random_bytes(8));
putenv('P2S_CANARY_SECRET=' . $canary);
putenv('NO_COLOR');

/* ---------------------------------------------------------------------- */
section('Syntax');
foreach (array($bin, __FILE__) as $file) {
    list($code, $out) = run_cli('-l', array($file));
    check($code === 0 && strpos($out, 'No syntax errors') !== false, 'php -l ' . basename($file));
}

/* ---------------------------------------------------------------------- */
section('Read-only guarantee');
$cliSource = (string) file_get_contents($bin);
$forbidden = array(
    'network' => '/\b(curl_[a-z_]+|fsockopen|pfsockopen|stream_socket_client|socket_create|get_headers|dns_get_record|gethostbyname|mail)\s*\(/i',
    'writes' => '/\b(file_put_contents|fputcsv|unlink|rename|rmdir|mkdir|copy|touch|chmod|chown|tempnam|tmpfile)\s*\(/i',
    'execution' => '/\b(exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec|eval|assert)\s*\(|`/i',
);
foreach ($forbidden as $label => $pattern) {
    check(preg_match($pattern, $cliSource) === 0, 'CLI source contains no ' . $label . ' calls');
}
check(preg_match_all('/\bfopen\s*\(([^)]*)\)/', $cliSource, $fopens) === count(array_filter($fopens[1], function ($a) {
    return strpos($a, 'php://std') !== false;
})), 'CLI fopen() only targets php://stdout / php://stderr');

/* ---------------------------------------------------------------------- */
section('Unit: parsing helpers & constraint evaluator');
// Load functions without running main(): strip the shebang and opening tag, then eval.
define('P2S_LIBRARY_MODE', true);
$source = (string) file_get_contents($bin);
$source = preg_replace('/^#![^\n]*\n/', '', $source);
$source = preg_replace('/^<\?php/', '', $source);
eval($source);

check(p2s_parse_bytes('128M') === 134217728, 'parse_bytes 128M');
check(p2s_parse_bytes('1G') === 1073741824, 'parse_bytes 1G');
check(p2s_parse_bytes('512k') === 524288, 'parse_bytes 512k');
check(p2s_parse_bytes('-1') === -1, 'parse_bytes -1');
check(p2s_parse_bytes('8388608') === 8388608, 'parse_bytes raw bytes');
check(p2s_parse_bytes('') === null, 'parse_bytes empty');

$cases = array(
    array('^7.1', '8.3', false),
    array('^7.4 || ^8.0', '8.3', true),
    array('^5.6|^7.0', '8.3', false),
    array('~7.4', '8.3', false),
    array('~8.0.0', '8.3', false),
    array('>=7.1 <8.0', '8.3', false),
    array('>=7.2,<8.2', '8.3', false),
    array('>=7.4 <8.4', '8.3', true),
    array('>=7.4 <8.4', '8.4', false),
    array('>=8.1', '8.4', true),
    array('>= 5.5', '8.4', true),
    array('7.*', '8.3', false),
    array('8.*', '8.4', true),
    array('7.0 - 7.4', '8.3', false),
    array('7.0 - 8', '8.4', true),
    array('^0.3', '8.3', false),
    array('*', '8.4', true),
    array('^8.3@dev', '8.3', true),
);
foreach ($cases as $c) {
    check(p2s_constraint_supports_branch($c[0], $c[1]) === $c[2], sprintf('constraint "%s" supports %s => %s', $c[0], $c[1], $c[2] ? 'yes' : 'no'));
}

check(p2s_classify_runtime('7.4.33')['status'] === 'eol', 'classify 7.4.33 eol');
check(p2s_classify_runtime('8.1.31')['status'] === 'eol', 'classify 8.1.31 eol');
check(p2s_classify_runtime('8.2.34')['status'] === 'unpatched', 'classify 8.2.34 unpatched');
check(p2s_classify_runtime('8.2.35')['status'] === 'patched', 'classify 8.2.35 patched');
check(p2s_classify_runtime('8.4.26')['status'] === 'unpatched', 'classify 8.4.26 unpatched');
check(p2s_classify_runtime('8.5.12')['status'] === 'patched', 'classify 8.5.12 patched');
check(p2s_classify_runtime('8.3.6-1ubuntu1.4')['status'] === 'unpatched', 'classify distro-suffixed 8.3.6 unpatched');
check(p2s_classify_runtime('8.6.0')['status'] === 'newer', 'classify 8.6.0 newer');

/* ---------------------------------------------------------------------- */
section('Vulnerable: PHP 7.4 ini + www.conf + legacy composer.lock (directory form)');
$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'p2s-test-' . bin2hex(random_bytes(6));
mkdir($tmp);
copy($fixtures . '/legacy-composer.lock', $tmp . '/composer.lock');

$vulnArgs = array(
    '--ini=' . $fixtures . '/vulnerable-php74.ini',
    '--fpm-conf=' . $fixtures . '/vulnerable-www.conf',
    '--path=' . $tmp,
    '--php-version=7.4.33',
    '--no-discover',
);
list($code, $out, $err) = run_cli($bin, array_merge($vulnArgs, array('--json')));
$report = json_decode($out, true);
check($code === 0, 'exit 0 without --ci');
check(is_array($report), 'JSON decodes');
check($err === '', 'no stderr output');
if (!is_array($report)) {
    $report = array('findings' => array(), 'composer' => null, 'summary' => array(), 'sources' => array());
}

$critical = finding_ids($report, 'CRITICAL');
$high = finding_ids($report, 'HIGH');
check(in_array('runtime.eol', $critical, true), 'CRITICAL runtime.eol');
check(in_array('oom.headroom_ratio', $high, true), 'HIGH oom.headroom_ratio (128M / 64M = 2.0)');
check(in_array('multipart.upload_progress', $high, true), 'HIGH multipart.upload_progress');
check(in_array('fpm.max_requests', $high, true), 'HIGH fpm.max_requests (pm.max_requests = 0)');
check(in_array('oom.max_input_vars', finding_ids($report, 'WARNING'), true), 'WARNING oom.max_input_vars');
check(in_array('multipart.body_parts', finding_ids($report, 'WARNING'), true), 'WARNING multipart.body_parts');
check(isset($report['summary']['overall_risk']) && $report['summary']['overall_risk'] === 'CRITICAL', 'overall_risk CRITICAL');
check(isset($report['summary']['ci_exit_code']) && $report['summary']['ci_exit_code'] === 1, 'summary.ci_exit_code = 1');
check(isset($report['metrics']['oom_headroom_ratio']) && abs($report['metrics']['oom_headroom_ratio'] - 2.0) < 0.001, 'metrics.oom_headroom_ratio = 2.0');
check(isset($report['sources']) && $report['sources'] === array('ini' => 'provided', 'fpm_conf' => 'provided', 'composer_lock' => 'found'), 'sources labelled without paths');

$composer = isset($report['composer']) && is_array($report['composer']) ? $report['composer'] : array('php_blockers' => array(), 'abandoned' => array(), 'extension_blockers' => array(), 'complexity' => '', 'packages_total' => 0);
$blockers = array();
foreach ($composer['php_blockers'] as $b) {
    $blockers[] = $b['name'];
}
$expectedBlockers = array(
    '(root project)',
    'acme/billing-core',
    'acme/legacy-auth',
    'acme/payment-gateway-sdk',
    'acme/report-engine',
    'fzaninotto/faker',
    'phpoffice/phpexcel',
    'phpunit/phpunit',
    'zendframework/zend-diactoros',
);
check($blockers === $expectedBlockers, 'all PHP 8.3/8.4 blockers detected exactly (' . count($expectedBlockers) . ')');
$billing = null;
foreach ($composer['php_blockers'] as $b) {
    if ($b['name'] === 'acme/billing-core') {
        $billing = $b;
    }
}
check($billing !== null && $billing['blocks_php83'] === false && $billing['blocks_php84'] === true, 'acme/billing-core blocks 8.4 only');

$abandoned = array();
foreach ($composer['abandoned'] as $a) {
    $abandoned[$a['name']] = $a['replacement'];
}
check($abandoned === array(
    'fzaninotto/faker' => null,
    'phpoffice/phpexcel' => 'phpoffice/phpspreadsheet',
    'swiftmailer/swiftmailer' => 'symfony/mailer',
    'zendframework/zend-diactoros' => 'laminas/laminas-diactoros',
), 'abandoned packages + replacements detected');

$exts = array();
foreach ($composer['extension_blockers'] as $e) {
    $exts[] = $e['name'] . ':' . $e['extension'] . ':' . $e['status'];
}
check($exts === array('acme/payment-gateway-sdk:ext-mcrypt:removed', 'php-imap/php-imap:ext-imap:unbundled'), 'C-extension blockers detected');
check($composer['complexity'] === 'HIGH - STRANGLER FIG RECOMMENDED', 'complexity HIGH - STRANGLER FIG RECOMMENDED');
check($composer['packages_total'] === 19, 'packages_total = 19');

list($code) = run_cli($bin, array_merge($vulnArgs, array('--ci', '--no-color')));
check($code === 1, '--ci exits 1 on CRITICAL/HIGH');

list($code, $fileFormOut) = run_cli($bin, array(
    '--ini=' . $fixtures . '/vulnerable-php74.ini',
    '--fpm-conf=' . $fixtures . '/vulnerable-www.conf',
    '--path=' . $fixtures . '/legacy-composer.lock',
    '--php-version=7.4.33', '--no-discover', '--json',
));
$fileForm = json_decode($fileFormOut, true);
check(is_array($fileForm) && count($fileForm['composer']['php_blockers']) === count($expectedBlockers), '--path accepts a composer.lock file directly');

/* ---------------------------------------------------------------------- */
section('Hardened: PHP 8.3.36 ini');
$hardArgs = array(
    '--ini=' . $fixtures . '/hardened-php83.ini',
    '--php-version=8.3.36',
    '--path=' . $fixtures,
    '--no-discover',
);
list($code, $out) = run_cli($bin, array_merge($hardArgs, array('--json')));
$hard = json_decode($out, true);
check(is_array($hard), 'JSON decodes');
if (!is_array($hard)) {
    $hard = array('findings' => array(), 'summary' => array());
}
$hardCritHigh = array_merge(finding_ids($hard, 'CRITICAL'), finding_ids($hard, 'HIGH'));
check(count($hardCritHigh) === 0, 'no CRITICAL/HIGH findings (' . implode(',', $hardCritHigh) . ')');
$runtimeIniWarnings = array();
foreach ($hard['findings'] as $f) {
    if ($f['severity'] !== 'PASS' && $f['severity'] !== 'INFO' && in_array($f['module'], array('runtime', 'cve-2026-109618'), true)) {
        $runtimeIniWarnings[] = $f['id'];
    }
    if ($f['severity'] === 'WARNING' && $f['module'] === 'cve-2026-109619' && $f['id'] !== 'fpm.max_requests') {
        $runtimeIniWarnings[] = $f['id'];
    }
}
check(count($runtimeIniWarnings) === 0, 'runtime + INI checks all pass (' . implode(',', $runtimeIniWarnings) . ')');
foreach (array('runtime.patched', 'oom.headroom_ratio', 'oom.max_input_vars', 'oom.max_input_nesting_level', 'multipart.upload_progress', 'multipart.body_parts') as $id) {
    check(in_array($id, finding_ids($hard, 'PASS'), true), 'PASS ' . $id);
}
check(in_array('composer.lock_missing', finding_ids($hard, 'INFO'), true), 'missing composer.lock reported as INFO');
list($code) = run_cli($bin, array_merge($hardArgs, array('--ci', '--no-color')));
check($code === 0, '--ci exits 0');

/* ---------------------------------------------------------------------- */
section('Shipped configs');
list($code, $out) = run_cli($bin, array('--ini=' . $root . '/configs/php-fpm-hardening.ini', '--php-version=8.3.36', '--path=' . $fixtures, '--no-discover', '--json'));
$shipped = json_decode($out, true);
check(is_array($shipped) && count(array_merge(finding_ids($shipped, 'CRITICAL'), finding_ids($shipped, 'HIGH'))) === 0, 'configs/php-fpm-hardening.ini yields no CRITICAL/HIGH');
check(is_array($shipped) && $shipped['metrics']['oom_headroom_ratio'] >= 4.0, 'configs/php-fpm-hardening.ini headroom ratio >= 4');
$waf = json_decode((string) file_get_contents($root . '/configs/cloudflare-waf-rules.json'), true);
check(is_array($waf) && count($waf['rulesets']) === 2 && count($waf['rulesets'][0]['rules']) >= 4, 'configs/cloudflare-waf-rules.json parses with custom + rate-limit rulesets');
$nginx = (string) file_get_contents($root . '/configs/nginx-multipart-guard.conf');
check(strpos($nginx, 'client_max_body_size        1m;') !== false && strpos($nginx, 'location = /api/v1/upload') !== false, 'configs/nginx-multipart-guard.conf caps public bodies and isolates /api/v1/upload');

/* ---------------------------------------------------------------------- */
section('Runtime baselines via --php-version');
list($code, $out) = run_cli($bin, array('--ini=' . $fixtures . '/hardened-php83.ini', '--path=' . $fixtures, '--no-discover', '--json', '--php-version=8.4.26'));
$r = json_decode($out, true);
check(is_array($r) && in_array('runtime.unpatched', finding_ids($r, 'HIGH'), true), '8.4.26 => HIGH runtime.unpatched');
list($code, $out) = run_cli($bin, array('--ini=' . $fixtures . '/hardened-php83.ini', '--path=' . $fixtures, '--no-discover', '--json', '--php-version=8.4.27'));
$r = json_decode($out, true);
check(is_array($r) && in_array('runtime.patched', finding_ids($r, 'PASS'), true), '8.4.27 => PASS runtime.patched');
list($code, $out) = run_cli($bin, array('--ini=' . $fixtures . '/hardened-php83.ini', '--path=' . $fixtures, '--no-discover', '--json', '--php-version=8.1.31'));
$r = json_decode($out, true);
check(is_array($r) && in_array('runtime.eol', finding_ids($r, 'CRITICAL'), true), '8.1.31 => CRITICAL runtime.eol');

/* ---------------------------------------------------------------------- */
section('JSON anonymization');
list($code, $runtimeOut) = run_cli($bin, array('--json', '--path=' . $tmp));
$runtimeReport = json_decode($runtimeOut, true);
check(is_array($runtimeReport), 'runtime-mode JSON decodes');
$required = array('schema_version', 'tool', 'runtime', 'sources', 'metrics', 'findings', 'composer', 'summary');
foreach (array($report, $hard, $runtimeReport) as $i => $payload) {
    $missing = array();
    foreach ($required as $key) {
        if (!is_array($payload) || !array_key_exists($key, $payload)) {
            $missing[] = $key;
        }
    }
    check(count($missing) === 0, 'payload #' . ($i + 1) . ' has required keys' . (count($missing) ? ' (missing ' . implode(',', $missing) . ')' : ''));
}

$hostname = (string) gethostname();
$home = (string) getenv('HOME');
foreach (array('vulnerable' => json_encode($report), 'hardened' => json_encode($hard), 'runtime' => $runtimeOut) as $label => $blob) {
    $blob = (string) $blob;
    $raw = stripslashes($blob);
    check(strpos($raw, $canary) === false, "$label: no environment canary");
    check(!contains_token($raw, $hostname), "$label: no hostname");
    check($home === '' || strpos($raw, $home) === false, "$label: no \$HOME path");
    check(strpos($raw, $fixtures) === false && strpos($raw, $root) === false, "$label: no repository/fixture absolute paths");
    check(strpos($raw, $tmp) === false, "$label: no temp project path");
    check(strpos($raw, '/Users/') === false && strpos($raw, '/home/') === false, "$label: no /Users/ or /home/ paths");
}

list($code, $again) = run_cli($bin, array_merge($vulnArgs, array('--json')));
check($again === json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | (defined('JSON_PRESERVE_ZERO_FRACTION') ? JSON_PRESERVE_ZERO_FRACTION : 0)) . PHP_EOL, 'JSON output is deterministic across runs');

/* ---------------------------------------------------------------------- */
section('Terminal output & CLI contract');
list($code, $out) = run_cli($bin, array_merge($vulnArgs, array('--no-color')));
check($code === 0, 'text mode exits 0');
check(strpos($out, "\033[") === false, '--no-color emits no ANSI escapes');
foreach (array('[CRITICAL]', '[HIGH]', '[WARNING]', 'COMPOSER BLOCKERS', 'STRANGLER_FIG_RFC_TEMPLATE.md', 'configs/') as $needle) {
    check(strpos($out, $needle) !== false, 'text report contains ' . $needle);
}

list($code, $out) = run_cli($bin, array('--help'));
check($code === 0 && strpos($out, '--fpm-conf') !== false, '--help exits 0 and documents flags');
list($code, , $err) = run_cli($bin, array('--bogus'));
check($code === 2 && strpos($err, 'Unknown option') !== false, 'unknown flag exits 2');
list($code, , $err) = run_cli($bin, array('--ini=' . $fixtures . '/does-not-exist.ini', '--no-discover'));
check($code === 2 && strpos($err, 'Cannot read --ini') !== false, 'missing --ini file exits 2');
list($code, , $err) = run_cli($bin, array('--php-version=banana', '--no-discover'));
check($code === 2, 'invalid --php-version exits 2');
list($code, , $err) = run_cli($bin, array('--path=' . $tmp . '/missing-dir', '--no-discover'));
check($code === 2, 'missing --path exits 2');

/* ---------------------------------------------------------------------- */
@unlink($tmp . '/composer.lock');
@rmdir($tmp);

$total = $GLOBALS['p2s_pass'] + $GLOBALS['p2s_fail'];
fwrite(STDOUT, PHP_EOL . sprintf('%d/%d assertions passed on PHP %s', $GLOBALS['p2s_pass'], $total, PHP_VERSION) . PHP_EOL);
exit($GLOBALS['p2s_fail'] === 0 ? 0 : 1);
