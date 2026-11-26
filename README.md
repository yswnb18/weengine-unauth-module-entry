# WeEngine (微擎) — unauthenticated access issues, by vulnerabilit
**Tested against:** official 2.9.13 (`IMS_RELEASE_DATE = 202610280001`, build 2026-10-28, package md5
`d14bcecbfb774d27f41c3c43796e2e05`), plus 1.7.2 and 1.7.7.

> 中文速览：本仓库把 6 个问题拆成 6 个独立检测脚本。**WE7-5、WE7-6 在当前最新版 2.9.13 上仍然存在**；
> WE7-1/2/3 是 1.7.x 的问题、2.9.13 已修；WE7-4 是信息类。所有脚本都是**非破坏性**的：只发 GET，
> 不上传、不写文件、不建/删数据、不发短信邮件。

---

## 0. Index — one vulnerability per script

| ID | Vulnerability class | Component | Affected versions | Status in 2.9.13 | Script |
|---|---|---|---|---|---|
| **WE7-5** | **CWE-862** Missing Authorization (also CWE-306) | `web/source/site/entry.ctrl.php` | **1.7.2 → 2.9.13** | **still vulnerable** | `we7_5_module_entry_bypass.py` |
| **WE7-6** | **CWE-799** Improper Control of Interaction Frequency (also CWE-770) | `web/source/utility/verifycode.ctrl.php` | **1.7.2 → 2.9.13** | **still vulnerable** | `we7_6_verifycode_trigger.py` |
| WE7-1 | **CWE-306** → CWE-434 / CWE-94 | `web/source/cloud/dock.ctrl.php` | 1.7.2 – 1.7.7 | fixed | `we7_1_cloud_dock_rce.py` |
| WE7-2 | **CWE-918** SSRF (full response echo) — **prior art, published 2021-03** (see §0.1) | `web/source/utility/wxcode.ctrl.php` | 1.7.2 – 1.7.7 | allow-list added, **but bypassable → WE7-7** | `we7_2_wxcode_ssrf.py` |
| **WE7-7** | **CWE-918 + CWE-183** incomplete fix: allow-list bypass restores the same SSRF | `web/source/utility/wxcode.ctrl.php:28` | **2.9.13 only** | **still vulnerable** | `we7_7_wxcode_allowlist_bypass.py` |
| WE7-3 | **CWE-434** Unrestricted upload | `web/source/utility/file.ctrl.php` | 1.7.2 – 1.7.7 | fixed | `we7_3_file_upload.py` |
| WE7-4 | **CWE-200** Information exposure (informational) | `web/source/utility/modules.ctrl.php` | 1.7.2 – 2.9.13 | not fixed | `we7_4_module_enum.py` |
| — | runner | — | — | — | `run_all.py` |

Each script is standalone (Python 3, standard library only), prints a verdict and uses exit codes
`0 = not vulnerable / not exposed`, `1 = vulnerable / exposed`, `2 = inconclusive`.

---

## 0.1 Prior art — what was already public, and what is new here

WeEngine has been audited in public before, and what is public includes the fact that
`verifycode`, `file`, `wxcode`, `modules`, `dock` and `site/entry` sit on the no-login `direct`
list. Anything in this repository that only repeats that list is **not** claimed as new. The
honest split:

| Public before | Where | What this repository actually adds |
|---|---|---|
| `c=utility&a=wxcode&do=image&attach=<url>` is an unauthenticated **echo** SSRF, payload published as `attach=http://127.0.1.13:80/`, together with the whole `direct` list | xq17, *代码审计之某通用商城系统getshell过程*, Butian, 2021-03, section `0x04` | **WE7-7 only**: the allow-list that 2.9.13 added to fix it is incomplete and can be walked around |
| `api.php` blind SSRF through `analyzeImage` / `PicUrl` (a different endpoint) | xq17, *微擎最新版前台某处无回显SSRF漏洞*, 2021-08-04 | nothing in this repository |
| `cloud/dock?do=download` reaches `file_put_contents(IA_ROOT.$path, $file)` once `md5(md5(file) . path . token) === sign`; the author states the only missing piece is *"只需要获取拿到 token 值即可"* | Joseph, *微擎sql注入到getshell*, 90sec, 2020-01-16 | **WE7-1**: the unauthenticated `do=callback` branch lets an attacker **set** that token, which removes the "obtain a token first" precondition |

What that means for a CVE submission, stated plainly:

* **WE7-2 is not submitted.** The original SSRF is prior art; a submission would be closed as a duplicate.
* **WE7-7 is the submission for this endpoint**, and it is scoped to 2.9.13, the release that introduced the allow-list.
* **WE7-1 is submitted on the `callback` step**, and its description says up front that the arbitrary-write primitive was published in 2020.
* **WE7-3 is not submitted on its own** — "`utility.file` is on the direct list" is part of the 2021 publication; it stays here as a step in the WE7-1 chain.
* **WE7-5 / WE7-6 are submitted on their consequences**, never on "the endpoint is reachable without a login":
  * WE7-5 = a module backend entry that the module's own `manifest.xml` never declared can be invoked anonymously, while the declared ones are still gated (differential shown in §2);
  * WE7-6 = unlimited SMS / e-mail to an arbitrary recipient: the per-recipient quota is keyed on a caller-supplied `uniacid` (rotate it, quota resets) and the captcha gate — **on by default** — is switched off by the caller sending `need_checkcaptcha=1`.
  * The `site/entry` action appears in the 2021 list as the *framework's own* entry action. The behaviour documented here is different: it is the per-module `direct` flag inside the module's own entry file (`web/source/site/entry.ctrl.php:27-50`), and it is still present in 2.9.13.

---

## 1. Lab results — the differential that the detectors rely on

| check | 1.7.2 | 1.7.7 | 2.9.13 |
|---|---|---|---|
| WE7-1 `dock` download, empty payload | `failed <token>` | `failed <token>` | `cloud service is unavailable.` |
| WE7-2 `wxcode` self-fetch echo | page echoed | page echoed | empty body |
| **WE7-7** `wxcode` allow-list bypass | n/a (no allow-list in 1.7.x) | n/a | **`attach=http://mmbiz.qlogo.cn@host/...` echoed; `mmbiz.qpic.cn@host` and plain URLs empty** |
| WE7-3 `file` upload endpoint (no file sent) | JSON error | JSON error | `302` login |
| WE7-4 `modules` list | module JSON | module JSON | module JSON |
| WE7-5 entry with `direct=1` | `200` page (module had **no** binding rows) | `302` login (that module **has** 7 binding rows — the gate worked) | `200` page for undeclared entries, `302` for declared ones |
| WE7-6 `verifycode` with malformed receiver | error text | error text | JSON error |

`run_all.py` output on the three extremes:

```
target: http://127.0.0.1:8082            # 1.7.2
WE7-1  CWE-306 -> 434/94  unauth file write -> RCE   VULNERABLE
WE7-2  CWE-918  SSRF with response echo              VULNERABLE   (prior art - not submitted)
WE7-7  CWE-918  allow-list bypass                    n/a (1.7.x has no allow-list)
WE7-3  CWE-434  unauth upload endpoint               EXPOSED
WE7-4  CWE-200  module enumeration                   EXPOSED
WE7-6  CWE-799  unauth code trigger                  REACHABLE WITHOUT A SESSION
WE7-5  CWE-862  missing authorization (module entry) VULNERABLE

target: http://127.0.0.1:8084            # 2.9.13 (current)
WE7-1  ... not vulnerable (hardened build: cloud guard reached before the download branch)
WE7-2  ... not vulnerable (no echo without a bypass)
WE7-7  ... BYPASS CONFIRMED (allow-list incomplete; echo received through mmbiz.qlogo.cn@host)
WE7-3  ... not exposed (redirects to the login page)
WE7-4  ... EXPOSED
WE7-6  ... REACHABLE WITHOUT A SESSION
WE7-5  ... VULNERABLE

target: http://127.0.0.1:8099            # NOT WeEngine - adversarial false-positive target
WE7-1  ... inconclusive
WE7-2  ... not vulnerable
WE7-3  ... inconclusive
WE7-4  ... not exposed
WE7-6  ... inconclusive
WE7-5  ... no bypass observed
vulnerable: none
```

### 1.1 False-positive / false-negative testing

A detector is worthless if it "finds" the bug on hosts that do not have it. An earlier revision of
these scripts did exactly that: run against a non-WeEngine server that merely *looked* plausible
(a body starting with `failed`, a large HTML page, any `200` with JSON, any redirect), five of the six
checks reported VULNERABLE. That is why every check now requires a **WeEngine-specific structure**
rather than a shape:

| check | structural requirement (post-hardening) |
|---|---|
| WE7-1 | body starts with `failed`, is tiny plain text (<120 B, no `<`), and the tail is a single **token-shaped word** (16–64 chars `[A-Za-z0-9_\-.]`). A sentence such as `failed to fetch package from cloud mirror` no longer matches. |
| WE7-2 | the fetch target is WeEngine's own module-list JSON, and the reply must **be that JSON envelope** (`{`…`"errno"`/`"items"`…) — a big HTML page cannot pass for an echo. |
| WE7-3 | reply must be a JSON object carrying **both** `error` and `message` keys (WeEngine's upload-error convention), with no markup. |
| WE7-4 | the reply must parse to the real envelope `message → message → items` (dict), not merely contain the word `items`. |
| WE7-5 | gate must fire without `direct` (3xx / tiny body / password form) **and** the `direct=1` reply must carry WeEngine markers (`微擎`, `c=site`, …) or be a data response (non-HTML body >100 B), with deny pages (`没有权限`, `not authorized`, …) excluded. |
| WE7-6 | reply must be WeEngine's ajax JSON envelope **or** the endpoint's own validation text (`邮箱或手机号`, `验证码`), no markup. Any `200` page is not enough. |

`_fp_target.py` ships with this repository — it is **not** WeEngine, it deliberately answers the probe
URLs with look-alike responses (a body starting with `failed`, a 5 KB HTML page, `200`+JSON,
`direct=0` → `302` to `/news/`, `direct=1` → a big page). Run it and re-run the checks:

```bash
python3 _fp_target.py 8099 &
python3 run_all.py -u http://127.0.0.1:8099 -m fakemodule    # expected: "vulnerable: none"
```

Results after hardening (all measured, not asserted):

| target | WE7-1 | WE7-2 | WE7-7 | WE7-3 | WE7-4 | WE7-5 | WE7-6 | false positives |
|---|---|---|---|---|---|---|---|---|
| 1.7.2 lab | VULN | VULN | n/a (no allow-list) | EXPOSED | EXPOSED | VULN | REACHABLE | 0 (all are real) |
| 1.7.7 lab, module with 7 bindings | VULN | VULN | n/a (no allow-list) | EXPOSED | EXPOSED | protected *(correct: undeclared entries only)* | REACHABLE | 0 |
| 2.9.13 lab | not vuln | not vuln | **BYPASS** | not exposed | EXPOSED | VULN | REACHABLE | 0 |
| `_fp_target.py` (not WeEngine) | inconclusive | not vuln | not bypassed | inconclusive | not exposed | no bypass | inconclusive | **0** |

Two honest limitations remain:

* a check that answers **inconclusive** on a non-WeEngine host is by design — it means "the reply does
  not look like WeEngine", not "safe";
* WE7-5 can only test entries you name (`-m module -d do`); the framework does not expose a list of
  third-party entries to an anonymous caller, so a "clean" result means "none of the entries you
  named were exposed", not "the site is safe".

---

## 2. WE7-5 — unauthenticated invocation of a module backend entry

**Class:** CWE-862 Missing Authorization (also CWE-306) · **Component:** `web/source/site/entry.ctrl.php`
**Affected:** 1.7.2 – 2.9.13 (current) · **Script:** `we7_5_module_entry_bypass.py`

### Principle

The controller decides whether to authenticate from the `direct` field of a `modules_bindings` row.
When **no row matches**, it fabricates the row from the request — including the authorization flag:

```php
$entry = table('modules_bindings')->where(array('module' => $m, 'do' => $do))->get();
if (empty($entry)) {
    $entry = array(
        'module' => $entry_module_name,
        'do'     => $_GPC['do'],
        'direct' => !empty($_GPC['direct']) ? safe_gpc_string($_GPC['direct']) : 0,   // attacker-controlled
    );
}
if (!$entry['direct']) {              // the only gate in the entire flow
    checklogin();
    /* + account / module permission checks */
}
$method = 'doWeb' . ucfirst($entry['do']);
exit($site->$method());               // module method called by name
```

Consequences:

* `modules_bindings` rows are generated from the module's `manifest.xml <bindings>` section, so the
  exposed surface is **every `doWeb*` method the module implements but does not declare** (exports,
  batch operations, cache/token maintenance, diagnostics) and **every module that declares no
  bindings at all**;
* an entry that *is* declared stays protected — the binding row wins over the request parameter. Our
  lab shows both sides: on 1.7.7 `hc_doudou` has 7 binding rows, `do=setting&direct=1` → `302` login;
  on 1.7.2 the same module has no rows, the same request → `200` admin page;
* 2.9.13 only wrapped the value in `safe_gpc_string()` (an XSS/trim filter). The authorization logic
  is unchanged, which is why the bypass is still present today.

### What it means in practice

Verified anonymously on 2.9.13 (no cookie, no session) against three third-party modules:

| module | entry | observed |
|---|---|---|
| activity / payment module | `do=setting&direct=1` | HTTP 200, module admin page rendered, its save handler wrote a file |
| form module | `do=list` / `do=typeadd` / `do=typedel` | form list as JSON; form created; form deleted with its field and submission tables cascaded |
| activity/voting module | `do=excledraw&direct=1` | `Content-Disposition: attachment; …csv` — member nicknames, openid, real name, phone and address exported to an anonymous caller |

### Detection

Differential, GET only:

```bash
python3 we7_5_module_entry_bypass.py -u http://127.0.0.1:8084 -m xiaof_toupiao
```

```
  xiaof_toupiao?do=diagnose     direct=0 -> 302 | direct=1 -> 200 | VULNERABLE (direct=1 bypassed the login gate)
  xiaof_toupiao?do=lists        direct=0 -> 302 | direct=1 -> 302 | protected (a binding row exists -> checklogin() is enforced)
```

### Remediation

Fail closed: treat "no binding row" as "not authorized", never build the authorization flag from
request input, and require authentication for every entry the module did not declare public.

---

## 3. WE7-6 — unauthenticated verification-code trigger (e-mail / SMS)

**Class:** CWE-799 / CWE-770 · **Component:** `web/source/utility/verifycode.ctrl.php`
**Affected:** 1.7.2 – 2.9.13 (current) · **Script:** `we7_6_verifycode_trigger.py`

### Principle

`verifycode` sits in the unauthenticated `direct` ACL of `utility`, so no session is required.
Three further weaknesses turn a covered feature into an open relay:

```php
$need_checkcaptcha = true;
if (isset($_GPC['need_checkcaptcha']) && intval($_GPC['need_checkcaptcha']) > 0) {
    $need_checkcaptcha = false;                     // 1. the caller switches the captcha off
}
$receiver = safe_gpc_string($_GPC['receiver']);     // 2. arbitrary recipient
$row = $verifycode_table->getByReceiverVerifycode($_W['uniacid'], $receiver, '');
if ($row['total'] >= 5) iajax(-1, 'too frequent');   // 3. quota keyed on a request parameter
pdo_delete('uni_verifycode', array('createtime <' => TIMESTAMP - 1800));
```

`$_W['uniacid']` is initialised from `$_GPC['uniacid']`, so rotating it grants a fresh 5-message
quota; counters are purged after 30 minutes anyway. Delivery then uses the site's own transport:

```php
if ('email' == $receiver_type) { $result = ihttp_email($receiver, ...); }     // site SMTP
else                          { $result = cloud_sms_send($receiver, '800002', ...); }  // billed to the owner
```

Impact: the site's SMTP becomes a bulk sender for arbitrary recipients (domain/IP blacklisting), and
on a site registered with the vendor cloud each SMS is billed to the site owner, so the balance can be
drained; arbitrary phone numbers can be flooded. No account, session or user interaction is required.

### What was measured on the official 2.9.13 package

Installation: `IMS_VERSION = 2.9.13`, `IMS_RELEASE_DATE = 202610280001`, md5
`d14bcecbfb774d27f41c3c43796e2e05`. The receiver is an `example.com` address on our own lab — no real
phone number and no real mailbox is involved. Script: `tests/we7_2913_verifycode_abuse.sh`.

| step | request | result |
|---|---|---|
| valid e-mail receiver, `uniacid` omitted | 5 × `do=send_code&receiver=abuse@example.com` | 5 × `{"errno":-1,"message":"SMTP connect() failed. …PHPMailer…"}` — **a code was generated and the mail transport was actually called** |
| 6th, same receiver and uniacid | same | `errno -1, "您的操作过于频繁,请稍后再试"` (quota 5/5) |
| same receiver, `uniacid=2` | `&uniacid=2` | accepted again: a **new row** `uniacid=2 total=1` and the transport called again |
| `failed_count=3`, no captcha parameter | `&receiver=captcha@example.com&uniacid=2` | `errno -3, "请输入图形验证码!"` — the gate is **on by default** |
| same, `need_checkcaptcha=1` | `&need_checkcaptcha=1` | gate skipped, transport called again |
| same, `need_checkcaptcha=0` | `&need_checkcaptcha=0` | `errno -3` again — only a value `> 0` switches the gate off |

State of `ims_uni_verifycode` afterwards:

```
uniacid=0  abuse@example.com     total=5  code=443388
uniacid=2  abuse@example.com     total=1  code=282068
uniacid=2  captcha@example.com   total=2  code=526738
```

That is the whole issue in a single line: **a verification code was created for a recipient this site
has never seen, and the delivery layer was invoked, with no session and nothing but a query string.**

Two honest notes:

* the `SMTP connect() failed` message is a *delivery* failure on the lab (no SMTP server), and that is
  precisely what makes it good evidence — the failure can only be produced after the send is attempted;
* the SMS branch calls `cloud_prepare()` first, so an installation that is not registered with the
  vendor cloud stops there. On a registered site the same request sends a **billed** SMS. Our lab is
  not registered, which is why the reproduction above uses the e-mail branch.

### Detection (nothing is ever sent)

```bash
python3 we7_6_verifycode_trigger.py -u http://127.0.0.1:8084
```

The script only ever uses a **malformed receiver**, which validation rejects before a code is
generated — so the probe proves reachability without producing a single message. A "does it really
send" test is deliberately not implemented: it costs the site owner money.

### Remediation

Remove the endpoint from the unauthenticated ACL (or require a CSRF-protected session), decide the
captcha server-side only, key throttling on client IP + recipient, cap total sends per IP and window.

---

## 4. WE7-1 — cloud `dock` unauthenticated settings overwrite → arbitrary file write → RCE

**Class:** CWE-306 → CWE-434 / CWE-94 · **Component:** `web/source/cloud/dock.ctrl.php`
**Affected:** 1.7.2 – 1.7.7 (fixed in 2.9.13) · **Script:** `we7_1_cloud_dock_rce.py`
**Prior art:** the `download` branch's arbitrary-write primitive (`file_put_contents(IA_ROOT.$path,$file)`
guarded by `md5(md5(file).path.token)===sign`) was published by Joseph on 90sec in 2020-01, with the
author noting that only a token was missing. **What is new here is the unauthenticated `do=callback`
branch**, which supplies that token — it removes the precondition instead of the primitive.

### Principle

Two actions are chained because the handler trusts state the request can rewrite:

```php
if ($do == 'callback') {                       // 1. runs BEFORE the cloud guard, then exits
    $site = json_decode(base64_decode($_GPC['token']), true);
    setting_save($site, 'site');               //    writes site.key / site.token
    exit("1");
}
if ($do != 'auth') { if (is_error(cloud_prepare())) exit('cloud service is unavailable.'); }

if ($do == 'download') {                       // 2. signs with the key from step 1
    $string = md5($file) . $ret['path'] . $_W['setting']['site']['token'];
    if (!empty($_W['setting']['site']['token']) && md5($string) === $ret['sign']) {
        $path = IA_ROOT . $ret['path'];        //    no path / extension restriction
        @mkdirs(dirname($path));
        file_put_contents($path, $file);
    }
    exit("failed$post " . $_W['setting']['site']['token']);   //    and echoes the token
}
```

`cloud_prepare()` only checks that `site.key` and `site.token` are non-empty — values that step 1 has
just set. The HMAC therefore protects nothing: the attacker signs his own payload. Writing a `.php`
file under the web root completes the chain.

Verified on 1.7.2 and 1.7.7 with a lab-only payload that returns `uid=0(root)`. Not present in the
2018 1.0 builds (their download handler already reads the key from the cache), and fixed in 2.9.13
(`callback` removed, key moved to `authcode(cache_load('cloud:transtoken'),'DECODE')`, writes under
`/web/` and `/framework/` redirected to `data/patch/upgrade/`).

### Detection (non-destructive)

```bash
python3 we7_1_cloud_dock_rce.py -u http://127.0.0.1:8080
```

The script sends an **empty** payload to the legacy `download` handler. A vulnerable build answers
`failed <site-token>`; a hardened one answers `cloud service is unavailable.` or plain `failed`.
Nothing is written and the settings-poisoning `callback` action is never touched. Because the legacy
reply leaks the site token, the script masks it (length + first 4 characters only).

### Remediation

Authenticate the callback action, never derive a signing key from request-modifiable state, whitelist
the write path, and stop echoing the token in error responses.

---

## 5. WE7-2 — unauthenticated SSRF with full response echo

**Class:** CWE-918 · **Component:** `web/source/utility/wxcode.ctrl.php` (do=image)
**Affected:** 1.7.2 – 1.7.7 · **Status:** **prior art — published 2021-03, not submitted as a CVE**
**Script:** `we7_2_wxcode_ssrf.py` (kept as a detector for old deployments only)

### Principle

```php
$content = ihttp_request($_GPC['attach']);   // unauthenticated, URL fully controlled
echo $content['content'];                    // entire response body returned
```

`ihttp_allow_host()` filters destinations only when the site configured
`setting.cloudip.ip_white_list`; the default is empty, so nothing is filtered. `CURLOPT_FOLLOWLOCATION`
is enabled, so redirects into private ranges are followed. Because the body is echoed, this is a
full-read SSRF (internal panels, intranet services, cloud metadata), not a blind one.

### Prior art

This exact endpoint, method and echo behaviour were published in March 2021:

> xq17, *代码审计之某通用商城系统getshell过程*, Butian, section `0x04 前台某处可回显SSRF`
> `http://host/web/index.php?c=utility&a=wxcode&do=image&attach=http://127.0.1.13:80/`

The same article also published the `direct` list this endpoint appears on. Consequently **this
entry is not the subject of a CVE submission** — it would be closed as a duplicate. It is kept
here because (a) the detector is still useful against 1.7.x installations, and (b) it is the
precondition for §5.1.

### Detection (non-destructive)

```bash
python3 we7_2_wxcode_ssrf.py -u http://127.0.0.1:8080
```

The destination used is **the target itself** — no third-party host is contacted and no internal port
is scanned. Vulnerable builds echo the fetched HTML back; builds with an allow-list return an empty
body.

### Remediation

Strict host allow-list, re-validate after redirects, reject private/link-local ranges.
**2.9.13 attempted this and got it wrong** — see §5.1 for the bypass and for the check that actually holds.

---

## 5.1 WE7-7 — the 2.9.13 fix for the above is incomplete: the allow-list can be bypassed

**Class:** CWE-918 SSRF through a permissive allow-list (also CWE-183, CWE-697)
**Component:** `web/source/utility/wxcode.ctrl.php:28` · **Affected: 2.9.13 only**
**Script:** `we7_7_wxcode_allowlist_bypass.py`

We are not re-reporting the 2021 SSRF. We are reporting that **the code written to fix it does not
fix it**, and that the same full-read SSRF is therefore still reachable in the current release.

### Principle

```php
web/source/utility/wxcode.ctrl.php:23,28
$image = safe_gpc_url($_GPC['attach'], false);
...
if (!starts_with($image, array('http://mmbiz.qpic.cn/',  'https://mmbiz.qpic.cn/',
                               'http://mmbiz.qlogo.cn',  'https://mmbiz.qlogo.cn'))) {
    ... reject ...
}
```

Two entries carry a trailing slash, two do not, and `starts_with()` is a plain string prefix test —
it never looks at the host. So any URL that merely *begins with* `http://mmbiz.qlogo.cn` is accepted
while its real host is something else entirely:

```
http://mmbiz.qlogo.cn.evil.test/...      # attacker-registered domain, prefix matches
http://mmbiz.qlogo.cn@127.0.0.1:8080/    # userinfo trick: prefix matches, real host is after the @
```

The `mmbiz.qpic.cn` pair is not usable this way, which is what makes the trailing slash — a
one-character difference — the actual bug. Everything downstream is the 2021 code: `ihttp_request()`
follows redirects, and the body is echoed back to the caller.

### What was measured on the official 2.9.13 package

Installation: official package, `IMS_VERSION = 2.9.13`, `IMS_RELEASE_DATE = 202610280001`,
md5 `d14bcecbfb774d27f41c3c43796e2e05`.

Self-fetch differential (`we7_7_wxcode_allowlist_bypass.py` — the "internal" resource is the site's
own module-list JSON; no third party is contacted):

| case | `attach=` | result |
|---|---|---|
| A control | `http://127.0.0.1:8084/web/index.php?c=utility&a=modules&do=list` | 200, **0 bytes** |
| **B bypass** | `http://mmbiz.qlogo.cn@127.0.0.1:8084/web/index.php?c=utility&a=modules&do=list` | 200, **205 bytes, JSON echoed** |
| C control | `http://mmbiz.qpic.cn@127.0.0.1:8084/web/index.php?c=utility&a=modules&do=list` | 200, **0 bytes** |
| D no DNS | `http://mmbiz.qlogo.cn.<random>.invalid/web/...` | 200, 0 bytes |

Same test with an explicit internal service instead of a self-fetch
(`tests/we7_2913_ssrf_bypass.sh`, service on `127.0.0.1:9099` returning `INTERNAL_MARKER_9099`):

| case | `attach=` | result |
|---|---|---|
| A control | `http://127.0.0.1:9099/` | 200, 0 bytes |
| **B bypass** | `http://mmbiz.qlogo.cn@127.0.0.1:9099/` | 200, **20 bytes — marker received** |
| C control | `http://mmbiz.qpic.cn@127.0.0.1:9099/` | 200, 0 bytes |
| **D bypass** | `http://mmbiz.qlogo.cn.evil.test:9099/` (via hosts file) | 200, **20 bytes — marker received** |
| F control | `http://example.invalid/` | 200, 0 bytes |

A and F returning nothing is what makes this a real bypass rather than the endpoint echoing whatever
it is handed: the body only appears when the prefix matches **and** the destination resolves.

One thing deliberately not claimed: the `https://` entries have the same missing slash, but whether
an https target is reachable depends on that target speaking TLS. The lab had no TLS service, so the
https path is **code-level only** — it is stated as such, not as verified.

### Detection (non-destructive)

```bash
python3 we7_7_wxcode_allowlist_bypass.py -u http://127.0.0.1:8084
```

Exit `1` = bypass confirmed, `0` = not bypassed, `2` = inconclusive (or "this build has no
allow-list at all", which is what 1.7.x answers — that case belongs to §5, not here).

Run against the adversarial non-WeEngine target in `_fp_target.py` it answers **not bypassed**, so
the check does not fire on a host that merely returns a `200`.

### What it means in practice

Identical to the 2021 issue: an unauthenticated caller can point a 2.9.13 site at internal HTTP
services, cloud metadata (`169.254.169.254`) and internal admin panels, and read the responses.
The only difference is that on 2.9.13 the `attach` value must carry the `mmbiz.qlogo.cn` prefix.

### Remediation that actually holds

```php
$u = parse_url($image);
if (empty($u['host']) || !in_array(strtolower($u['host']), array('mmbiz.qpic.cn', 'mmbiz.qlogo.cn'), true)) {
    die('bad url');
}
if (!in_array(strtolower($u['scheme'] ?? ''), array('http', 'https'), true)) { die('bad url'); }
if (isset($u['user']) || isset($u['pass'])) { die('bad url'); }   // no userinfo trick
if (($u['path'][0] ?? '') !== '/') { die('bad url'); }
```

Do not string-prefix match. Compare the parsed host for strict equality, refuse userinfo, and — as a
second layer — resolve the host and drop the request if it lands in a loopback, private or
link-local range.

---

## 6. WE7-3 — unauthenticated upload endpoint with no content validation

**Class:** CWE-434 · **Component:** `web/source/utility/file.ctrl.php` (do=upload)
**Affected:** 1.7.2 – 1.7.7 (fixed in 2.9.13) · **Script:** `we7_3_file_upload.py`
**Not submitted on its own:** "`utility.file` is on the unauthenticated `direct` list" is part of the
2021 publication (see §0.1), so this is documented as chain material for §4 rather than as a separate
CVE.

### Principle

`file` is part of the unauthenticated `direct` ACL in 1.7.x:

```php
'utility' => array('direct' => array('verifycode', 'code', 'file', ...))
```

`file_upload()` validates the **extension only**, never the content, and stores results under
`attachment/images/<uniacid>/…`. PHP extensions are rejected, so this is not direct RCE; the impact is
stored XSS from the site's own origin, file hosting under the victim's domain, and chain material.
2.9.13 moved `file` to the authenticated (vice-founder/owner) part of the ACL.

### Detection (nothing is uploaded)

```bash
python3 we7_3_file_upload.py -u http://127.0.0.1:8080
```

A GET to the upload action with **no file attached**: a reachable handler answers with its own JSON
error, a hardened build answers `302` to the login page. The script never posts a file.

### Remediation

Require authentication, validate magic bytes/content, store outside the web root, serve attachments
with `Content-Disposition` and a restrictive `Content-Type`.

---

## 7. WE7-4 — unauthenticated module enumeration (informational)

**Class:** CWE-200 · **Component:** `web/source/utility/modules.ctrl.php` (do=list)
**Affected:** 1.7.2 – 2.9.13 · **Script:** `we7_4_module_enum.py`

`modules` is in the unauthenticated `direct` ACL and returns the module table as JSON (identifiers,
titles, `issystem`, `enabled`). No direct impact, but it is the reconnaissance step for WE7-5: the
module name plus an undeclared entry is all an attacker needs.

```bash
python3 we7_4_module_enum.py -u http://127.0.0.1:8084
```

---

## 8. Run every check

```bash
python3 run_all.py -u http://127.0.0.1:8084 -m xiaof_toupiao
python3 run_all.py -u https://target -m some_module --json
```

WE7-7 is 2.9.13-only and is run separately (it needs no module name):

```bash
python3 we7_7_wxcode_allowlist_bypass.py -u http://127.0.0.1:8084
```

---

## 9. Safety of these scripts

* GET requests only; no POST/PUT/DELETE, no multipart upload, no form submission;
* no record is created, modified or deleted;
* no e-mail or SMS is produced (WE7-6 uses an invalid recipient that is rejected pre-delivery);
* no brute force, no payload list, no scanning of hosts or ports;
* WE7-7 sends four requests, all to the target itself (the "internal" resource is the site's own module list); no third-party host is contacted;
* exactly one request per check (WE7-5 sends two per module/entry pair, that is the differential).

Use them only on systems you own or are authorised to test.

---

## 10. Disclosure timeline

| Date | Event |
|---|---|
| 2026-11-26 | Reproduced in a local lab (1.7.2 / 1.7.7 / 2.9.13); WE7-7 established on 2.9.13 |
| — | This advisory will be updated when a fix ships |

### Interim mitigation for operators

Until a fix is available, block at the reverse proxy (both issues are reachable through these paths):

```
/web/index.php?c=site&a=entry     # WE7-5
/web/index.php?c=utility&a=verifycode   # WE7-6
/web/index.php?c=utility&a=wxcode       # WE7-7 (the 2.9.13 allow-list does not hold)
```

or restrict them to authenticated administrative source addresses.

WeEngine has no CNA (it is not covered by Patchstack, Wordfence/WPScan or a product CNA), which is why
the request goes to the CNA of last resort.

---

## 11. References

* Vendor: <https://www.we7.cc> · marketplace: <https://s.w7.cc> · developer docs: <https://dev.w7.cc>
* CWE-862 / CWE-306 / CWE-434 / CWE-918 / CWE-200 / CWE-799 / CWE-770 / CWE-183
* MITRE CNA of Last Resort: <https://cveform.mitre.org>
* Prior art, wxcode echo SSRF + the `direct` list: xq17, *代码审计之某通用商城系统getshell过程*,
  2021-03 — <https://mp.weixin.qq.com/s/rSP8LQJpIkP-Ahljkof5sA>
  (mirror: <https://mdr.skyeye.qianxin.com/forum/share/45>)
* Prior art, `dock` download arbitrary file write: Joseph, *微擎sql注入到getshell*, 90sec, 2020-01-16 —
  <https://forum.90sec.com/t/topic/702>
