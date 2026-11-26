# WeEngine (微擎) — unauthenticated access issues, by vulnerability

**Status:** vendor notified 2026-11-26 · **Published:** 2026-11-26 · **CVE:** requested (not yet assigned)
**Vendor:** WeEngine (微擎), 宿州市微擎云计算有限公司 — <https://www.we7.cc>
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
| WE7-2 | **CWE-918** SSRF (full response echo) | `web/source/utility/wxcode.ctrl.php` | 1.7.2 – 1.7.7 | fixed | `we7_2_wxcode_ssrf.py` |
| WE7-3 | **CWE-434** Unrestricted upload | `web/source/utility/file.ctrl.php` | 1.7.2 – 1.7.7 | fixed | `we7_3_file_upload.py` |
| WE7-4 | **CWE-200** Information exposure (informational) | `web/source/utility/modules.ctrl.php` | 1.7.2 – 2.9.13 | not fixed | `we7_4_module_enum.py` |
| — | runner | — | — | — | `run_all.py` |

Each script is standalone (Python 3, standard library only), prints a verdict and uses exit codes
`0 = not vulnerable / not exposed`, `1 = vulnerable / exposed`, `2 = inconclusive`.

---

## 1. Lab results — the differential that the detectors rely on

| check | 1.7.2 | 1.7.7 | 2.9.13 |
|---|---|---|---|
| WE7-1 `dock` download, empty payload | `failed <token>` | `failed <token>` | `cloud service is unavailable.` |
| WE7-2 `wxcode` self-fetch echo | page echoed | page echoed | empty body |
| WE7-3 `file` upload endpoint (no file sent) | JSON error | JSON error | `302` login |
| WE7-4 `modules` list | module JSON | module JSON | module JSON |
| WE7-5 entry with `direct=1` | `200` page (module had **no** binding rows) | `302` login (that module **has** 7 binding rows — the gate worked) | `200` page for undeclared entries, `302` for declared ones |
| WE7-6 `verifycode` with malformed receiver | error text | error text | JSON error |

`run_all.py` output on the two extremes:

```
target: http://127.0.0.1:8082            # 1.7.2
WE7-1  CWE-306 -> 434/94  unauth file write -> RCE   VULNERABLE
WE7-2  CWE-918  SSRF with response echo              VULNERABLE
WE7-3  CWE-434  unauth upload endpoint               EXPOSED
WE7-4  CWE-200  module enumeration                   EXPOSED
WE7-6  CWE-799  unauth code trigger                  REACHABLE WITHOUT A SESSION
WE7-5  CWE-862  missing authorization (module entry) VULNERABLE

target: http://127.0.0.1:8084            # 2.9.13 (current)
WE7-1  ... not vulnerable (hardened build: cloud guard reached before the download branch)
WE7-2  ... not vulnerable (no echo - allow-list in place)
WE7-3  ... not exposed (redirects to the login page)
WE7-4  ... EXPOSED
WE7-6  ... REACHABLE WITHOUT A SESSION
WE7-5  ... VULNERABLE
```

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
**Affected:** 1.7.2 – 1.7.7 (fixed in 2.9.13) · **Script:** `we7_2_wxcode_ssrf.py`

### Principle

```php
$content = ihttp_request($_GPC['attach']);   // unauthenticated, URL fully controlled
echo $content['content'];                    // entire response body returned
```

`ihttp_allow_host()` filters destinations only when the site configured
`setting.cloudip.ip_white_list`; the default is empty, so nothing is filtered. `CURLOPT_FOLLOWLOCATION`
is enabled, so redirects into private ranges are followed. Because the body is echoed, this is a
full-read SSRF (internal panels, intranet services, cloud metadata), not a blind one. 2.9.13 now
requires the URL to start with `http(s)://mmbiz.qpic.cn/` or `http(s)://mmbiz.qlogo.cn/`.

### Detection (non-destructive)

```bash
python3 we7_2_wxcode_ssrf.py -u http://127.0.0.1:8080
```

The destination used is **the target itself** — no third-party host is contacted and no internal port
is scanned. Vulnerable builds echo the fetched HTML back; hardened builds return an empty body.

### Remediation

Strict host allow-list, re-validate after redirects, reject private/link-local ranges.

---

## 6. WE7-3 — unauthenticated upload endpoint with no content validation

**Class:** CWE-434 · **Component:** `web/source/utility/file.ctrl.php` (do=upload)
**Affected:** 1.7.2 – 1.7.7 (fixed in 2.9.13) · **Script:** `we7_3_file_upload.py`

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

---

## 9. Safety of these scripts

* GET requests only; no POST/PUT/DELETE, no multipart upload, no form submission;
* no record is created, modified or deleted;
* no e-mail or SMS is produced (WE7-6 uses an invalid recipient that is rejected pre-delivery);
* no brute force, no payload list, no scanning of hosts or ports;
* exactly one request per check (WE7-5 sends two per module/entry pair, that is the differential).

Use them only on systems you own or are authorised to test.

---

## 10. Disclosure timeline

| Date | Event |
|---|---|
| 2026-11-26 | All six issues reproduced in a local lab (1.7.2 / 1.7.7 / 2.9.13) |
| 2026-11-26 | **Vendor notified** (support ticket + e-mail to the maintainer address on the project's repository) |
| 2026-11-26 | **Public advisory published** (this repository) — WE7-5 and WE7-6 were unfixed in 2.9.13 at publication time |
| — | CVE requested from MITRE (CNA of last resort); ID not assigned yet |
| — | This advisory will be updated when a fix ships |

### Interim mitigation for operators

Until a fix is available, block at the reverse proxy (both issues are reachable through these paths):

```
/web/index.php?c=site&a=entry     # WE7-5
/web/index.php?c=utility&a=verifycode   # WE7-6
```

or restrict them to authenticated administrative source addresses.

WeEngine has no CNA (it is not covered by Patchstack, Wordfence/WPScan or a product CNA), which is why
the request goes to the CNA of last resort.

---

## 11. References

* Vendor: <https://www.we7.cc> · marketplace: <https://s.w7.cc> · developer docs: <https://dev.w7.cc>
* CWE-862 / CWE-306 / CWE-434 / CWE-918 / CWE-200 / CWE-799 / CWE-770
* MITRE CNA of Last Resort: <https://cveform.mitre.org>
