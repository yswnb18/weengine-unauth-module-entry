# WeEngine (微擎) — Unauthenticated module entry access & verification-code trigger

**Status:** vendor notification pending · **CVE:** not assigned yet
**Vendor:** WeEngine (微擎), 宿州市微擎云计算有限公司 — <https://www.we7.cc>
**Tested against:** official release 2.9.13 (`IMS_RELEASE_DATE = 202610280001`, build 2026-10-28,
package md5 `d14bcecbfb774d27f41c3c43796e2e05`), plus 1.7.2 and 1.7.7.

This repository contains a **non-destructive detector** for two issues that are still present in the
current WeEngine release, together with the technical description needed to reproduce the finding in
a controlled lab. It contains **no weaponised payload, no file upload, no data-modifying request and
no SMS/e-mail is ever sent**.

---

## 1. Affected versions

| Issue | Affected | Verified live | Fixed in |
|---|---|---|---|
| **WE7-5** unauthenticated invocation of a module backend entry (`site/entry`) | 1.7.2 → **2.9.13** | 1.7.2, 2.9.13 | **not fixed** as of 2.9.13 |
| **WE7-6** unauthenticated verification-code trigger (`utility/verifycode`) | 1.7.2 → **2.9.13** | 1.7.7, 2.9.13 | **not fixed** as of 2.9.13 |
| WE7-1 `cloud/dock` unauthenticated settings overwrite → arbitrary file write → RCE | 1.7.2, 1.7.7 | 1.7.2, 1.7.7 | 2.9.13 |
| WE7-2 `utility/wxcode` unauthenticated SSRF with response echo | 1.7.2, 1.7.7 | 1.7.2, 1.7.7 | 2.9.13 |
| WE7-3 `utility/file` unauthenticated arbitrary-content upload | 1.7.2, 1.7.7 | 1.7.7 | 2.9.13 |
| WE7-4 `utility/modules` unauthenticated module enumeration (informational) | 1.7.2 → 2.9.13 | 2.9.13 | not fixed |

WE7-1/2/3 are listed for context only — they are fixed in the current release and have been discussed
publicly before. The two issues this repository focuses on are the ones that are **still live**.

---

## 2. WE7-5 — unauthenticated invocation of a module backend entry

### 2.1 Where

`web/source/site/entry.ctrl.php`

```php
// 1) look the entry up in modules_bindings
$entry = table('modules_bindings')
    ->where(array('module' => $entry_module_name, 'do' => safe_gpc_string($_GPC['do'])))
    ->get();

// 2) if there is no such row, build one from the request
if (empty($entry)) {
    $entry = array(
        'module' => $entry_module_name,
        'do'     => safe_gpc_string($_GPC['do']),
        'state'  => !empty($_GPC['state'])  ? safe_gpc_string($_GPC['state'])  : '',
        'direct' => !empty($_GPC['direct']) ? safe_gpc_string($_GPC['direct']) : 0,   // attacker-controlled
    );
}

// 3) the only authorization gate in the whole flow
if (!$entry['direct']) {
    checklogin();
    /* ... account / module permission checks ... */
}

// 4) then the method is called by name
$method = 'doWeb' . ucfirst($entry['do']);
exit($site->$method());
```

`modules_bindings` rows are generated from the `<bindings>` section of each module's `manifest.xml`.
Consequently the reachable surface is **every `doWeb*` method a module implements but does not declare
as a binding** — typically exports, batch operations, AJAX handlers, cache/token maintenance and
diagnostic pages — plus every module that declares no bindings at all.

Version 2.9.13 only wraps the value in `safe_gpc_string()` (an XSS/trim filter). The authorization
logic is unchanged, so the bypass survives in the current release.

### 2.2 Verified behaviour (2.9.13, no cookie, no session)

Bindings were installed exactly as the framework derives them from the module's manifest, so the test
reflects a normally installed module:

| request | result |
|---|---|
| `do=lists` (declared in manifest → binding row, `direct=0`) | `302` → login (protected) |
| `do=drawlists` (declared) | `302` → login (protected) |
| `do=diagnose` (not declared) | **`200`, admin page rendered** |
| `do=excletop` (not declared, export) | **`200`, export produced** |
| `do=excledraw` (not declared, export) | **`200`, `Content-Disposition: attachment; filename=<activity>-<date>.csv`** |

The exported CSV of the activity module contains, per member: nickname, openid, real name, phone
number and shipping address — i.e. personal data of the site's members, returned to an anonymous
caller. Two further modules were used to confirm that the entry point, not one specific handler, is
the problem: an activity/payment module wrote a file through its own save handler, and a form module
created and deleted business records anonymously.

Control: the same requests with `direct=0` return `302` to the login page.

### 2.3 Impact

Installations that run one or more third-party modules — the normal operating mode of the product —
expose those modules' undeclared backend methods to anyone who can reach the site: configuration and
credential writes, business-record creation/deletion, and bulk export of member data. Sites without
third-party modules are not affected by this issue.

### 2.4 Remediation

Treat "no binding row" as "not authorized" (fail closed) instead of synthesising the authorization
flag from request input, and require authentication for every module entry that the module did not
explicitly declare public.

---

## 3. WE7-6 — unauthenticated verification-code trigger

### 3.1 Where

`web/source/utility/verifycode.ctrl.php`, reachable without authentication because it is listed in the
`direct` array of the utility ACL in `web/common/permission.inc.php`.

```php
$need_checkcaptcha = true;
if (isset($_GPC['need_checkcaptcha']) && intval($_GPC['need_checkcaptcha']) > 0) {
    $need_checkcaptcha = false;          // the client can switch the captcha off
}

$receiver = safe_gpc_string($_GPC['receiver']);   // arbitrary recipient
...
$row = $verifycode_table->getByReceiverVerifycode($_W['uniacid'], $receiver, '');
if ($row['total'] >= 5) iajax(-1, 'too frequent');
pdo_delete('uni_verifycode', array('createtime <' => TIMESTAMP - 1800));  // counters expire in 30 min
```

The throttle is keyed on `(uniacid, receiver)`, and `uniacid` is itself a request parameter
(`$_GPC['uniacid']`), so rotating it yields a fresh quota; the counter rows are purged after
30 minutes.

Delivery then goes through the site's own transport:

```php
if ('email' == $receiver_type) {
    $result = ihttp_email($receiver, "...", $content);        // site SMTP
} else {
    $result = cloud_sms_send($receiver, '800002', $postdata); // billed to the site owner's cloud balance
}
```

### 3.2 Impact

* e-mail: the site's SMTP is used to send to arbitrary recipients → sending domain/IP blacklisting,
  abuse complaints;
* SMS: each message is debited from the site owner's purchased cloud SMS balance → direct financial
  loss, and arbitrary numbers can be flooded;
* neither requires an account, a session or user interaction.

### 3.3 Verified behaviour

On 2.9.13 an unauthenticated request caused the server to actually attempt delivery (the response
carried the mailer transport error), confirming the send routine runs rather than being blocked by an
authorization check. The detector below deliberately uses a **malformed** receiver, which the endpoint
rejects before any message is generated — nothing is sent.

### 3.4 Remediation

Remove the endpoint from the unauthenticated ACL (or require a CSRF-protected session), decide the
captcha requirement server-side only, key throttling on client IP + recipient, and cap total sends
per IP and per window.

---

## 4. Detector

`we7_unauth_check.py` — Python 3, standard library only.

```bash
# basic run against an installation where a module named "xiaof_toupiao" is installed
python3 we7_unauth_check.py -u http://127.0.0.1:8084 -m xiaof_toupiao

# test specific entries
python3 we7_unauth_check.py -u https://target -m some_module -d diagnose -d lists

# machine-readable
python3 we7_unauth_check.py -u https://target -m some_module --json
```

Sample output (2.9.13 lab, bindings installed as the framework would create them):

```
=== target: http://127.0.0.1:8084 ===
  [WE7-4] module enumeration exposed: True (HTTP 200)
  [WE7-5] xiaof_toupiao?do=diagnose     direct=0 -> 302 | direct=1 -> 200 | VULNERABLE (unauthenticated access via direct=1)
  [WE7-5] xiaof_toupiao?do=excletop     direct=0 -> 302 | direct=1 -> 200 | VULNERABLE (unauthenticated access via direct=1)
  [WE7-5] xiaof_toupiao?do=excledraw    direct=0 -> 302 | direct=1 -> 200 | VULNERABLE (unauthenticated access via direct=1)
  [WE7-5] xiaof_toupiao?do=lists        direct=0 -> 302 | direct=1 -> 302 | not reachable (binding row exists -> checklogin() enforced)
  [WE7-6] endpoint reachable without login: True (HTTP 200) — nothing was sent
  [WE7-2] response echoed back: False (HTTP 200)

summary: VULNERABLE
vulnerable entries: xiaof_toupiao?do=diagnose, xiaof_toupiao?do=excletop, xiaof_toupiao?do=excledraw
```

### 4.1 What the detector does *not* do

* no POST/PUT/DELETE, no form submission, no file upload;
* no create/update/delete of any record;
* no SMS or e-mail delivery (WE7-6 is probed with an invalid recipient, rejected before delivery);
* no brute force, no payload list, no rate-abuse;
* exactly one GET per check, one check per module/entry pair you name.

---

## 5. Disclosure timeline

| Date | Event |
|---|---|
| 2026-11-26 | Issues reproduced in a local lab on 1.7.2 / 1.7.7 / 2.9.13 |
| _pending_ | Vendor notification (ticket + e-mail) |
| _pending_ | Requested fix window: 90 days from notification |
| _pending_ | Public advisory + CVE request via MITRE (CNA of last resort) |

WeEngine has no CNA (it is not covered by Patchstack, Wordfence/WPScan or any product CNA), which is
why the request goes to the CNA of last resort.

---

## 6. Usage policy

Use this code only against systems you own or are explicitly authorised to test. The detector issues
plain GET requests that render administrative pages; on a production site that may still be logged,
rate-limited or treated as hostile traffic. The authors accept no liability for misuse.

## 7. References

* Vendor: <https://www.we7.cc> · <https://s.w7.cc>
* Product documentation: <https://dev.w7.cc>
* CWE-862 Missing Authorization · CWE-306 Missing Authentication for Critical Function
* CWE-799 Improper Control of Interaction Frequency
