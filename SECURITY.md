# Security & responsible use

## Scope of this tool

`php2shell-scanner` is a **passive, non-destructive** exposure-mapping tool for
CVE-2026-109618 / CVE-2026-109619. It fingerprints the PHP version a web host
advertises; it does **not** attempt exploitation and does **not** trigger the
out-of-memory condition the real vulnerability relies on.

It reports **exposure**, not confirmed exploitability. A result of
`INDETERMINATE` is not a clean bill of health — it means the version could not
be read, not that the host is safe.

## Acceptable use

Only scan systems that you own or are explicitly authorised to test under a
written agreement (engagement contract, rules of engagement, or equivalent).
Unauthorised scanning may be illegal in your jurisdiction.

Do not publish reports, screenshots, or datasets that identify a specific
vulnerable third-party host. Aggregate and anonymise before sharing anything
publicly.

## Reporting a bug in this tool

If you find a defect in the scanner itself (a false result, a crash, a way it
could cause unintended load), please open an issue, or email
**security@groupsystemik.com**. Please do not include identifiable third-party
scan data in reports.

## Reporting the underlying vulnerability

If you are responding to php2shell on systems you operate: patch to PHP
8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or a vendor backport) and read the
[official PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5).
