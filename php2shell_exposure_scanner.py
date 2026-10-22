#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell-scanner — Non-destructive exposure scanner for php2shell
===============================================================================
    CVE-2026-109618  (RCE via OOM corruption)
    CVE-2026-109619  (RCE via stale global state)
    PHP Security Release of 21 October 2026.

WHAT IT DOES
    Takes an ASN (e.g. AS37649), a CIDR/subnet, a single IP, or a file of
    targets, enumerates web hosts and fingerprints the PHP version exposed by
    each one, then grades every host:

        LIKELY_EXPOSED      — exposed PHP version is below the UPSTREAM fixed
                              version for its branch (8.2.35 / 8.3.36 / 8.4.27 /
                              8.5.12). See the backport caveat below.
        LIKELY_EXPOSED_EOL  — unmaintained branch (7.x–8.1): no official fix.
        PATCHED             — exposed version is at or above the upstream fix.
        INDETERMINATE       — PHP detected but version hidden, or no PHP banner.

    Each verdict carries a CONFIDENCE level (confirmed / likely / possible /
    none) so you never get a binary verdict that over-promises.

IMPORTANT — WHY "LIKELY", NOT "VULNERABLE"
    This tool reads the version string a server advertises. Linux distributions
    (Debian, Ubuntu, RHEL, …) routinely BACKPORT security fixes WITHOUT bumping
    the upstream version number: a Debian host showing "PHP/8.2.28" may already
    carry the fix in package revision 8.2.28-1+debXuY, invisible over HTTP.
    A LIKELY_EXPOSED verdict therefore means "running an outdated upstream
    version — confirm the distro package", NOT "confirmed vulnerable". This is
    exactly why version-only scanners produce false positives; verify hits
    out-of-band before acting.

DETECTION PHILOSOPHY — SAFE BY DESIGN
    This scanner fingerprints only. It NEVER tries to trigger the out-of-memory
    condition that the real exploit relies on, so it never crashes remote PHP
    workers and sends no exploitation traffic. The trade-off: a host that hides
    its version comes back INDETERMINATE, not "safe". Confirm sensitive hosts
    another way (server access, `php -v`, asset inventory). This is the right
    behaviour for defenders inventorying their own / contracted estate in
    production hours.

FINGERPRINT SOURCES (passive, read-only, GET/HEAD of '/')
    - Server and X-Powered-By response headers
    - Set-Cookie (PHPSESSID and custom session cookie names)
    - Default PHP error-page wording
    - An opportunistic read of a mistakenly-exposed /phpinfo.php (only if the
      operator left one world-readable — we never create one)

LEGAL
    Use ONLY against hosts you are authorised to test (your own assets, or
    clients under a signed engagement / rules of engagement). Unauthorised
    scanning is illegal in most jurisdictions, including the UEMOA area. The
    --authorized flag is mandatory.

Dependencies: Python 3.8+ standard library only. No installation required.
License: MIT (see repository LICENSE).
===============================================================================
"""

import argparse
import asyncio
import csv
import hashlib
import ipaddress
import json
import re
import ssl
import sys
import time
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Fixed-version reference (PHP Security Release, 21 Oct 2026)
# A branch is SAFE only from the listed version onward.
# ---------------------------------------------------------------------------
FIXED_BY_BRANCH = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
# End-of-life branches: no official branch fix. Source backports exist for
# 7.4 / 8.0 / 8.1 but are undetectable remotely -> flagged exposed by default.
EOL_BRANCHES = {(5, 4), (5, 5), (5, 6),
                (7, 0), (7, 1), (7, 2), (7, 3), (7, 4),
                (8, 0), (8, 1)}

# ---------------------------------------------------------------------------
# Verdicts and confidence levels
# ---------------------------------------------------------------------------
VULN = "LIKELY_EXPOSED"
EOL = "LIKELY_EXPOSED_EOL"
PATCHED = "PATCHED"
INDET = "INDETERMINATE"

CONF_CONFIRMED = "confirmed"   # exact version read from a server banner
CONF_LIKELY = "likely"         # strong signal (EOL branch w/ version, phpinfo)
CONF_POSSIBLE = "possible"     # PHP present but version hidden
CONF_NONE = "none"             # no PHP evidence at all

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------
PHP_VER_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
PHPINFO_VER_RE = re.compile(r"PHP Version (\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
PHP_HINT_RE = re.compile(r"php", re.IGNORECASE)
PHPSESSID_RE = re.compile(r"\bPHPSESSID=", re.IGNORECASE)
# Common framework/CMS session cookies that imply PHP even if PHPSESSID absent
PHP_COOKIE_HINTS = re.compile(
    r"\b(PHPSESSID|laravel_session|XSRF-TOKEN|symfony|ci_session|"
    r"wordpress_|wp-settings|prestashop|oc_sessionPassphrase)",
    re.IGNORECASE)
# Default PHP error-page fingerprints
PHP_ERROR_HINTS = re.compile(
    r"(Fatal error.*on line \d+|<b>Warning</b>:|<b>Notice</b>:|"
    r"Call to undefined function|X-Powered-By: PHP)",
    re.IGNORECASE)


@dataclass
class Result:
    ip: str
    port: int
    scheme: str
    status: int = 0
    server: str = ""
    powered_by: str = ""
    set_cookie: str = ""
    php_version: str = ""
    verdict: str = INDET
    confidence: str = CONF_NONE
    evidence: list = field(default_factory=list)
    detail: str = ""

    @property
    def url(self):
        return f"{self.scheme}://{self.ip}:{self.port}"

    def row(self):
        return [self.ip, self.port, self.scheme, self.status,
                self.php_version or "-", self.verdict, self.confidence,
                "; ".join(self.evidence), self.detail,
                self.server[:80], self.powered_by[:60]]


# ===========================================================================
# 1. Target building
# ===========================================================================
def asn_to_prefixes(asn, timeout=20, v6=False):
    asn_num = asn.strip().upper().removeprefix("AS")
    url = ("https://stat.ripe.net/data/announced-prefixes/data.json"
           f"?resource=AS{asn_num}")
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": f"php2shell-scanner/{VERSION}"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:
        sys.exit(f"[!] Could not resolve {asn} via RIPEstat: {e}")
    prefixes = []
    for p in data.get("data", {}).get("prefixes", []):
        pfx = p["prefix"]
        is_v6 = ":" in pfx
        if is_v6 == v6:
            prefixes.append(pfx)
    if not prefixes:
        sys.exit(f"[!] No {'IPv6' if v6 else 'IPv4'} prefixes announced "
                 f"for AS{asn_num}.")
    return prefixes


def expand_targets(cidrs, max_hosts):
    hosts = []
    for c in cidrs:
        c = c.strip()
        if not c:
            continue
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            try:
                hosts.append(str(ipaddress.ip_address(c)))
                continue
            except ValueError:
                print(f"[!] Skipped invalid target: {c}", file=sys.stderr)
                continue
        if net.num_addresses == 1:
            hosts.append(str(net.network_address))
            continue
        for ip in net.hosts():
            hosts.append(str(ip))
            if len(hosts) >= max_hosts:
                print(f"[!] Reached --max-hosts ({max_hosts}); truncating.",
                      file=sys.stderr)
                return hosts
    return hosts


# ===========================================================================
# 2. Async non-destructive probing
# ===========================================================================
def _ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    return ctx

_SSL = _ssl_context()
UA = f"Mozilla/5.0 (php2shell-scanner/{VERSION}; non-intrusive exposure check)"


async def _raw_request(ip, port, scheme, method, path, timeout):
    """One minimal HTTP/1.1 request over asyncio. Returns (status, headers_dict,
    raw_header_blob, body_snippet) or None."""
    try:
        if scheme == "https":
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=_SSL,
                                        server_hostname=None),
                timeout=timeout)
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return None

    try:
        host_hdr = f"[{ip}]" if ":" in ip else ip
        req = (f"{method} {path} HTTP/1.1\r\n"
               f"Host: {host_hdr}\r\n"
               f"User-Agent: {UA}\r\n"
               f"Accept: */*\r\n"
               f"Connection: close\r\n\r\n")
        writer.write(req.encode("latin-1", "replace"))
        await asyncio.wait_for(writer.drain(), timeout=timeout)

        # Read headers (up to blank line), then a small body snippet.
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 16384:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            raw += chunk
        head, _, rest = raw.partition(b"\r\n\r\n")
        body = rest
        # pull a little more body only for GET (error-page sniff), capped
        if method == "GET":
            while len(body) < 8192:
                try:
                    chunk = await asyncio.wait_for(reader.read(4096),
                                                   timeout=timeout)
                except Exception:
                    break
                if not chunk:
                    break
                body += chunk
    except Exception:
        try:
            writer.close()
        except Exception:
            pass
        return None
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except Exception:
            pass

    head_text = head.decode("latin-1", "replace")
    lines = head_text.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return None
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        status = 0
    headers = {}
    cookies = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if k == "set-cookie":
            cookies.append(v)
        else:
            headers[k] = v
    if cookies:
        headers["set-cookie"] = " | ".join(cookies)
    return status, headers, head_text, body.decode("latin-1", "replace")


async def probe(ip, port, scheme, timeout, check_phpinfo):
    r = Result(ip=ip, port=port, scheme=scheme)

    # Primary: GET / (so we can also sniff cookies and error-page wording)
    primary = await _raw_request(ip, port, scheme, "GET", "/", timeout)
    if primary is None:
        # Fallback to HEAD in case GET body streaming misbehaves
        primary = await _raw_request(ip, port, scheme, "HEAD", "/", timeout)
    if primary is None:
        return None

    status, headers, _head_text, body = primary
    r.status = status
    r.server = headers.get("server", "")
    r.powered_by = headers.get("x-powered-by", "")
    r.set_cookie = headers.get("set-cookie", "")

    # Opportunistic phpinfo read (only a mistakenly-exposed one answers 200)
    phpinfo_ver = None
    if check_phpinfo:
        pi = await _raw_request(ip, port, scheme, "GET", "/phpinfo.php", timeout)
        if pi and pi[0] == 200:
            pi_body = pi[3]
            if "phpinfo()" in pi_body.lower() or PHPINFO_VER_RE.search(pi_body):
                m = PHPINFO_VER_RE.search(pi_body)
                if m:
                    phpinfo_ver = (int(m.group(1)), int(m.group(2)),
                                   int(m.group(3)))
                    r.evidence.append("exposed /phpinfo.php")

    classify(r, body=body, phpinfo_ver=phpinfo_ver)
    return r


# ===========================================================================
# 3. Classification with graded confidence
# ===========================================================================
def _grade_version(major, minor, patch):
    branch = (major, minor)
    if branch in FIXED_BY_BRANCH:
        fx = FIXED_BY_BRANCH[branch]
        if (major, minor, patch) >= fx:
            return PATCHED, f">= {fx[0]}.{fx[1]}.{fx[2]} upstream (fixed)"
        return VULN, (f"upstream < {fx[0]}.{fx[1]}.{fx[2]} — confirm distro "
                      f"backport (CVE-2026-109618/109619)")
    if branch in EOL_BRANCHES:
        return EOL, "unmaintained branch — exposed unless source-backported"
    return INDET, "branch outside reference set — verify manually"


def classify(r, body="", phpinfo_ver=None):
    banner = f"{r.server} {r.powered_by}"

    # (a) Exact version from a server banner -> highest confidence
    m = PHP_VER_RE.search(banner)
    if m:
        major, minor, patch = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        r.php_version = f"{major}.{minor}.{patch}"
        r.verdict, r.detail = _grade_version(major, minor, patch)
        r.confidence = CONF_CONFIRMED
        r.evidence.insert(0, "version in HTTP banner")
        return

    # (b) Exact version from an exposed phpinfo -> confirmed too
    if phpinfo_ver:
        major, minor, patch = phpinfo_ver
        r.php_version = f"{major}.{minor}.{patch}"
        r.verdict, r.detail = _grade_version(major, minor, patch)
        r.confidence = CONF_CONFIRMED
        return

    # No exact version — gather soft PHP signals
    signals = []
    if PHP_COOKIE_HINTS.search(r.set_cookie):
        signals.append("php session cookie")
    if PHP_HINT_RE.search(banner):
        signals.append("'php' in banner (no version)")
    if body and PHP_ERROR_HINTS.search(body):
        signals.append("php error-page wording")

    if signals:
        # PHP present, version hidden (expose_php=Off) -> possible, not safe
        r.verdict = INDET
        r.confidence = CONF_POSSIBLE
        r.evidence.extend(signals)
        r.detail = ("PHP detected but version hidden — treat as potentially "
                    "exposed; confirm out-of-band")
        return

    # No PHP evidence at all
    r.verdict = INDET
    r.confidence = CONF_NONE
    r.detail = "no PHP evidence (may be non-PHP, or fully hidden)"


# ===========================================================================
# 4. Orchestration (async, bounded concurrency, optional rate limit, resume)
# ===========================================================================
async def run_scan(hosts, ports, timeout, concurrency, rate,
                   check_phpinfo, only_hits, on_result, done_keys):
    sem = asyncio.Semaphore(concurrency)
    jobs = []
    for ip in hosts:
        for port in ports:
            key = f"{ip}:{port}"
            if key in done_keys:
                continue
            scheme = "https" if port in (443, 8443, 4443) else "http"
            jobs.append((ip, port, scheme))

    total = len(jobs)
    state = {"done": 0, "hits": 0}
    interval = (1.0 / rate) if rate and rate > 0 else 0.0
    last = [0.0]
    ratelock = asyncio.Lock()

    async def one(ip, port, scheme):
        if interval:
            async with ratelock:
                now = time.monotonic()
                wait = last[0] + interval - now
                if wait > 0:
                    await asyncio.sleep(wait)
                last[0] = time.monotonic()
        async with sem:
            try:
                r = await probe(ip, port, scheme, timeout, check_phpinfo)
            except Exception:
                r = None
        state["done"] += 1
        if r is not None:
            if not (only_hits and r.confidence == CONF_NONE):
                if r.verdict in (VULN, EOL) or r.confidence == CONF_POSSIBLE:
                    state["hits"] += 1
                on_result(r, state, total)
        if state["done"] % 200 == 0 or state["done"] == total:
            sys.stderr.write(f"\r[*] {state['done']}/{total} probes, "
                             f"{state['hits']} findings")
            sys.stderr.flush()
        return r

    await asyncio.gather(*(one(*j) for j in jobs))
    sys.stderr.write("\r" + " " * 60 + "\r")
    return total


# ===========================================================================
# 5. Output
# ===========================================================================
CSV_HEADER = ["ip", "port", "scheme", "status", "php_version", "verdict",
              "confidence", "evidence", "detail", "server", "x_powered_by"]


def load_resume(path):
    """Read a JSONL output file and return the set of ip:port already scanned."""
    done = set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                    done.add(f"{o['ip']}:{o['port']}")
                except Exception:
                    continue
    except OSError:
        pass
    return done


def write_html(results, path, meta):
    def esc(s):
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;"))
    order = {VULN: 0, EOL: 1, INDET: 2, PATCHED: 3}
    rows = sorted(results, key=lambda r: (order.get(r.verdict, 9),
                                          r.confidence != CONF_POSSIBLE, r.ip))
    counts = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    badge = {VULN: "#c0392b", EOL: "#e67e22", INDET: "#7f8c8d",
             PATCHED: "#27ae60"}
    tr = []
    for r in rows:
        tr.append(
            f"<tr><td><code>{esc(r.url)}</code></td>"
            f"<td>{esc(r.php_version or '—')}</td>"
            f"<td><span style='color:#fff;background:{badge.get(r.verdict,'#555')};"
            f"padding:2px 8px;border-radius:4px;font-size:12px'>{esc(r.verdict)}</span></td>"
            f"<td>{esc(r.confidence)}</td>"
            f"<td>{esc('; '.join(r.evidence))}</td>"
            f"<td>{esc(r.detail)}</td></tr>")
    summary = " · ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
    html = f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>php2shell exposure report</title>
<style>
 body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
   margin:0;background:#f5f6f8;color:#1a1a1a}}
 header{{background:#111827;color:#fff;padding:20px 28px}}
 header h1{{margin:0;font-size:20px}} header p{{margin:4px 0 0;color:#9ca3af;font-size:13px}}
 .wrap{{max-width:1100px;margin:24px auto;padding:0 16px}}
 .summary{{background:#fff;border-radius:8px;padding:14px 18px;margin-bottom:18px;
   box-shadow:0 1px 3px rgba(0,0,0,.08);font-size:14px}}
 table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;
   overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid #eee;font-size:13px;
   vertical-align:top}}
 th{{background:#f0f1f3;font-weight:600}} code{{font-size:12px}}
 .note{{color:#6b7280;font-size:12px;margin-top:14px;line-height:1.5}}
</style></head><body>
<header><h1>php2shell — exposure report (CVE-2026-109618 / CVE-2026-109619)</h1>
<p>Generated {esc(meta['generated'])} · scope: {esc(meta['scope'])} · non-destructive banner fingerprint</p></header>
<div class="wrap">
<div class="summary"><b>{len(results)}</b> web responses · {esc(summary)}</div>
<table><thead><tr><th>Host</th><th>PHP</th><th>Verdict</th><th>Confidence</th>
<th>Evidence</th><th>Detail</th></tr></thead><tbody>
{''.join(tr)}
</tbody></table>
<p class="note"><b>Read before acting.</b> This is a non-destructive scan:
the PHP version is read from HTTP banners / cookies / error pages only, and the
tool never triggers the OOM condition or sends exploitation traffic.
<b>LIKELY_EXPOSED</b> means the host advertises a PHP version below the upstream
fix — but Linux distributions backport fixes without changing the version
string, so a Debian/Ubuntu/RHEL host may already be patched. Always confirm a
hit out-of-band (distro package revision, <code>php -v</code>) before reporting
it. An <b>INDETERMINATE</b> + <i>possible</i> row means PHP is present but its
version is hidden — treat as potentially exposed, not safe. Upstream fixed
versions: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. Credits: Calif, OpenAI, Wiz
(discovery); PHP Foundation (fix); Searchlight Cyber (detection research).</p>
</div></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def print_summary(results):
    buckets = {}
    for r in results:
        buckets.setdefault(r.verdict, []).append(r)
    print("\n" + "=" * 64)
    print("SUMMARY")
    print("=" * 64)
    labels = [(VULN, "LIKELY EXPOSED (outdated)"),
              (EOL, "LIKELY EXPOSED (EOL branch)"),
              (INDET, "INDETERMINATE"), (PATCHED, "UP TO DATE (upstream)")]
    for key, label in labels:
        items = buckets.get(key, [])
        if not items:
            continue
        if key == INDET:
            poss = sum(1 for r in items if r.confidence == CONF_POSSIBLE)
            print(f"  {label:26}: {len(items):5}   ({poss} with PHP signals)")
        else:
            print(f"  {label:26}: {len(items):5}")
    print("=" * 64)
    hot = buckets.get(VULN, []) + buckets.get(EOL, [])
    poss = [r for r in buckets.get(INDET, []) if r.confidence == CONF_POSSIBLE]
    if hot:
        print("\nPRIORITY (outdated upstream — confirm distro backport):")
        for r in sorted(hot, key=lambda x: x.ip):
            print(f"  {r.url:30} PHP {r.php_version or '?':9} [{r.confidence}] {r.detail}")
    if poss:
        print("\nTO VERIFY (PHP present, version hidden):")
        for r in sorted(poss, key=lambda x: x.ip)[:50]:
            print(f"  {r.url:30} {'; '.join(r.evidence)}")
        if len(poss) > 50:
            print(f"  … and {len(poss) - 50} more (see output file)")


# ===========================================================================
# 6. CLI
# ===========================================================================
def main():
    ap = argparse.ArgumentParser(
        prog="php2shell-scanner",
        description="Non-destructive exposure scanner for php2shell "
                    "(CVE-2026-109618 / CVE-2026-109619).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  php2shell-scanner --authorized --asn AS37649 --html report.html --jsonl out.jsonl
  php2shell-scanner --authorized --cidr 196.1.95.0/24 --ports 80,443,8080
  php2shell-scanner --authorized --targets-file ips.txt --rate 50 --resume out.jsonl
""")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--asn", help="ASN to resolve to announced prefixes (e.g. AS37649)")
    src.add_argument("--cidr", action="append", help="CIDR/subnet or IP (repeatable)")
    src.add_argument("--targets-file", help="File: one IP/CIDR per line")

    ap.add_argument("--authorized", action="store_true",
                    help="MANDATORY: attest you are authorised to scan these targets.")
    ap.add_argument("--ports", default="80,443", help="Ports to probe (default 80,443)")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--concurrency", type=int, default=400,
                    help="Max concurrent connections (default 400)")
    ap.add_argument("--rate", type=float, default=0,
                    help="Approx requests/sec cap (0 = unlimited)")
    ap.add_argument("--max-hosts", type=int, default=65536,
                    help="Safety cap on enumerated hosts (default 65536)")
    ap.add_argument("--ipv6", action="store_true",
                    help="For --asn: use announced IPv6 prefixes instead of IPv4")
    ap.add_argument("--phpinfo-check", action="store_true",
                    help="Also read a mistakenly-exposed /phpinfo.php if present "
                         "(extra request per host)")
    ap.add_argument("--only-hits", action="store_true",
                    help="Keep only hosts with any PHP evidence")
    ap.add_argument("--jsonl", help="Stream results to JSONL (also used by --resume)")
    ap.add_argument("--resume", help="Resume: skip ip:port already in this JSONL file")
    ap.add_argument("--csv", help="Write CSV at the end")
    ap.add_argument("--json", help="Write a single JSON array at the end")
    ap.add_argument("--html", help="Write an HTML report at the end")
    ap.add_argument("--version", action="version", version=f"php2shell-scanner {VERSION}")
    args = ap.parse_args()

    if not args.authorized:
        sys.exit("[!] Re-run with --authorized to confirm you have permission "
                 "to scan these targets.")

    try:
        ports = [int(p) for p in args.ports.split(",") if p.strip()]
    except ValueError:
        sys.exit("[!] Invalid --ports.")

    scope = ""
    if args.asn:
        cidrs = asn_to_prefixes(args.asn, v6=args.ipv6)
        scope = f"{args.asn} ({len(cidrs)} prefixes)"
        print(f"[*] {args.asn} -> {len(cidrs)} announced "
              f"{'IPv6' if args.ipv6 else 'IPv4'} prefixes")
    elif args.cidr:
        cidrs = args.cidr
        scope = ", ".join(args.cidr)
    else:
        try:
            with open(args.targets_file, encoding="utf-8") as f:
                cidrs = [l.strip() for l in f
                         if l.strip() and not l.startswith("#")]
        except OSError as e:
            sys.exit(f"[!] Cannot read targets file: {e}")
        scope = f"file:{args.targets_file}"

    hosts = expand_targets(cidrs, args.max_hosts)
    if not hosts:
        sys.exit("[!] No hosts to scan.")

    done_keys = load_resume(args.resume) if args.resume else set()
    if done_keys:
        print(f"[*] Resume: {len(done_keys)} ip:port already done, skipping them.")

    results = []
    jsonl_f = None
    if args.jsonl:
        jsonl_f = open(args.jsonl, "a", encoding="utf-8")

    def on_result(r, state, total):
        results.append(r)
        if jsonl_f:
            jsonl_f.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")
            jsonl_f.flush()
        if r.verdict in (VULN, EOL):
            sys.stderr.write("\r" + " " * 60 + "\r")
            print(f"[!] {r.verdict:15} {r.url:30} PHP {r.php_version or '?':9} "
                  f"[{r.confidence}] {r.detail}")

    print(f"[*] {len(hosts)} hosts x {len(ports)} ports | concurrency "
          f"{args.concurrency} | timeout {args.timeout}s"
          + (f" | ~{args.rate} req/s" if args.rate else ""))
    print("-" * 64)

    t0 = time.time()
    try:
        asyncio.run(run_scan(hosts, ports, args.timeout, args.concurrency,
                             args.rate, args.phpinfo_check, args.only_hits,
                             on_result, done_keys))
    except KeyboardInterrupt:
        sys.stderr.write("\r" + " " * 60 + "\r")
        print("\n[!] Interrupted. Partial results kept"
              + (f"; resume with --resume {args.jsonl}" if args.jsonl else "")
              + ".")
    finally:
        if jsonl_f:
            jsonl_f.close()

    print_summary(results)

    meta = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "scope": scope}
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(CSV_HEADER)
            for r in sorted(results, key=lambda x: (x.verdict, x.ip)):
                w.writerow(r.row())
        print(f"[+] CSV: {args.csv}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"meta": meta, "results": [asdict(r) for r in results]},
                      f, ensure_ascii=False, indent=2)
        print(f"[+] JSON: {args.json}")
    if args.html:
        write_html(results, args.html, meta)
        print(f"[+] HTML: {args.html}")
    if args.jsonl:
        print(f"[+] JSONL: {args.jsonl}")

    print(f"\n[*] Done in {time.time()-t0:.1f}s. {len(results)} web responses.")
    print("[i] Reminder: LIKELY_EXPOSED = outdated upstream version, NOT "
          "confirmed vulnerable — distro backports are invisible over HTTP. "
          "INDETERMINATE is not 'safe'. Confirm hits out-of-band "
          "(distro package, `php -v`, asset inventory) before reporting.")


if __name__ == "__main__":
    main()
