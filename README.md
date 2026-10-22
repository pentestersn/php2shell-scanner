# php2shell-scanner

**Non-destructive exposure scanner for php2shell — CVE-2026-109618 & CVE-2026-109619.**

Give it an ASN, a subnet, an IP, or a file of targets. It fingerprints the PHP
version each web host exposes and grades the host's exposure to the two
critical PHP remote-code-execution vulnerabilities disclosed in the
[PHP Security Release of 21 October 2026](https://www.php.net/archive/2026.php#2026-10-21-5) —
**without ever triggering the crash the real exploit relies on.**

```
LIKELY_EXPOSED      PHP below upstream fix (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)
LIKELY_EXPOSED_EOL  unmaintained branch (7.x–8.1): no official branch fix
PATCHED             at or above the upstream fix for its branch
INDETERMINATE       PHP present but version hidden, or no PHP banner at all
```

Every verdict carries a **confidence level** (`confirmed` / `possible` / `none`)
so you never get a binary answer that over-promises.

> ⚠️ **It says `LIKELY_EXPOSED`, not `VULNERABLE`, on purpose.** The tool reads
> the version a server advertises. Linux distributions (Debian, Ubuntu, RHEL…)
> backport security fixes **without changing the version string**, so a host
> showing `PHP/8.2.28` may already be patched via its distro package. A
> `LIKELY_EXPOSED` verdict means *"running an outdated upstream version —
> confirm the distro package"*, **not** *"confirmed vulnerable"*. This is why
> version-only scanners produce false positives. Always verify a hit
> out-of-band before acting on it. See [Known limitations](#known-limitations).

---

## Why "safe by design"

The php2shell vulnerability is a memory-corruption RCE that is *reached* by
forcing an out-of-memory (OOM) condition in the PHP worker. The only way to
**prove** exploitability is to actually trigger that condition — which crashes
the worker. The official
[Searchlight / Assetnote scanner](https://github.com/assetnote/php2shell-scanner)
does exactly that, and warns about it.

This tool deliberately does **not**. It only reads what a server already
advertises:

- `Server` and `X-Powered-By` response headers
- `Set-Cookie` session cookies (`PHPSESSID`, `laravel_session`, `wordpress_`, …)
- default PHP error-page wording
- an opportunistic read of a *mistakenly-exposed* `/phpinfo.php` (opt-in; it
  never creates one)

**Consequences of that choice — read both:**

- ✅ It sends **no exploitation traffic** and will **not take down** a production
  worker. You can run it against your own estate during business hours.
- ⚠️ A host that hides its PHP version comes back **`INDETERMINATE` / `possible`**,
  **not "safe."** It must be confirmed another way (server access, `php -v`,
  asset inventory). Treat `possible` as *potentially exposed*.

If you have a single host under a signed engagement where you need **active
confirmation**, use the official destructive scanner there, with explicit
sign-off in your rules of engagement — not this tool against a whole range.

---

## Install

No dependencies. Python 3.8+ standard library only.

```bash
git clone https://github.com/<your-user>/php2shell-scanner.git
cd php2shell-scanner
python3 php2shell_exposure_scanner.py --help
```

---

## Usage

The `--authorized` flag is **mandatory** — it is your attestation that you have
permission to scan the targets.

```bash
# Scan an ASN (resolved to announced prefixes via RIPEstat), full report
python3 php2shell_exposure_scanner.py --authorized --asn AS37649 \
    --html report.html --jsonl out.jsonl

# Scan a subnet, extra ports, opportunistic phpinfo read
python3 php2shell_exposure_scanner.py --authorized --cidr 203.0.113.0/24 \
    --ports 80,443,8080,8443 --phpinfo-check

# Scan from a file, rate-limited and resumable
python3 php2shell_exposure_scanner.py --authorized --targets-file ips.txt \
    --rate 50 --jsonl out.jsonl --resume out.jsonl
```

### Key options

| Option | What it does |
|---|---|
| `--asn AS####` | Resolve an ASN to its announced prefixes (RIPEstat, no API key) |
| `--cidr`, `--targets-file` | Subnet/IP (repeatable) or a file of targets |
| `--ports 80,443,…` | Ports to probe (443/8443/4443 → HTTPS) |
| `--concurrency 400` | Max concurrent connections (async engine) |
| `--rate N` | Approx requests/sec cap, to stay polite / low-noise |
| `--phpinfo-check` | Also read an exposed `/phpinfo.php` if present |
| `--max-hosts N` | Safety cap on enumerated hosts (default 65 536) |
| `--jsonl FILE` + `--resume FILE` | Stream results and resume an interrupted scan |
| `--csv`, `--json`, `--html` | Report formats; HTML is RSSI-ready |
| `--ipv6` | For `--asn`: use announced IPv6 prefixes |

---

## Output

- **Console**: live findings + a summary with a priority list.
- **JSONL**: one result per line, machine-readable, and the resume source.
- **CSV / JSON**: full structured results.
- **HTML**: a clean report you can forward to a CISO as-is.

A result row looks like:

```json
{"ip":"203.0.113.10","port":443,"scheme":"https","status":200,
 "php_version":"8.3.30","verdict":"LIKELY_EXPOSED","confidence":"confirmed",
 "evidence":["version in HTTP banner"],
 "detail":"upstream < 8.3.36 — confirm distro backport (CVE-2026-109618/109619)"}
```

---

## How verdicts are decided

1. Exact version in a `Server` / `X-Powered-By` banner, or in an exposed
   `phpinfo` → **confirmed**, compared against the fixed-version table.
2. No version, but a PHP session cookie / error-page wording / `php` in the
   banner → **INDETERMINATE, possible** (PHP present, version hidden).
3. No PHP evidence at all → **INDETERMINATE, none**.

Fixed versions (PHP Security Release, 21 Oct 2026):

| Branch | Fixed in |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 and older | EOL — no official branch fix (source backports exist for 7.4 / 8.0 / 8.1) |

> Remote mod_php vs PHP-FPM detection is unreliable, so this tool does not claim
> it. The advisory rates the risk highest for Apache mod_php, where an
> unauthenticated request can trigger the bug before any application code runs.

---

## Known limitations

Be upfront about these — they are inherent to **any** banner-based scanner, and
knowing them is what separates triage from a false alarm.

- **Distro backports cause false positives.** This is the big one. Debian,
  Ubuntu and RHEL ship security fixes in their own package revisions
  (`8.2.28-1+debXuY`) *without* bumping the upstream version string. Such a host
  is patched but still advertises `PHP/8.2.28`, so it shows up as
  `LIKELY_EXPOSED`. Treat every hit as "verify the distro package", not
  "confirmed vulnerable". The tool deliberately says *likely*, never
  *vulnerable*, for this reason.
- **Hidden versions cause "false negatives" in disguise.** Hardened servers set
  `expose_php = Off`, so most real-world hosts emit no version. They land in
  `INDETERMINATE` — which is **not** a clean bill of health, just an unknown. On
  a real scan expect many `INDETERMINATE` rows and relatively few `confirmed`.
- **Name-based virtual hosts / CDNs.** The scanner connects by IP without SNI,
  so a shared-hosting IP or a CDN edge may answer with a default vhost (or
  refuse TLS), giving the wrong banner or none. Pair the results with DNS data
  for name-vhosted estates.
- **Exposure ≠ exploitability.** This tool maps who is *likely* running
  unpatched PHP. It does not and will not prove the RCE is reachable — that
  requires the destructive OOM test this tool refuses to perform.

In short: use it to **prioritise a patch campaign**, not to certify a host as
safe or to publish a "vulnerable" label about anyone.

---

## Responsible use

- Scan **only** assets you own or are contracted to test, with written
  authorisation / rules of engagement. Unauthorised scanning is illegal in most
  jurisdictions, including the UEMOA area.
- Even non-destructive scanning generates traffic and logs. Use `--rate` and
  scope tightly.
- Never publish a report, screenshot, or dataset that identifies a specific
  vulnerable third-party host. Aggregate and anonymise.
- This tool reports **exposure**, not confirmed exploitability. `INDETERMINATE`
  is not a clean bill of health.

---

## Remediation (what to tell the owner)

**Patch.** Upgrade to PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, or a vendor
backport. There is no complete mitigation short of patching. If you genuinely
cannot patch yet, the PHP advisory lists partial, temporary measures (e.g.
`memory_limit=-1` set so applications can't override it, a low `post_max_size`,
and `session.upload_progress.enabled=0`) — read it in full before relying on
any of them.

---

## Credits

- **Vulnerability discovery:** Calif Research (Ryan Austin, @lcfr_hax), OpenAI,
  and Wiz — [write-up](https://calif.io/php2shell/).
- **Fix & advisory:** The PHP Foundation / PHP security team —
  [release](https://www.php.net/archive/2026.php#2026-10-21-5).
- **Detection research & reference scanner:** Searchlight Cyber (ex-Assetnote) —
  [research](https://www.slcyber.io/research/high-fidelity-detection-mechanism-for-php2shell-cve-2026-109618-and-cve-2026-109619).

This project is an independent, non-destructive exposure-mapping tool. It is not
affiliated with, or endorsed by, any of the above.

## License

MIT — see [LICENSE](LICENSE).

Maintained by [Group Systemik](https://groupsystemik.com/).
