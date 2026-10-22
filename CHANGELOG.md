# Changelog

## 1.0.0 — 2026-10-22
Initial public release.

- ASN (via RIPEstat), CIDR, IP, and targets-file input.
- Non-destructive multi-source PHP fingerprinting: HTTP headers, session
  cookies, error-page wording, opt-in exposed `/phpinfo.php`.
- Graded confidence: confirmed / possible / none.
- Verdicts: LIKELY_EXPOSED, LIKELY_EXPOSED_EOL, PATCHED, INDETERMINATE, against
  the 21 Oct 2026 upstream fixed-version table (8.2.35 / 8.3.36 / 8.4.27 /
  8.5.12). Verdicts are framed as "likely exposed", not "vulnerable", because
  distro backports are invisible over HTTP (documented in README limitations).
- Async engine with bounded concurrency and optional rate limiting.
- Resumable scans (JSONL stream + `--resume`).
- Output: console summary, JSONL, CSV, JSON, HTML report.
