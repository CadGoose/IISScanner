# IISScanner: IIS tilde (~) short-name enumeration checker

Checks whether an IIS web server leaks **8.3 short file and folder names** through the tilde (`~`) character, a long-standing IIS information disclosure (CWE-200). When vulnerable, an attacker can guess the first characters of hidden files and folders (for example `BACKUP~1.ZIP` or `WEB~1.CON`) that should never be discoverable, which often leads to backup, config or admin-panel exposure.

## What it does

1. **Fingerprints the server:** looks for IIS / ASP.NET headers and warns when a CDN (CloudFront, Cloudflare) may be filtering tilde requests.
2. **Differential test:** sends a valid tilde pattern (`/*~1*/.aspx`) and an invalid control (`/xyz123~1*/.aspx`), then compares status code, response length and timing. A consistent difference means short names are enumerable.
3. **Common paths:** repeats the test on `/admin/`, `/uploads/`, `/backup/`, `/api/` and other common folders.
4. **Extensions:** probes `.aspx`, `.config`, `.bak`, `.zip` and others.
5. **Report:** prints the result with remediation and saves a plain-text copy (`iis_tilde_scan_<host>_<time>.txt`).

## Usage

```bash
pip install -r requirements.txt
python3 iis_tilde_scanner.py -u https://target.example
python3 iis_tilde_scanner.py -u https://target.example -H "X-Bug-Bounty: CadGoose" -c "session=abc123"
```

Exit code is `1` when the target is vulnerable, `0` otherwise, so it can be scripted.

## Remediation (for defenders)

- Disable 8.3 name creation: `fsutil 8dot3name set <volume> 1`, then strip existing short names (`fsutil 8dot3name strip`)
- Keep IIS and .NET patched
- Block `~` in URLs with a request-filtering or URL Rewrite rule

## Notes

- Only test systems you own or are explicitly authorized to test (for example, an in-scope bug bounty asset).
- The scan is non-destructive (GET requests only) but noisy, and TLS verification is disabled for lab targets.
- Timing differences alone can be caused by network jitter, so confirm by hand before reporting.

---

Part of [@CadGoose](https://github.com/CadGoose)'s security tooling · [cadgoose.github.io](https://cadgoose.github.io)
