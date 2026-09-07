# SSRF — OWASP Juice Shop

**Challenge:** Request a hidden resource on server through server
**Difficulty:** 6-star
**Classification:** A10:2021 — Server-Side Request Forgery
**Target:** OWASP Juice Shop (Docker), `http://localhost:3000`
**Tools:** Firefox, Wireshark, OWASP ZAP

## Summary

This challenge required chaining three separate misconfigurations to reach a full SSRF: an information leak in `robots.txt`, an open directory listing, and an unvalidated URL parameter on the profile image feature. The endpoint and the key needed to solve the challenge were not visible anywhere in the application UI. They had to be recovered by capturing outbound traffic from a malware sample found in the exposed directory.

## Root Cause

The profile image upload feature accepts a user-supplied `imageUrl` value and fetches it server-side to set the avatar. The backend does not validate the destination of this URL in any way — no scheme restriction, no allow-list, and no check against internal or loopback address ranges. This is the core SSRF condition: the server can be made to issue requests to arbitrary internal targets on the attacker's behalf.

Two additional issues extended the impact:

- `robots.txt` disclosed a path (`/ftp`) that was intended to stay hidden, since it excludes crawlers rather than restricting access.
- Directory indexing was enabled on `/ftp/quarantine`, exposing its file listing to anyone who requested it directly.

## Recon

Checking `robots.txt` is a standard first step against any target:

```
User-agent: *
Disallow: /ftp
```

`Disallow` only tells crawlers not to index a path — it has no effect on direct access. Requesting `/ftp/quarantine` returned a full directory listing with no authentication required:

```
juicy_malware_linux_amd_64.url
juicy_malware_linux_arm_64.url
juicy_malware_macos_64.url
juicy_malware_windows_64.exe.url
```

## Static and Dynamic Analysis

`juicy_malware_linux_amd_64.url` was pulled to a local Kali VM. Rather than executing it directly, it was opened first in a text editor to check for anything obvious before running it — standard practice with any unknown file. The contents indicated it was a pointer file rather than a real binary, meant to trigger an outbound connection.

To see what it actually connected to, Wireshark was set to capture on the loopback interface (`lo`) with an `http` display filter, and the file was then run from the command line.

The capture showed a single cleartext HTTP GET request:

```http
GET /solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3 HTTP/1.1
Host: localhost:3000
User-Agent: Go-http-client/1.1
```

This request disclosed both pieces of information needed to complete the challenge: the internal endpoint (`/solve/challenges/server-side`) and the key required to authorize it.

## Exploitation

The endpoint above only accepts requests originating from the server itself — a direct request from the browser is rejected. The profile image feature provides the mechanism to make the server issue that request on the attacker's behalf.

OWASP ZAP was set up as an intercepting proxy on the profile update request:

```http
POST /profile/image/url HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded

imageUrl=<original value>
```

The `imageUrl` parameter was replaced with the internal endpoint and key recovered from the packet capture, URL-encoded:

```
imageUrl=http%3A%2F%2Flocalhost%3A3000%2Fsolve%2Fchallenges%2Fserver-side%3Fkey%3DtRy_H4rd3r_n0thIng_iS_Imp0ssibl3
```

Forwarding the modified request caused the backend to fetch that URL itself. Because the request originated from `127.0.0.1`, it satisfied the endpoint's internal-origin check and bypassed the access restriction entirely.

## Result

```
You successfully solved a challenge: SSRF (Request a hidden resource on server through server)
```

| Outcome | Severity | Category |
|---|---|---|
| Forged internal request; retrieved restricted key; reached admin-only endpoint | Critical | A10:2021 — SSRF |

## Impact

This same primitive, in a production environment, could be used to:

- Reach internal services and admin interfaces that are not meant to be publicly routable.
- Query cloud metadata endpoints (e.g. `169.254.169.254` on AWS/GCP/Azure) to obtain temporary credentials.
- Enumerate internal hosts and ports through response timing and error behavior.
- Use the web server as a proxy to read from or interact with internal resources.

## Remediation

| Issue | Recommendation |
|---|---|
| `imageUrl` not validated | Restrict to an explicit allow-list of trusted domains. Do not pass user-controlled input directly to a server-side HTTP client. |
| Internal addresses reachable | Block requests to loopback and private IP ranges, re-validated after DNS resolution to prevent rebinding. |
| Redirects not restricted | Disable automatic redirect following, or re-check the destination on every redirect. |
| Directory indexing enabled | Disable indexing on all static file paths. |
| Sensitive path listed in `robots.txt` | Protect the path with authentication. `robots.txt` is public and provides no access control. |
| Secret transmitted in cleartext | Use TLS for internal traffic; don't rely on network position for confidentiality. |

## Reproduction

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Then follow the steps above against `http://localhost:3000`.

---

*Performed against a local instance of OWASP Juice Shop, an application built for security training. No third-party systems were involved.*
