# OWASP Juice Shop — SSRF: "Request a hidden resource on server through server"

> A full exploit chain against a 6-star Juice Shop challenge, from `robots.txt` recon to forging an internal request through a vulnerable profile-image endpoint.

| | |
|---|---|
| **Challenge** | SSRF — Request a hidden resource on server through server |
| **Difficulty** | ⭐ 6-star |
| **OWASP Top 10** | A10:2021 – Server-Side Request Forgery |
| **Severity** | Critical |
| **Target** | OWASP Juice Shop (Docker), `http://localhost:3000` |
| **Environment** | Kali Linux VM, Firefox, Wireshark, OWASP ZAP |

---

## Why this challenge is interesting

Most SSRF labs hand you the internal URL. This one doesn't. The endpoint you need to reach — and the secret key that guards it — are hidden inside a malware sample sitting in an exposed quarantine directory. You have to chain three separate misconfigurations before you even get to the SSRF itself:

1. `robots.txt` leaks the path to a directory that was supposed to be hidden.
2. Directory indexing on that path exposes its contents without authentication.
3. The profile-image endpoint accepts an arbitrary URL and fetches it server-side with no validation.

None of these is critical alone. Together they're a full server-side request forgery.

---

## Step 1 — Recon: `robots.txt` gives away the hidden path

The first thing worth checking on any web target is `robots.txt`. It's not an access control — it's a request to crawlers, and it's readable by anyone:

```
User-agent: *
Disallow: /ftp
```

`Disallow` is advisory. All this actually does is tell an attacker where to look.

**Takeaway:** if a path needs to be hidden, it needs authentication. Listing it in `robots.txt` does the opposite of hiding it.

## Step 2 — Directory indexing exposes a quarantine repository

Navigating directly to `/ftp/quarantine` returned an open directory listing, no authentication required:

```
~ / ftp / quarantine
    juicy_malware_linux_amd_64.url
    juicy_malware_linux_arm_64.url
    juicy_malware_macos_64.url
    juicy_malware_windows_64.exe.url
```

Cross-compiled malware samples, publicly browsable. `juicy_malware_linux_amd_64.url` matched the target platform, so that's the one I pulled.

## Step 3 — Static analysis: inspect before you execute

The file was downloaded to the local Kali environment and opened in a plain text editor (Mousepad) rather than executed. Opening an unknown binary in a text editor first is basic hygiene — you get metadata, configuration, and any embedded pointers with zero risk of detonating it.

The contents showed it was a shortcut/pointer file referencing an external payload, which meant it was designed to initiate a network connection. That's exactly the kind of behaviour that won't show up in static analysis alone, so the next step had to be dynamic.

## Step 4 — Dynamic analysis: catching the C2 beacon in Wireshark

To see where the sample tried to communicate without exposing anything real:

- Wireshark listening on the **loopback interface (`lo`)**, since the whole target stack is local.
- Display filter set to `http` to cut noise.
- Sample executed from the command line while capturing.

The binary made a single **unencrypted HTTP GET** request, which Wireshark caught in full:

```http
GET /solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3 HTTP/1.1
Host: localhost:3000
User-Agent: Go-http-client/1.1
Accept-Encoding: gzip
```

Two things fall out of this one packet: the **hidden internal endpoint** (`/solve/challenges/server-side`) and the **secret key** that authorizes it. Cleartext HTTP means no interception effort was needed at all — the credential was simply on the wire.

**Takeaway:** anything sensitive travelling over plain HTTP, even on loopback, is readable by anyone who can capture on that interface.

## Step 5 — Finding the injection vector

Knowing *what* to request isn't enough. That endpoint only accepts requests originating from the server itself, so a direct browser request is refused. Something on the server has to make the request on my behalf.

The **User Profile** page provides exactly that: an option to set a profile image by URL. The backend takes the user-supplied `imageUrl`, and its internal HTTP client fetches it server-side. No allow-list, no scheme restriction, no block on private or loopback addresses.

That's the SSRF primitive.

## Step 6 — Interception and payload injection with OWASP ZAP

OWASP ZAP was configured as an inline intercepting proxy on `localhost:8080`, with a breakpoint on outbound requests.

Triggering a profile image update from the browser captured this request:

```http
POST /profile/image/url HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded
Origin: http://localhost:3000
Referer: http://localhost:3000/profile

imageUrl=<original value>
```

The `imageUrl` value was replaced with the internal endpoint and key discovered in Step 4, URL-encoded:

```
imageUrl=http%3A%2F%2Flocalhost%3A3000%2Fsolve%2Fchallenges%2Fserver-side%3Fkey%3DtRy_H4rd3r_n0thIng_iS_Imp0ssibl3
```

Request forwarded.

## Result

The backend accepted the input without validation and issued the request itself. Because it originated from `127.0.0.1`, it satisfied the endpoint's internal-origin condition and bypassed the external access controls entirely:

> ✅ **You successfully solved a challenge: SSRF (Request a hidden resource on server through server)**

| Achieved | Impact | Severity | OWASP |
|---|---|---|---|
| Forged an unauthorized internal request; retrieved C2 key; reached a restricted admin endpoint | Critical | 6-star | A10:2021 – SSRF |

---

## Real-world impact

In a production environment, this same primitive would allow an attacker to:

- **Bypass perimeter controls** — the request originates inside the trust boundary, so firewall rules written for external traffic never apply.
- **Reach internal-only services** — admin panels, health endpoints, and internal APIs that were never meant to be publicly routable.
- **Hit cloud metadata services** — on AWS/GCP/Azure, `169.254.169.254` is a classic SSRF target that can leak temporary IAM credentials.
- **Port-scan the internal network** — response timing and error differences reveal which internal hosts and ports are live.
- **Exfiltrate data** — using the web server as a proxy to pull from internal resources and return them in the response.

## Remediation

| Issue | Fix |
|---|---|
| No validation on `imageUrl` | Enforce a strict **allow-list** of permitted domains. Never pass user input directly to a server-side HTTP client. |
| Internal addresses reachable | Block requests to loopback and private ranges: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`. Re-check **after** DNS resolution to prevent rebinding. |
| Redirect bypass | Disable automatic redirect following, or re-validate the destination on every hop. |
| Directory indexing enabled | Disable indexing on all static paths; serve only explicitly referenced files. |
| `robots.txt` used to hide paths | Treat it as public documentation. Protect sensitive paths with authentication, not obscurity. |
| Cleartext internal traffic | Use TLS for internal service-to-service communication; don't rely on network position for confidentiality. |
| Flat internal network | Apply segmentation so the web tier cannot reach admin interfaces even when SSRF occurs. |

---

## Reproducing this

```bash
docker pull bkimminich/juice-shop
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Then visit `http://localhost:3000` and work through the steps above.

---

*Performed against a local instance of OWASP Juice Shop — an application intentionally built and maintained for security education. No third-party or production systems were involved.*
