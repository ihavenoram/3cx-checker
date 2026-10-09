# 3CX Desk-Phone Connectivity Checker - technical notes

> The full reference for every tab and check. The [README](../README.md) has the short version. The regression tests mentioned below are not part of this release.

A **PowerShell WinForms** tool for confirming, on-site, that a location can reach
its 3CX server on the ports desk phones use, for measuring how well the UDP path
to the PBX actually behaves, and for spotting the Yealink phones already on the
LAN.

Built for **Windows PowerShell 5.1** (the built-in `powershell.exe`). No admin
rights are needed for the network tests.

## Files

| File | Role |
|------|------|
| `3CX-Checker.ps1` | UI, background worker, report rendering |
| `Generate-3cxReport.ps1` | Report generator: the exported JSON in, a self-contained HTML site report out |
| `3CX-Checker.Helpers.ps1` | All network helpers. Loaded as text and dot-sourced into both the UI thread and the worker runspace, so there is one definition of each test. |
| `Launch-3CX-Checker.cmd` | Launcher |

No other files are needed. The SSH terminal uses Windows' own `ssh.exe`; PuTTY's
`plink`/`putty` are optional. They are looked for in `Program Files\PuTTY` first,
then `C:\temp` (alongside the UniFi troubleshooter's copy), then `PATH` - and are
used **only if validly signed by Simon Tatham**. `C:\temp` is writable by every
user on a PC, so an unsigned or re-signed copy planted there is ignored, and the
SIP / SBC tab names it. The signature is checked again just before each run.

Both `.ps1` files must sit in the same folder.

**Never commit site data.** Scan exports, report JSON/HTML, PBX event logs,
blacklist exports and any `3CXSBC` folder describe a customer site - and an SBC's
`3cxsbc.conf` holds its tunnel password and provisioning key. `.gitignore` keeps
them out of the repository; keep it that way.

## Run it

Double-click **`Launch-3CX-Checker.cmd`**. It launches the script with `-STA`
(required by WinForms) and `-ExecutionPolicy Bypass`, so nothing needs to be
installed or unblocked first.

## What it checks

### 3CX Connectivity tab
Enter the 3CX FQDN or full URL (e.g. `yourpbx.3cx.us` or
`https://yourpbx.3cx.us:5001`) and click **Check 3CX**. The box opens with
`<test>.3cx.us`, and clicking into it selects `<test>`, so typing the site
name replaces just that part. Until it is replaced the box is treated as empty:
Check 3CX asks for the name, and the template is never tested or compared against
the phones' provisioning. For each desk-phone port it reports:

| Port | Purpose | Tests run |
|------|---------|-----------|
| 443  | HTTPS provisioning/presence (new v20 & hosted default) | TCP reach + TLS certificate check + HTTPS HEAD |
| 5001 | HTTPS provisioning (v18 / upgraded-v20 default)        | TCP reach + TLS certificate check + HTTPS HEAD |
| 5060 | SIP signalling                           | TCP reach **+ live SIP OPTIONS over UDP** |
| 5061 | SIP over TLS                             | TCP reach + TLS certificate check |
| 5090 | 3CX Tunnel / SBC                         | TCP reach |
| 9000-10999/UDP | RTP audio media                | informational (UDP can't be reliably TCP-tested) |

It also detects and displays the **site's public egress IP** (so you can check it
against 3CX's Allowed / Blacklisted IP lists).

> **Why the UDP SIP test matters.** Desk phones usually register over **UDP**
> 5060 (or TLS/SBC), not TCP. A TCP connect to 5060 succeeding does **not** prove
> the phone's real path works — so the tool sends an actual **SIP OPTIONS** packet
> over UDP and waits for the PBX to answer (`200 OK`). If every TCP port is green
> but phones still say "No Service", this row is the one to read.

The summary box gives a plain-English verdict — which HTTPS port is serving
provisioning (a closed **5001** with an open **443** is normal on modern 3CX),
whether SIP works over both **TCP and UDP**, whether the tunnel is reachable, the
site's public IP, and a warning if the TLS certificate expires within 30 days.

**The TLS certificate check validates the certificate**, the way a phone will.
A hostname mismatch, an expired certificate, a self-signed or private-CA chain,
or a server that **does not send its intermediate certificate** turns the row
red (`cert REJECTED`) and says why. The last one is the easy one to miss:
Windows and browsers quickly fetch a missing intermediate themselves, so the
site looks fine in a browser - but Yealink phones do not fetch it, and
provisioning over TLS fails. The tool compares the chain Windows built with the
certificates the server actually sent, so it catches this even when Windows
papered over it. (Validation uses this PC's trust store; a phone with old
firmware may trust fewer roots, never more.)

> This is the PowerShell 5.1-safe replacement for
> `Invoke-WebRequest -SkipCertificateCheck` (that switch only exists in
> PowerShell 7+). The tool installs a certificate-validation callback instead,
> so self-signed / mismatched certs don't block the reachability test.

### Media / Path Quality tab

The connectivity tab proves *reachability*. It does not prove the audio path is
healthy: a single SIP OPTIONS exchange only shows that one small datagram made
it there and back once. This tab measures the things that actually break calls —
sustained loss, jitter, NAT behaviour and SIP mangling.

#### Read this before trusting any number here

**Nothing answers on the RTP range.** 3CX only opens UDP 9000–10999 for an
established call, so there is no responder to measure real media against.
Everything on this tab is measured over the **SIP signalling path** (UDP 5060 to
the same PBX) or over **STUN**. That is a good proxy — same transport, same
NAT, same WAN, same PBX — but it is a proxy, and the tool says so on every row
rather than only here.

Specifically:

- Loss and jitter are **round-trip**. One-way figures are derived assuming a
  symmetric path, which is stated on the row that uses them.
- The **MOS figure is an estimate** from signalling timing, not a call
  measurement. It is computed for G.711 only, and is refused outright below 100
  replies. G.722 is wideband and the narrowband E-model does not apply to it, so
  no G.722 MOS is offered rather than a wrong one.
- Round-trip time **includes the PBX's own time to answer OPTIONS**, which a
  media relay would not add. When the fastest reply is far quicker than the
  typical one, the tool says so explicitly — that pattern points at the PBX's
  scheduling rather than at your network, and it would otherwise read as "fix
  your WAN".

For quality measured on **real calls**, two sources exist outside this tab: 3CX v20's
own *Monitor Connection Quality*, and the phones' VQ-RTCPXR reporting — see
**Voice-quality (VQ-RTCPXR) readiness** under the Yealink Phones tab.

#### What it measures

| Check | What it tells you |
|-------|-------------------|
| **UDP path quality** | Packet loss, RTT (min/p50/p95/max), RFC 3550 jitter, reordering and duplicates, from a paced train of SIP OPTIONS. |
| **Instrument noise floor** | The tool's own send-pacing spread. Jitter below ~3× this is reported as `<X ms` rather than quoted, because at that point the tool is measuring itself. |
| **NAT mapping behaviour** | Queries two independent STUN servers from one socket. Endpoint-independent mapping is what direct STUN phones need; destination-dependent ("symmetric-like") means they will get one-way or no audio. |
| **Mapping on the SIP path** | Compares the `rport=` the PBX reports against the STUN mapped port **from the same socket** — the mapping test done on the real SIP path, not just against a STUN server. |
| **SIP ALG** | Detects a router rewriting SIP headers. |
| **Path MTU** | DF-bit binary search. Not about RTP (a G.711 packet is ~214 bytes); it matters because a DF-blackhole path stalls TLS handshakes, which looks like provisioning hanging or phones rebooting in a loop. |
| **RTP range reachability** | Positive-only. See below. |
| **Soak** | Repeats a short burst on a slow cycle for 5/15/60 minutes, tracking current / average / **worst** per metric plus full outages. |

#### Known limits, stated up front

- **The RTP range test is positive-only.** An ICMP port-unreachable proves a
  datagram reached the PBX and ICMP came back. *Silence proves nothing* — it is
  equally what a filtered path looks like. Note that unbound RTP ports are
  **normal**: 3CX allocates them per call, so an idle PBX legitimately has the
  whole range closed. The tool will not report that as a fault.
- **SIP ALG detection can produce false negatives.** Many ALGs only rewrite
  REGISTER or INVITE, not OPTIONS, and an ALG that rewrites only `Contact` is
  invisible to *any* OPTIONS-based test because the server never echoes that
  header back. A clean result is not a guarantee — if phones misbehave anyway,
  disable SIP ALG regardless.
- **3CX does not send `received=`**, even though RFC 3581 asks for it. The
  cross-check that would spot UDP and HTTPS leaving by different WANs is
  therefore usually unavailable against 3CX, and the tool says so instead of
  reporting a match.
- **The NAT binding-lifetime test is blind on a port-preserving NAT.** If the
  router hands a re-created binding the same port, a surviving binding and an
  expired one look identical. The tool reports `inconclusive` and tells you to
  leave the phone keep-alive at 30s, rather than inventing a number.
- **Path MTU needs ICMP.** Most cloud-hosted 3CX instances drop echo, in which
  case the tool reports "not measurable" after a single probe instead of
  binary-searching eleven timeouts into a fabricated answer.
- **Reordering and duplicates are never scored.** On a single request/response
  train they read zero almost everywhere, so treating a zero as a pass would be
  claiming a test that was never really exercised.

#### Rate safety

The UDP path test is the only part of this tool that sends the PBX a sustained
stream. If it trips 3CX anti-hacking or Fail2ban, **the whole site loses SIP**
during business hours — so the limits are enforced in code, not just in the UI:

- Default **400 packets over 20s** (20 pps). Gentle mode is 300 over 30s.
- Hard caps of **50 pps and 600 packets** per run, which no caller can raise.
- A **60-second cooldown** between runs.
- Only ever the configured PBX on 5060. The RTP range is probed at 3 ports plus
  a control, spaced ≥1.2s apart — never swept, because 2000 ports from one
  source is a port scan.

If replies stop partway and never resume, the tool reports that as
**rate-limiting, not packet loss**, names the packet number where it happened,
checks whether TCP 443 still works to tell a SIP-layer throttle from a full IP
block, and **suppresses the loss/jitter/MOS figures** rather than publishing
numbers it knows are invalid.

#### Site health

A single Green / Amber / Red verdict, taken as the **worst measured subscore** —
weakest link, not an average, because an excellent MOS must not be allowed to
average away a symmetric NAT that will break every call. "Not measured" is a
first-class fourth state: it never drags the result down, but it is always
listed, so you can tell a healthy site from an untested one. There is
deliberately no 0–100 score — aggregating one real measurement, two heuristics
and a model estimate into "73" would be false precision.

### Yealink Phones tab
Click **Scan LAN**. The subnet box is pre-filled with the network this PC routes
through - the adapter with the lowest-metric default route, with its **real**
prefix (a `/22` office LAN is filled in as `/22`, not cut down to a `/24`). If
the PC is on more than one network (Wi-Fi beside wired, a VPN), the status bar
says which one was used. If none is found, the box is left empty rather than
guessed. Edit it if needed. Any CIDR from `/8` to `/32` is accepted; a network
larger than a **`/22`** (1,022 hosts) is narrowed to the `/22` containing this
PC, and the activity log says so.

The tool ping-sweeps the range to warm the ARP cache, then lists every MAC that
matches a Yealink OUI (IP, MAC, and hostname where DNS resolves).

> **Same network segment only.** Discovery reads this PC's ARP table, so phones
> on a separate voice VLAN or another routed subnet can't be seen from here,
> even if the subnet box covers them. If no phones are found, run the tool from
> a PC on the phones' VLAN or switch port.

Yealink OUIs recognised: `24:9A:D8`, `44:DB:D2`, `80:5E:0C`, `80:5E:C0`,
`C4:FC:22`, `EC:1D:A9`, `00:15:65`, `64:4F:56`, `34:97:D7`, `B0:61:A9`,
`F0:16:53`.

**Each phone's model straight away, with no login.** Discovery also reads each
phone's web page title, so the **Model** column fills in (T57W, T46U, W60B...)
before anyone types a password: enough to match the rows against the per-phone
passwords in the 3CX admin console. Older firmware that hides the title behind a
script redirect (a T40P, for one) is followed one hop to its login page. Newer
script-driven pages show no model until logged in.

*Reg / Notes* says when a phone's web UI does not answer, refuses this PC, or has
**locked its web login** after failed attempts (Yealink serves a 403 page saying so,
with the wait in minutes). A locked phone gets **no login attempt at all** until it
clears, even with a password typed, because each attempt only extends the lock. Any
HTTP answer counts as a working web UI: phones answering 401 (Basic auth) used to be
reported as "no HTTP response" and were never logged in to.

**Logging in: type each phone's password into its row.** The Yealink grid has
editable **User** (pre-filled `admin`) and **Password** columns, tinted yellow.

1. **Find phones** (Yealink tab) scans the LAN *without logging in to anything*
   and puts the cursor in the first empty Password cell. (Scan LAN finds them too.)
2. Type each phone's web password into its row, or paste a whole column: click the
   first Password cell and press **Ctrl+V**, and the passwords fill downwards in
   the grid's order. Tab-separated lines fill User and Password together, e.g.
   from a spreadsheet.
3. Click **Log in to N phone(s)**. The count follows your typing. It logs in to the
   listed phones only: there is no rescan, and nothing else is re-run.

Once logged in, the tool reads each phone's **Model, Firmware, configured SIP
Server, and registration status** into the grid. This is the fast way to spot
phones still pointed at a **dead old-office SBC or private IP** after an office
move: if the SIP Server column shows a `192.168.x` / `10.x` address that no
longer exists on the new LAN, that phone will show "No Service".

The **Reg** column reports registration state, e.g. `Registered (2)`,
`Register Failed / Registering (1)`, `Unregistered / Disabled (0)`, or a literal
string such as `Register Failed` when the firmware returns words instead of
codes. Several endpoints and field-name variants are tried, since Yealink's web
API differs across models and firmware.

- **A phone left blank gets no login attempt at all**, and a password is only ever
  tried on the phone it was typed against (matched by MAC). That matters: every
  wrong login counts towards a Yealink's web lock-out. Nothing is guessed; there
  is no `admin:admin` fallback.
- Passwords are masked (*Show passwords* reveals them).
- **Log in to phones on Scan LAN / Run All** (checkbox) uses the same passwords on
  every later scan for as long as the tool stays open. Typing a password ticks it.
  **Clear** keeps the passwords; the next scan re-attaches them by MAC.
- Passwords are held **for this session only**, keyed by MAC. They are never
  written to disk, the activity log, an export, the clipboard copy or the report,
  and they are gone when the tool closes.

(Earlier versions had a free-text box of `user:pass` lines that were "tried" on
every phone, then a pop-up. Both are gone. One password per phone, typed against
that phone, is quicker and never risks locking out the wrong one.)

Each phone is capped at a **20-second budget** so a slow or unresponsive web UI can
never stall the scan. Passwords are sent URL-encoded, so `&`, `+`, `%`, `#` and `=`
are safe. If a phone's web UI only answers over plain HTTP and it uses the older
login, the log notes that its password crossed the LAN unencrypted. The newer T5x
login encrypts the password either way.

**Open phone web page** (button, double-click a phone's row, or right-click it):
opens that phone's web UI in the default browser, over whichever of HTTPS or HTTP
answered during the scan. Expect the browser's certificate warning: phones use
self-signed certificates. Right-click also copies the IP or MAC.

In a **ScreenConnect Backstage** session (detected as running as SYSTEM, or launched
from the Backstage shell) there is no default browser, so it opens
`C:\temp\Palemoon-Portable.exe` instead. The same file is the fallback when no
browser is registered. Because Backstage runs as SYSTEM and ordinary users can
usually replace files in `C:\temp`, a copy not signed by Pale Moon's publisher is
only run after you confirm it, once per exact file (by hash). The address handed to
the browser is built from the phone's IPv4 address alone.

**Columns.** User and Password come straight after Model, then *Reg / Notes*, *SIP
Server* and *Provisions from*, which are visible at the default window size. VQ,
Firmware and Hostname follow. IP, MAC, Model, Firmware and Hostname are sized to
what they hold (never cut off; capped so one long value cannot take the screen).
The notes columns share the rest, and when the window is too narrow the grid
scrolls sideways with the IP column frozen. Maximise the window to see every
column at once.

**Save raw probe data** (checkbox): writes every raw response to
`%TEMP%\3CX-Checker-probe_<timestamp>.txt` and logs the path in the activity log.
That covers the phones' web pages **and** the full reply of every SIP responder the
SBC sweep finds, and it works whether or not the phones are probed. Use it when a
column comes back empty — the file shows the exact field names that
model/firmware uses, so the parser can be extended to match it. Provisioning
secrets are **redacted** on the way into the file: a provisioning link keeps its
host but loses its path, and any provisioning user name or password is blanked.
The file is safe to send.

**Provisions from** (Yealink grid column): for every phone the probe logs in to,
the **host** of its Auto Provision URL. That's the 3CX instance it pulls its
config from at every reboot or provisioning cycle. If that isn't the PBX in the
FQDN box, or it's a LAN address (an old SBC or on-site PBX), the cell turns
**red** and the log warns. Such a phone works today and **reverts at its next
reboot**, and fixing it by hand won't stick until its Auto Provision URL points
at this site's PBX. Found on a real site: a W60B DECT base still provisioned from
an older 3CX instance, so each reboot re-applied a retired SBC and both handsets
lost service. With the FQDN box empty, phones that provision from more than one
PBX are called out instead. Only the host is ever kept, shown, logged or
exported. The link's path is a secret that hands out the device's config,
including its SIP credentials. Read on T5x phones through the same web API as
the SIP server; best-effort on older models such as the W60B.

> The web-UI probe is **best-effort**. **Model** is read from the page title and
> works without credentials. **SIP Server / Reg** need a successful login. On
> other models a failure reads *"login failed ... a wrong password, or a web login
> this tool does not handle"*, because the probe cannot tell those apart.

#### T5x phones (T54W and family): the JSON web API

Current T5x firmware (T54W 96.87.0.22 on a real site) has no `/servlet` pages. Its
web page is an app that talks to a JSON API, with the password **RSA-encrypted in
the browser**. The tool now speaks that API, built from the phone's own web-app code
(saved from a real T54W), for any model whose page title reads T5x:

1. `POST /api/common/info` fetches the phone's RSA public key.
2. The password is encrypted exactly as the web page does it: PKCS#1 v1.5, which
   .NET's built-in RSA matches. This was cross-checked against Node.js's
   independent RSA, 96 of 96 round trips including a Unicode password.
3. `POST /api/auth/login`, then **named settings only** through
   `/api/inner/readconfig`: SIP server, outbound proxy and the VQ switches, never
   the whole configuration. Then `/api/account/status` for registration, and the
   RTP status for last-call quality.
4. **It always logs out.** The phone allows *one* web session at a time: a second
   login is refused with "the user is busy". Leaving a session open would lock a
   technician's browser out.

It stops at the first refusal that another password cannot fix, so it never makes a
lock worse:

| The phone says | The row says |
|---|---|
| wrong password | *password rejected by the phone* |
| login **locked** (too many failures) | *LOCKED … for N s. Wait before trying again.* It tries no further passwords on that phone. |
| someone is logged in | *someone is logged in to its web page from <IP>*. The tool does not push them out. |
| no login key at all | *uses a newer web login than this tool knows*, which says nothing about the password |
| logged in, SIP server not in the reply | says so, and asks for the raw capture |

Read-only: no write endpoint is ever called. The raw capture records each reply,
but **never the password or its encrypted form**.

Honest limit: built from the phone's own code and tested against a mock that
follows it (a real RSA key, one-session login, lock and busy replies, CSRF check),
**but not yet against a real phone**. The login page's code was in the save; the
status pages' code was not (the app loads them on demand). So registration and
RTP status are parsed best-effort. The first site run with *Save raw probe data*
ticked settles it. The probe never hangs (20-second
> per-phone budget) and never guesses: it only reports a registration state it
> actually read. Verify anything important on the phone's own screen
> (**OK/Menu → Status**) or in the 3CX console.

#### Voice-quality (VQ-RTCPXR) readiness

Yealink phones can report **real per-call quality measured by their own DSP** —
MOS-LQ, MOS-CQ, jitter and packet loss — using RFC 6035 (VQ-RTCPXR). That is the one
thing the Media tab cannot measure itself, because nothing answers on the RTP range.
It is off by default.

Tick **Also read voice-quality (VQ-RTCPXR) readiness** (it needs the web-UI probe). For
each phone it reads, in the same logged-in session and **without changing anything**:

| Reads | Why it matters |
|---|---|
| **Outbound proxy** on/off | **Decisive.** With an outbound proxy enabled, Yealink sends VQ reports to the proxy — the PBX — instead of any collector, and this cannot be changed. So "outbound proxy ON" means a VQ collector could never receive that phone's reports as configured. |
| **custom.protect** | Off means anything changed on the phone's web UI is overwritten at the next 3CX provisioning cycle (about 24 h). |
| Session report / show on web / collector | Whether reporting is already on, and where it would go. |
| Last call's MOS-LQ / MOS-CQ / jitter / loss | Only if the phone displays them (see *Turning it on*). |

A site-level line in the log sums it up, e.g. *"outbound proxy is ON on 9 of 9
phone(s) — a VQ collector would never receive their reports"*. The column turns amber
for a phone where the collector route is blocked.

> **Best-effort until confirmed on a real phone.** Yealink does not document which web
> pages carry these settings, so the tool tries a short list of candidate pages. They
> are harmless GETs, sent only after a login has actually worked (a wrong password
> costs no extra requests), inside their own time budget. Anything not found is
> reported as **unknown**, never as "off" — a setting missing from a page is an
> absence of evidence, not a finding. Tick **Save raw probe data** on the first site
> visit and send the capture back: that turns the candidates into confirmed paths.

**Turning it on.** The tool never writes to a phone — a web-UI change would be wiped
at the next provisioning cycle anyway. **Copy 3CX template lines for VQ** copies three
lines for the site's *copied* 3CX phone template (Admin → Advanced → Templates —
not the base template, which 3CX overwrites). They make each phone show its last
call's quality on its own web page (Status → RTP Status) and LCD
(Menu → Status → More → RTP). Deliberately left out: `voice.rtcp_xr.enable`
(phone-to-phone reporting, not needed, and older Yealink guides say changing it
reboots the phone) and any collector address (3CX advises against hard-coding IPs in
templates, and no collector exists yet).

**Which phones.** The VQ-RTCPXR feature is on every current Yealink — T4S, T4U, T5,
T3x, T7x, T88 — with parameter names unchanged since firmware V73, and no licence
needed. The template lines therefore work on all of them. The readiness *probe* uses
the same classic web endpoints as the rest of this tab, so it works on the T4S family
including the T41S, and **not** on newer single-page-app firmware such as the T57W.

> **3CX already measures real calls.** 3CX v20's **Monitor Connection Quality** records
> per-leg loss, jitter, round-trip time and a score from real calls — switch it on for
> the site's users (up to 7 days at a time) and read it in call history or the call
> log report. For "how have calls been this week" that is the right tool. VQ-RTCPXR
> adds the phone's own view, calls whose audio bypasses the PBX (which 3CX cannot
> measure), and an answer on site during a visit.

### Local Listeners tab
Shows anything listening locally on TCP 5001/5060/5061/5090 and UDP 5060/5090
(address, port, state, PID, process). UDP matters: the 3CX SBC listens on **UDP**
5060 only, so a TCP-only view reports a running SBC as "nothing listening".
Process names for other users' processes may be blank unless the tool is run
elevated.

### Network tab
Runs automatically on every **Scan LAN** / **Run All** (no admin needed). It
identifies which device is your **default gateway** and **DHCP server**, resolves
its MAC, and checks the vendor. If a **Yealink phone** is filling either role, the
row is flagged red — a phone that's routing/serving DHCP can add a hidden
NAT layer that breaks provisioning, and it's cross-referenced against the
discovered phones so you know exactly which one.

Not to be confused with a **3CX Router Phone**: that is a phone running the 3CX
SBC for the other phones, which is a normal role, and the SIP / SBC tab identifies
it. This tab is about a phone routing the LAN itself, which is a fault.

### SIP / SBC tab
**Scan LAN for a 3CX SBC** on the Yealink tab is **ticked by default** (it adds
about 15-20 s on a /24; untick it to skip). With it on, **Scan LAN** and **Run
All** look for the site's SBC or Router Phone. The tool fires a **SIP OPTIONS** packet at every live host in the
ARP cache, then identifies whatever answered — plus any Raspberry Pi in the ARP
table even if it stayed silent.

Why it matters: a cloud-hosted 3CX with **no on-site SBC** means the desk phones
must reach the cloud directly (via **RPS** or a direct provisioning URL). If the
sweep finds **no** local SBC, that's your confirmation one is missing — a common
cause of a whole site losing service after a move.

#### How it decides

Rather than a bare "3CX (SBC or PBX)", each candidate gets a verdict with its
reasons attached. The signals, strongest first:

| Signal | What it tells you |
|---|---|
| **Port profile** | The real discriminator. A standalone SBC binds **5060 only** — it has no web endpoint at all, and it *dials out* to the PBX on 5090 rather than listening on it. A PBX has 5060 + 5061 + 443/5001 + 5090. So "answers SIP as 3CX and has nothing on 443/5001/5061/5090" is a strong SBC call. |
| **MAC OUI** | All eight registered Raspberry Pi IEEE assignments. Two further Pi blocks (`F040AF9…`, `8C1F6434A…`) are longer than 24 bits and are matched at full length — truncating them to six characters would false-positive on the fifteen unrelated vendors sharing `F040AF`, and the ~2,900 sharing `8C1F64`. |
| **SSH banner** | Read from TCP 22 with **nothing sent** — the server volunteers its identification string before the client speaks, so this never lands in the device's auth log as a failed login. Names the OS outright. |
| **Reverse DNS** | A soft hint only. There is no documented hostname convention: 3CX no longer ships a Pi image, so whoever flashed the card chose the name. |

Verdicts read `very likely the local SBC` / `likely` / `possible` / `unlikely`,
or `a Raspberry Pi, but nothing indicates it is the SBC`. A host that is already
a discovered phone is excluded outright — phones answer SIP OPTIONS too, and that
alone never made one an SBC.

> **One honest caveat on the 3CX signature.** 3CX sends no User-Agent, so it is
> matched on its header signature (`Supported: replaces, timer`, or
> `Allow-Events: …line-seize`). The string `line-seize` does not appear anywhere
> in the SBC binary — so a reply carrying it was most likely generated by the
> **PBX** and relayed through the tunnel. That still tells you the tunnel is up,
> but it describes the PBX, not the SBC. The tool records which signature matched
> and says so on the row.
>
> For reference, the **PBX's own** reply to OPTIONS does carry it
> (`Allow-Events: message-summary, dialog, call-info, line-seize`). So with **Save
> raw probe data** ticked, one capture at a site settles the question: if the SBC's
> reply carries `line-seize`, the SBC is relaying the PBX's answer through the
> tunnel; if it doesn't, the SBC is answering for itself.

#### Platform

A **Platform** column names the host outright — `Raspberry Pi (Linux)`, `Linux`,
`Windows`, `network appliance`, `Yealink phone` or `unknown` — rather than leaving
you to infer it from an OS string, and the Why column states what the call was
based on. This matters because 3CX supports the SBC on three platforms and they
are not equivalent:

| Platform | Identified by | SSH features |
|---|---|---|
| **Raspberry Pi** | registered Pi MAC (strongest), or a Raspbian SSH banner | Yes |
| **Linux** (Debian ISO SBC) | Debian/Ubuntu SSH banner | Yes |
| **Windows** | Windows SSH banner if present, otherwise **445/3389/135 answering**, otherwise reply TTL ~128 | **No** — see below |

The Windows case needed its own detection: **the 3CX SBC on Windows runs no SSH
server**, so the banner grab that names every other platform returns nothing for
exactly the one that most needs identifying. Two fallbacks cover it — the Windows
service ports, and an ICMP TTL fingerprint (initial TTL is 64 on Linux/Unix, 128 on
Windows, 255 on much network gear).

> The TTL fingerprint is only applied to hosts that came out of the **ARP table**,
> so they are on-link and the observed TTL is effectively the initial one. It is not
> trustworthy over distance — measured, `8.8.8.8` at twelve hops returns TTL 116,
> which this would read as Windows. That is why it is never used off the LAN.

When a candidate is a Windows host the row says so plainly, including that the
terminal and canned commands do not apply to it and it should be managed from the
console or RDP instead.

#### A 3CX Router Phone

A **Router Phone** is a desk phone doing an SBC's job: it carries other phones'
traffic to the PBX. The SIP sweep can tell one apart from an ordinary phone.
Ordinary Yealinks answer SIP OPTIONS *as themselves* (a Yealink User-Agent). A
Yealink that answers with the **PBX's 3CX signature and no Yealink User-Agent** is
passing SIP on to the PBX. Such a host gets a blue row: *"likely a 3CX Router Phone
(a phone doing the SBC's job)"*. If the reply carried `line-seize`, which only the
PBX generates, its own link to the PBX was up at that moment.

**Confirmed, and which PBX it serves.** A real Router Phone (a T57W) relays the
probe through its tunnel, and its reply carries
`Record-Route: <sip:3CXSBC@<its IP>:5060;...;tnlid=sbc.<id>>`. That is the 3CX SBC
code naming itself; the PBX answering for itself never adds it. When it is there
the row says *"3CX Router Phone (confirmed)"*, or *"the local 3CX SBC (confirmed)"*
for a Pi or Windows box. The reply's `To:` header also names **the PBX the tunnel
leads to**, shown as *"It forwards to the PBX ..."*. If that is not the PBX in the
FQDN box, the row turns **red** and the log warns. Every phone registering through
that SBC is reaching a different PBX: for example, an SBC still paired with an old
3CX instance.

Found on a real site: the reception phone, which the customer knew as the Router
Phone, answered this way, and the tool used to dismiss it as "just a phone". The
site's 3CX phone list confirmed it: all nine devices, including a W70B DECT base,
were listed *"via SBC Yealink T54W (10)"*, the reception phone. Two
follow-ups the row spells out:

- **Which phones go through it?** Log in to the phones (Yealink tab): each phone's SIP server
  shows whether it uses the Router Phone, a separate SBC, or the PBX directly.
- **It is a single point of failure** for every phone that does: unplugging or
  rebooting it takes them all off the PBX.

#### A phone acting as the gateway

If a **Yealink MAC is also the default gateway or DHCP server**, that host gets a
red row on this tab reading *"NOT an SBC — a phone is acting as the Default
Gateway"*. A phone should never be routing or handing out DHCP; it explains erratic
SIP and one-way audio, and it wants fixing before anything else on this tab is
worth reading.

The Network tab has always flagged this, but it is surfaced here too because this is
the tab you open when SIP is misbehaving. Such a host is pulled into the candidate
list deliberately, even though the verdict is that it is emphatically not an SBC.

#### When the tool runs on the SBC itself

The LAN sweep can never find an SBC on the machine the tool is running on — a
computer is never in its own ARP table, so it is never sent a SIP OPTIONS. This was
found at a real site: the tool ran on the Windows SBC box, reported no SBC, and the
SBC was sitting right there.

So on every run the tool first checks **this PC** for the `3CXSBC` service. On an
ordinary PC that is one service lookup and nothing else. When it is there, the SIP /
SBC tab gets a **this PC** row, green or red on its own health, built from:

| Check | How |
|---|---|
| Service | `3CXSBC` running / stopped, and its start type |
| Listening for the phones | who holds UDP 5060 — flagged if it is anything other than `3cxsbc` (a softphone, say) |
| Which PBX it is paired with | `TunnelAddr` / `TunnelPort` from `%ProgramData%\3CXSBC\3cxsbc.conf`, with `3cxsbc.conf.local` overrides. **`Password` and `ProvLink` are never read into the tool**, so they cannot reach the log or the export. |
| **Tunnel state** | every TCP connection the `3cxsbc` process holds, **in any state**: established to the tunnel port = up; `SynSent` = trying and failing; nothing at all = not connected. Checking only "established" cannot tell those apart. **But "nothing at all" is not taken as proof on its own.** On the real site there was no TCP socket in two checks hours apart, while the PBX recorded the tunnel Up and the SBC, which logs every failed attempt, had logged nothing since it started. The tunnel also has a UDP channel (named in the SBC's own log), and Windows cannot show where a UDP socket is talking to. So when something contradicts the empty TCP view, the row turns **amber: "tunnel NOT CONFIRMED"**, says what contradicts it, and points at the PBX console or a test call. The contradictions are: a quiet log for 10+ minutes since the start, a SIP reply carrying the PBX-only `line-seize`, or an established connection to the PBX from another process. With no contradiction it stays **red: "NO tunnel"**. |
| Can it reach the PBX | a TCP connect to `TunnelAddr:TunnelPort` from this PC — so a down tunnel is split into "network blocked" versus "reachable, so look at the SBC's pairing" |
| Does it answer SIP | one OPTIONS to its own LAN address; with **Save raw** ticked the full reply is captured |
| Its log | `%ProgramData%\3CXSBC\Logs\3cxsbc.log`: version, when the current run started, restarts in 24 h, errors and **failed DNS lookups for the PBX** in 7 days. "Too long inactivity" bridge failures are **not** tunnel outages: on a real site, none of them coincided with an outage the PBX recorded. The PBX event log (event 4102) is the authoritative record of the tunnel going down; import it on the Security tab for the outages and their causes. |

Two things it deliberately does **not** do:

- **No TLS handshake on the tunnel port.** Tested against two PBXes, including one
  whose tunnel is known to work, the tunnel refuses a plain TLS ClientHello — so
  such a check would raise a false alarm on every healthy site.
- **No reading silence as success.** At the default log level (`ERR`) the SBC logs
  failures but not successful connections. The row says so, and relies on the socket
  table instead.

It also catches **testing the wrong PBX**. If the FQDN box names a different PBX from
the one this PC's SBC is paired with, the 3CX tab's summary *leads* with a warning that
every result on it is for a different PBX — which is exactly what happened on that
site run, where the box still held the default. It is also flagged **before** a run:
when this PC's SBC is paired with a different PBX from the one in the box, the box
turns **amber** (with a tooltip saying why) and a bold **"Use <pbx> (this PC's SBC)"**
link appears beside the subnet box. One click fills the box. Starting *Check 3CX*,
*Run All* or *Media Test* in that state asks once: test the SBC's PBX instead, test
the name as typed (remembered, so it does not ask again), or cancel. A PBX typed as
its IP or URL counts as the same PBX. The box is never changed without that click
or that answer.

The tunnel state is one snapshot: the SBC retries every `ReconnectInterval` (30 s by
default), and the PBX admin console remains the authoritative view.

#### SSH to the SBC

Click a row and the SSH strip above the grid targets it — or **type an IP address
or host name into the Target box**. That matters because a grid row is not always
there: an SBC whose service has **crashed stops answering SIP** and drops off the
grid, which is exactly when you need SSH to restart it, and an SBC on another VLAN is
never in this PC's ARP table. (A Raspberry Pi stays listed either way, via its MAC.)
Re-running a scan auto-selects the first row, but never overwrites a target you
typed; clicking a row always does.

The target and the SSH user are both checked before use — letters, digits, dots
and hyphens only (plus underscore for the user), and never a leading hyphen. They
are written into the terminal launcher and into plink's arguments, so anything a
shell would act on (`&`, `|`, `;`, spaces, quotes) could otherwise run a command,
and a leading hyphen would be read as an ssh option. An invalid target turns the box
pink and disables the buttons.

- **Open SSH terminal** always works. It uses `ssh.exe`, which ships with Windows
  10 1803+, and falls back to `putty.exe` only if that happens to be installed.
  Nothing is downloaded and the tool never sees the password — you type it into
  the real client. Launched via a small self-deleting `.cmd` so the window
  survives the session ending, and so a client path containing a space cannot
  break the quoting.
- **Copy** puts the selected command on the clipboard, for pasting into that
  terminal. This path can never fail at runtime and needs nothing installed.
- **Run** captures the output into the pane below, but needs **plink** (PuTTY
  0.77+). Windows OpenSSH reads the password from the console rather than stdin
  by design, so it cannot be driven non-interactively with one — that is a
  property of OpenSSH, not a limitation of this tool. If plink is absent the
  button is disabled and the strip says so.

There is **no default SSH user**. 3CX no longer publishes a Raspberry Pi image —
you flash stock Raspberry Pi OS and create your own account — and Raspberry Pi OS
itself dropped the `pi`/`raspberry` default in April 2022. The field is seeded
with `pi` as a common habit, not as a fact.

#### The baked-in commands

Every command was verified against 3CX's own published package and installer
rather than assumed. Three things worth knowing:

- **The SBC unit is `3cxsbc`, all lowercase.** `systemctl status 3CX*` is the PBX
  idiom and does **not** match it, because unit names are case-sensitive.
- **`3CXStopServices` / `3CXStartServices` do not exist on an SBC.** They ship
  only in the `3cxpbx` package, which is amd64-only — so on a Raspberry Pi SBC
  they are `command not found` twice over. The SBC equivalent is
  `sudo systemctl restart 3cxsbc`.
- **`sudo` may prompt.** Raspberry Pi OS 6.2 (Trixie) disables passwordless sudo
  on new installs, and the current 3CX SBC guide points at Trixie. Read-only
  probes therefore use `sudo -n` so they fail instantly with a clear message
  instead of hanging on a prompt a captured session can never answer; the real
  commands feed the password to `sudo -S` over stdin.

Read-only commands cover service state, tunnel state, the paired PBX, and both
log sinks. Restart / stop / start / re-provision are marked in red and confirm
first, naming the consequence: **restarting the SBC drops every call in progress
at that site.**

The config read is a targeted `grep`, not a `cat`: `/etc/3cxsbc.conf` holds the
tunnel `Password` and a `ProvLink` that embeds the auth key, and this output goes
into the log and the CSV export.

> **Credentials.** The SSH password is held for the session only. For captured
> commands it is written to a temporary file under `%LOCALAPPDATA%` with
> inheritance stripped and a single owner-only ACE, deleted immediately after the
> command — measured on a test machine, the same file left at default permissions
> carries six ACEs including another account with read access. plink is given
> `-pwfile` rather than `-pw`, so the password never appears in the process list,
> and it is never written to a report or export. The device host key is accepted
> automatically on first connect.

### Security tab

Read-only, like the rest of the tool: it changes nothing on this PC, the PBX or the
router. Three buttons, three sources, and each reports only what it can see.

**The one thing none of them can see is the router's port forwards.** From inside
the LAN, testing the site's own public IP depends on the router's hairpin NAT, so
it would report the router's behaviour rather than what the internet can reach.
The tool does not attempt it. Where a finding depends on the router, it says so.

#### Check this PC's SBC

3CX only. It looks at what matters when **this PC runs the 3CX SBC**, plus
anything on this PC holding a SIP or 3CX port. General Windows hygiene (RDP,
SMB, clear-text services, firewall defaults) is not checked: it says nothing about
the 3CX setup, and on a PC that is not the SBC it only described that PC.

- **No SBC here:** it says so plainly ("No 3CX SBC runs on this PC ... nothing to
  report about the 3CX setup"), so a clean result on a technician's laptop is not
  read as "the SBC is fine". A Raspberry Pi SBC or a Router Phone cannot be checked
  from here; see the SIP / SBC tab.
- **The 3CX / SIP ports** (TCP/UDP 5060, TCP 5061, TCP/UDP 5090, TCP 5001) and any
  port a 3CX process holds, with its process and **what Windows Firewall does with
  it** on the network profile actually in use: allowed from any address, from the
  LAN only, blocked, or no rule at all, naming the rule that lets it in.
- Something other than the SBC holding a SIP port (a softphone, say) is reported:
  on an SBC box it would compete with the SBC for the phones' traffic.
- **When this PC runs the 3CX SBC:** who can read `3cxsbc.conf` (it holds the tunnel
  password and provisioning key). That is **HIGH** on a machine other people log on
  to, such as a terminal server. It also searches ProgramData, the temp folders and
  users' desktops, downloads and documents for **stray copies** of the config: a
  real site had one in a support tool's temp folder. Contents never reach a report:
  each file is only checked for whether it *has* a `Password=`/`ProvLink=` line, so
  a `3cxsbc.conf.local` that is all comments is reported as holding no password
  (info) rather than as a leak.
- The SBC's media ports (from FirstRtpPort, UDP 20000 on the real site) are reported
  as one range with its SIP port. If Windows Firewall is **off** on the SBC's
  network, that is a REVIEW finding about the SBC's ports.
- A reminder that **an SBC needs no inbound port from the internet.** It dials out
  to the PBX (TCP 5090), and only the LAN's phones talk to it, so any router
  forward to it is unnecessary exposure.

Honest limits: no admin rights are needed, but without them some process paths are
unknown. A rule that names a program is then matched on the file name only, and
marked `(?)`. Without admin rights, Windows' bulk firewall reads also come back
partial ("Access is denied" for 187 of 481 rules on the dev PC). The gaps are
fetched rule by rule, and a rule that still cannot be read is **left out and
counted, never assumed to be "Any"**. Rules belonging to a Store app never count
for a desktop service.

#### Import 3CX event log

Export the PBX's event log from the 3CX admin console as CSV and open it here. Only
extracted fields reach the tool's output. A 3CX event can carry a whole INVITE,
including digest responses and SRTP keys, and none of that is shown or exported.

| Event | What the tool makes of it |
|---|---|
| **4102** SBC Down / Up | **The tunnel history** (the PBX's own record): every outage with its duration, and an outage still open at the end of the export flagged HIGH |
| 30051 unidentified incoming call | Scanner / toll-fraud probes: count, peak per day, busiest sources and /24 ranges, and the numbers they were trying to reach (prefix variants such as `+44`, `0044` and `01144` grouped) |
| 12291 rejected by "Block WAN requests" | Grouped per attacker and **extension login presented**. The log cannot say whether the password was right; a blacklisting minutes later suggests guessing. |
| 12290 IP blacklisted | SIP versus web-client lockouts and their lengths (900 s web, 86400 s SIP on the real site) |
| 30052, 12294 | Calls with no outbound rule, trunk failures (listed, not security) |

**Why each outage happened.** Event 4102 records *when* the tunnel dropped, not why.
When you import on the SBC machine itself, three more sources give the reason:

- the SBC's log (`3cxsbc.log`)
- its supervisor log (`3cxsbc.log.mon`, which records *why* the SBC stopped: the
  main log only ever says "console control handler")
- Windows' own restart events (System log 1074 / 6008 / 41, readable without admin
  rights; 1074 names the process, e.g. `MoUsoCoreWorker.exe` = Windows Update)

Each outage is then labelled:

| Cause | Evidence |
|---|---|
| this PC restarting | the supervisor saw "console control handler" **and** "service manager request" in the same instant, and/or Windows logged a restart |
| service stopped | "service manager request" alone: a person, a script or an installer |
| DNS | failed DNS lookups for the PBX on this PC during the outage. The SBC exits when it cannot resolve the PBX at start-up (logged, misleadingly, as "Invalid bridge's configuration") and Windows restarts it, so a long DNS failure appears as a restart loop that ends on its own when lookups work again. The log cannot tell this PC's DNS from the site's internet, and the finding says so: if phones on another path stayed registered, it was this PC. |
| could not connect | timeouts / refusals with the SBC running |
| (blank) | nothing in the SBC's logs: never guessed |

On the real site, the four outages in a month turned out to be three restarts of
the SBC's PC (07:36, 20:31, 20:30) and one two-hour DNS failure on that PC that the
SBC recovered from by itself. The site's 3CX phone list later showed that **no phone
used that SBC at all**: every one went through a Router Phone. That is why the tool
no longer calls the DNS failure a site-wide internet outage. Time-of-day patterns are only reported between
outages with **the same cause**: without the SBC's logs, the 07:36 restart and the
07:42 DNS failure 13 days later looked like a pattern, and they are not one. When
the SBC is a different machine, the tool says it cannot tell the cause from here.

#### Paste 3CX IP blacklist

Copy the rows from the PBX's IP blacklist page and paste them in. The paste is
parsed as tab-separated with the header row, or pattern-matched line by line if
the columns were lost. The tool compares the list with **the site's real public IP**.
It only ever takes that IP from something that measured or recorded it: the Check
3CX run, or the SBC's public address in event 4102. It never guesses.

- The site's own IP **blacklisted**: HIGH. Phones cannot reach the PBX from it.
- The site's IP **not allow-listed**: REVIEW. With phones on STUN, one phone with a
  wrong password can get the whole office blacklisted for 24 hours. Only
  allow-list a static IP. Through an SBC, how 3CX counts failed logins has not been
  verified, and the finding says so.
- **Allow entries that are not the site's IP**: REVIEW. An allow-listed address is
  exempt from brute-force blocking, so an address nobody uses any more (an old ISP
  address since reassigned, or wherever the PBX was set up from, which is what
  "Created by PBX Express" entries usually are) is a standing exemption for a
  stranger. On one real site, an entry named after the site's old internet connection was allow-listed until 2045, but the
  site's IP had changed.
- Entries covering more than 256 addresses, and blocked addresses that also appear
  in the event log trying to call out with an extension's login.

## Reporting

Two exports, for two different jobs:

| | **Export CSV** | **Export report** (JSON) |
|---|---|---|
| For | eyeballing in Excel | the report generator, and a lasting record |
| Shape | every row flattened into `Section, Item, Detail1-4` | structured, one object per section |
| Verdicts | none (the summaries and site health are only on screen) | site health (level, subscores, actions), the 3CX and media summaries, the local SBC verdict, security findings |
| Numbers | as text (`"p50 79.12 ms"`) | as numbers (loss, jitter, round trip, MOS, soak) |
| Context | none | site name, PC, tool version, PBX, public IP, the last run's options |
| When | not recorded | **every section says when it was measured**, or `"measured": false`. One export can combine several runs, and it says so. |

### Export report

The **Site name** box beside the FQDN goes into the report and the file name. It
fills itself from the 3CX instance name when there is one
(`examplepbx.3cx.us` -> **EXAMPLEPBX**, or from the PBX this PC's SBC is paired
with), and never guesses from a custom domain. Once you type in it, your text
stays.

**Export report** then does three things:

1. Saves `Output\3CX-Report_<SITE>_<timestamp>.json` next to the script, or
   `Documents\3CX-Checker\Output` if that folder can't be written. It is UTF-8
   with a BOM, because Windows PowerShell 5.1 reads a BOM-less file as ANSI.
2. Copies it to the clipboard between `--- BEGIN JSON OUTPUT ---` and
   `--- END JSON OUTPUT ---`. The
   markers let the generator tell a truncated paste from a broken one.
3. Opens it in Notepad.

Never in it: the SSH password, phone passwords, the SBC's tunnel password or provisioning link, or raw event-log text (a 3CX event
can carry digest responses and SRTP keys; only extracted fields are exported).
The (private) tests check this against a real site's event log: none of its 17 SRTP keys
or its digest responses appear.

Schema `3cx-checker-report`, version `1.0`. Top-level keys: `tool`,
`generatedUtc`, `generatedLocal`, `timeZone`, `site`, `lastRunOptions`,
`connectivity`, `media` (`health`, `metrics`, `checks`), `phones.items`, `sbc`
(`thisPc`, `lan`), `network` (`roles`, `listeners`), `security` (`findings`,
`thisPc.posture`, `eventLog.analysis` with every outage and its cause,
`blacklist.entries`), and `log`. Dates are ISO 8601; PowerShell 5.1's
`\/Date(...)\/` form is never written.

### Generate-3cxReport.ps1

The companion report generator (Windows PowerShell 5.1, WinForms). Paste the
export (markers or not), or **Browse JSON...**, check the site name, then click
**Generate report**. It writes a self-contained HTML report to its own `Output`
folder and offers to open it. It refuses anything that is not a 3CX Checker
report, and names a truncated paste instead of showing a bare parse error.

The report contains:

- **At a glance:** call-path quality, PBX connectivity, phones, the SBC or Router
  Phone, and security counts.
- **What to do:** the health actions plus every HIGH / REVIEW security finding.
- **One section per area:** each says when it was measured, or "not run in this
  export". Times are in the site's time zone, taken from the export.
- **A hardening checklist.** It lists established measures that help whatever
  attackers do next, each with this site's own evidence when the export has some:
  - carrier-level barring and a spend cap
  - outbound rules limited to real destinations
  - "Block WAN requests"
  - unguessable authentication IDs
  - 2FA on the admin console
  - a tight allow list with automatic blacklisting left on
  - no inbound port forwards
  - the SBC's tunnel password protected
  - firmware kept current
  - notifications

  **Manually blocking attacking addresses is deliberately left off:** on the real
  site each range was active for only 1 to 4 days, and 3CX's automatic blacklist
  already blocks each new one.

`-NoGui` loads the functions only, for tests.

## Buttons

- **Run All** – runs the 3CX check and the LAN scan back to back.
- **Export CSV** – saves all populated results to a CSV.
- **Export report** – the JSON report for `Generate-3cxReport.ps1`: saved to
  `Output`, copied to the clipboard, opened in Notepad (see *Reporting*).
- **Copy** – copies the results and log to the clipboard.
- **Clear** – resets the grids and log (and the Security tab).

Export CSV and Copy include the Security tab's findings (section `Security`), and
Copy also includes its detailed report.

Scans run on a background thread, so the window stays responsive; the progress
bar and activity log show what's happening.

CSV export neutralises any cell that starts with `=`, `+`, `-` or `@` (a leading
apostrophe, which Excel hides). Device-supplied text such as SIP User-Agents and
SSH banners ends up in it, and Excel would otherwise run such a cell as a formula.

## Tests

The regression suite is not included in this release: its fixtures are real event logs and captures from customer sites.
