<!-- yeet:user-friendly-title: Detect malicious network activity -->

# `poolnarc`

> **A cryptominer has to talk to a pool, and it has to lie about who it is.** poolnarc catches the second lie with a kernel fact: real kernel threads cannot open TCP sockets.

<p align="center">
  <a href="#requirements"><img src="https://img.shields.io/badge/platform-Linux-1793D1" alt="Linux: kernel 5.5+ with BTF, fentry and tp_btf"></a>
  <a href="https://yeet.cx/docs/?utm_source=github&utm_medium=readme&utm_campaign=poolnarc&utm_content=badge"><img src="https://img.shields.io/badge/built%20with-yeet%20%2B%20eBPF-8A2BE2" alt="Built with yeet, a JS runtime for eBPF"></a>
  <a href="#the-lie-that-cant-survive-app-context"><img src="https://img.shields.io/badge/hook-fentry%20%2B%20tp__btf-FF6B35" alt="Attaches fentry on tcp_sendmsg and tp_btf on inet_sock_set_state"></a>
  <a href="#what-youre-looking-at"><img src="https://img.shields.io/badge/category-cryptomining%20detection-7C3AED" alt="Cryptomining detector: pool ports plus process-name mimicry"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-GPL--2.0-3DA639" alt="GPL-2.0, declared in the BPF program"></a>
  <a href="https://discord.gg/JxVseaAVAU"><img src="https://img.shields.io/badge/chat-Discord-5865F2" alt="Discord: ask about yeet scripts"></a>
</p>

<p align="center">
  <img src="assets/poolnarc.gif" alt="poolnarc flagging a process named kworker/u4:2 that is sending Stratum traffic to a Monero pool on port 14444" width="820">
</p>

**`poolnarc` is an eBPF cryptomining scanner for Linux: it watches outbound TCP in the kernel and names the process talking to a mining pool, even when that process has renamed itself to look like a kernel thread.**

## Quick start

```sh
curl -fsSL https://yeet.cx | sh              # install yeet, once
yeet run gh:yeet-src/poolnarc -- --audit     # 60-second scan, prints a verdict
```

Cryptojacking is the rare compromise that has to phone home on a schedule. The miner needs work units from a pool and has to return shares, so it holds a Stratum connection open and moves bytes on it for as long as it is earning. That connection is the part the attacker cannot obfuscate away.

The thing you would otherwise reach for is `ps` and `ss -tnp`, and both are answering a question you did not ask. `ps` shows you a process list the malware has already edited, via `prctl(PR_SET_NAME)`. `ss` shows you established sockets but not which of those destinations are pools, and it misses anything that opens and closes between polls. A signature scanner hashes files against a database that lags whatever is being deployed this month. `poolnarc` reads the process name from the kernel at the moment bytes move, which is after the rename, so the lie is evidence rather than camouflage.

> [!TIP]
> **No agent, no signature database, no data leaving the box.** A process that reaches `tcp_sendmsg` in application context is by definition not a kernel thread, so a socket owned by something calling itself `kworker/u4:2` is a userspace process wearing a kernel thread's name. That single fact is the detector.

## Contents

**Run it** — [Get started](#get-started) · [Have an agent set it up](#have-an-agent-set-it-up) · [Reading it without a TTY](#reading-it-without-a-tty)

**Understand it** — [A 60-second primer](#a-60-second-primer-on-stratum) · [Questions this tool answers](#questions-this-tool-answers) · [The lie that can't survive app context](#the-lie-that-cant-survive-app-context) · [What you're looking at](#what-youre-looking-at) · [How it works](#how-it-works) · [What it can't see](#what-it-cant-see)

**Reference** — [Verdicts](#verdicts) · [Requirements](#requirements) · [FAQ](#faq) · [License](#license)

**Contribute** — [Building from source](#building-from-source) · [Testing across kernels](#testing-across-kernels) · [Try it without real traffic](#try-it-without-real-traffic)

## Get started

```sh
curl -fsSL https://yeet.cx | sh              # install yeet, once
yeet run gh:yeet-src/poolnarc -- --audit     # scan for 60 seconds, print a verdict
```
[Manual install guide](https://yeet.cx/docs/install/manual-installation?utm_source=github&utm_medium=readme&utm_campaign=poolnarc) | Linux only

That is the whole install. `yeet run` clones the repo into its own cache, runs `make` to compile `bin/poolnarc.bpf.o`, then starts the script; the BPF toolchain is fetched automatically, so there is no clang or bpftool to install first. `yeet-src` is a trusted source for the runtime, so the build runs without a consent prompt.

Working on the script itself instead of just running it? Clone it and build in place:

```sh
git clone https://github.com/yeet-src/poolnarc && cd poolnarc
make                     # compile bin/poolnarc.bpf.o (toolchain auto-fetched)
yeet run . --tty         # the live dashboard
```

With no script flags you land on the live dashboard, which repaints every 200ms and runs until `Ctrl-C`. `--audit` is the one you want for anything you intend to keep: it collects for a fixed window, prints a report, and exits on its own.

Script flags go **after `--`** so the runtime routes them to the script rather than consuming them itself, which is the most common first-run mistake. Flags belonging to `yeet run` itself (`--tty`, `--quiet`, `--watch`) go *before* the `--`.

| flag | default | meaning |
| --- | --- | --- |
| `--audit` | off | one-shot scan: collect, report, exit. Writes scrolling stdout instead of repainting, so unlike the dashboard it survives a pipe, a redirect, and an SSH session with no TTY |
| `--duration=<n>` | `60` | scan window in seconds, capped at 3600. A non-numeric or negative value silently falls back to 60 rather than erroring, so check your quoting |
| `--json` | off | emit the snapshot as JSON instead of text: every alert, miner and pool plus the top 20 destinations, under a stable `poolnarc_audit_version`. This is the cron and CI surface |
| `--anonymize` | off | alias process names to `proc-01` and addresses to `host-01`, consistently within a run, for pasting into a ticket without leaking internal hostnames |

```sh
R=gh:yeet-src/poolnarc
yeet run $R -- --audit --duration 90              # longer window on a quiet host
yeet run $R -- --audit --json | tee scan.json     # machine-readable
yeet run $R --tty -- --anonymize                  # dashboard, safe to screenshot
```

(From a clone, `.` replaces `gh:yeet-src/poolnarc` in any of these.)

The dashboard needs a real terminal, so don't pipe or redirect it; `--audit` is the mode that pipes. Resize and the panels reflow.

## Have an agent set it up

Paste this into Claude Code or any agent with shell access:

```
Clone https://github.com/yeet-src/poolnarc and work in it.

1. Install yeet if it isn't present: curl -fsSL https://yeet.cx | sh
2. Run `make` and confirm bin/poolnarc.bpf.o was produced.
3. Start the simulated attack, which is what gives the scanner something
   to find on a clean box:
     ./tests/simulate_attack.sh          # needs python3
   It starts a fake pool on 127.0.0.1:14444 and a process that renames
   itself to kworker/u4:2 and pumps Stratum-shaped traffic at it.
4. In a second shell, run:
     yeet run . -- --audit --duration 20
5. Confirm the report ends in "VERDICT: CRITICAL" and that the ALERTS
   section names a pid whose comm is kworker/u4:2. A CLEAN verdict at
   this step means the probe never attached, not that the box is clean.
6. Ctrl-C the simulator.

"It compiled" is not the same as "it works". A clean verdict and a probe
that never loaded produce nearly identical output, which is why steps 3
and 5 are not optional.

Trap: this needs a kernel with BTF (CONFIG_DEBUG_INFO_BTF=y). The BPF
load fails at step 4, not at step 2, so a clean `make` tells you nothing
about whether it will run. Check /sys/kernel/btf/vmlinux exists before
debugging anything else.
```

Prefer to drive it yourself? [Try it without real traffic](#try-it-without-real-traffic) is the same sequence by hand.

## A 60-second primer on Stratum

The mental model for what `poolnarc` is looking for and why that is findable at all:

**Pools speak Stratum, which is line-delimited JSON-RPC over plain TCP.** A miner connects, subscribes, authorizes with a wallet address, and then the socket stays open: the pool pushes work units down, the miner pushes accepted shares back up. It is chatty and persistent, so a miner looks like a long-lived connection moving a steady trickle rather than a burst.

**Pools publish their ports, and clients ship those defaults.** Monero's reference pools use 14444, Ethereum-family pools cluster on 2020 and 12020, NiceHash uses 3357 and 9200, and a long tail of pools use the repdigit ports (3333, 4444, 5555, 7777) more or less by convention. An attacker who wants their malware to work against public pools has to use the pool's port, which is what makes a port-based classification work at all.

**A destination port is evidence about the pool, not proof about the process.** So the port database is tiered rather than a flat list, and a hit on a merely Stratum-shaped port is reported as Stratum-class rather than as confirmed mining. Port evidence alone never reaches the top verdict.

**The second signal is the process name, and it is the load-bearing one.** Port classification tells you a connection looks like mining; `comm` mimicry tells you something is hiding. See [the lie that can't survive app context](#the-lie-that-cant-survive-app-context), which is the reason this exists as its own tool rather than a `ss` one-liner.

## Questions this tool answers

**How do I check whether a Linux server is cryptomining right now, without installing an agent on it?**
One command: `yeet run gh:yeet-src/poolnarc -- --audit`. It attaches for 60 seconds, prints a verdict, and exits. Nothing is installed on the host beyond yeet, no daemon is left behind, and nothing leaves the machine.

**Something is pegging a core and `top` shows a `kworker` eating CPU. Is that real?**
Almost certainly not, if it is also moving network bytes. Kernel threads do real work but they do not open outbound TCP connections, so a `kworker` with a socket is a userspace process that renamed itself. poolnarc flags exactly this as CRITICAL and prints the real pid next to the pool. See [the lie that can't survive app context](#the-lie-that-cant-survive-app-context).

**Is poolnarc a replacement for Wazuh, CrowdStrike, or my CWPP?**
No, and it is not trying to be. There is no rule engine, no alert routing, no retention, no fleet console, and no response actions: poolnarc cannot quarantine, kill, or block anything. It is one behavioral check, scoped to one host, that answers in 60 seconds. A runtime-security platform is what you want running continuously with history you can query afterward. poolnarc is what you run on the box you are already SSH'd into while the platform is still deciding.

**When should I use poolnarc instead of `ss`, ClamAV, or a packet capture?**
Use `ss -tnp` when you already suspect a destination and just want to confirm a socket exists. Use a signature scanner when you have a file and a rule that covers it. Use `tcpdump` when you need the bytes on the wire as evidence. Reach for poolnarc when you have none of those: no known-bad IP, no sample, no idea which process, and you want the host to tell you whether the pattern is present at all. For per-endpoint bandwidth ranking without the mining classification, [`container-traffic`](https://github.com/yeet-src/container-traffic) fits better.

**How do I scan a whole fleet for cryptojacking and alert on the hits?**
Cron `--audit --json` and alert on any `verdict` that is not `CLEAN`. The JSON carries the verdict, per-alert pid and `comm`, the pool address and port, and the top 20 destinations by bandwidth, so the alert carries its own evidence instead of a boolean. There is no built-in aggregation: poolnarc scans one host and prints, and the fan-out is yours.

**Can I gate a golden image or a CI build on this, to catch a compromised base layer?**
Yes, and `--json` exists for it. Run `--audit --duration 30 --json` in the build, parse `verdict`, fail on anything but `CLEAN`. One caveat worth building around: a scan only sees its own window, so a miner that connects on a long interval can sit one out. Lengthen `--duration` for anything gating a release.

**Does this work in containers, and will it see traffic from inside them?**
Yes. The probes attach to `tcp_sendmsg` and `tcp_cleanup_rbuf` in the host kernel, which every container shares, so container traffic is visible without a sidecar or anything installed in the image. What comes back is the host-namespace pid, not the container name, so mapping an alert to a container is a lookup you do afterward.

**Will running this on a busy production host slow it down?**
Per-connection state lives in a kernel hash map and userspace hears about a connection three times: once when attribution settles, once per 64 KiB, and once at close. A connection moving gigabytes produces a bounded trickle of events rather than one per packet, so cost scales with connection count rather than traffic volume.

**Why can't I see the miner in my logs?**
Cryptojacking malware does not write logs, and the process name your log agent reports is the name the malware picked. poolnarc reads pid and destination from the socket rather than from the process, so neither is under the malware's control. The one thing it takes at face value is `comm`, which is precisely why a spoofed `comm` is treated as a signal instead of as identity.

## The lie that can't survive app context

Every process-attribution tool in the kernel has to answer one question: which process owns this socket. Answering it at the wrong moment is what makes naive versions of this detector useless, and getting it right is what turns the same mechanism into the detection.

`inet_sock_set_state` fires from **softirq context**. Calling `bpf_get_current_comm()` there frequently returns `swapper` or a `kworker`, not because anything is spoofing but because the CPU is servicing an interrupt and whatever it was doing has nothing to do with the socket. A detector that trusted that reading would flag every busy host as full of kernel-thread miners.

So `poolnarc` treats attribution at `ESTABLISHED` as provisional. The connection is recorded with `FLAG_PID_REAL` unset, and no `OPEN` event is emitted at all. It then waits for `tcp_sendmsg` or `tcp_cleanup_rbuf`, which run in **application context**, on the thread that actually owns the socket. The first time one fires with a non-kernel `comm`, the pid and name are overwritten and the attribution locks.

Here is the inversion. A connection whose `comm` is *still* `kworker` after it has passed through `tcp_sendmsg` in application context is not a misattribution, because a real kernel thread never reaches that path owning a socket. It is a userspace process that called `prctl(PR_SET_NAME)`. The same wait that removes every false positive is what makes a surviving `kworker` a true positive, and it is why `OPEN` is deliberately withheld until attribution settles rather than emitted when the connection is established.

That is the whole trick, and it is why this is a detector rather than a port-matching script.

## What you're looking at

Audit mode is the output most people see first. It is plain scrolling text, safe to pipe:

```
════════════════════════════════════════════════════════════════
  poolnarc audit · behavioral hidden-cryptominer scan
════════════════════════════════════════════════════════════════

  Scan started: 2026-05-31T14:18:01.234Z
  Scan ended:   2026-05-31 14:19:01 UTC
  Duration:     1m 0s

── Connections observed ────────────────────────────────────────
  TCP events seen:          847
  Connections opened:       42
  Connections closed:       38
  Distinct destinations:    18
  Total bytes ↑/↓:          12MB / 38MB

── Mining pool detection ───────────────────────────────────────
  High-confidence mining ports:  1 destination(s)
  Likely Stratum ports:          0
  Crypto P2P ports (BTC/ETH):    0  (informational, not mining)
  Mining traffic ↑/↓:            1.2MB / 340KB
  Overall:                       ✗ 1 HIT

── Comm-name mimicry detection ─────────────────────────────────
  Kernel-thread name spoofing:   1 process(es)
  System-daemon name spoofing:   0
  Overall:                       ✗ MIMICRY DETECTED — see alerts below

── ALERTS ──────────────────────────────────────────────────────
  ⚠ CRITICAL · pid 8821 (kworker/u4:2)
    Talked to: 65.21.198.20:14444  (mining)
    Bytes:     ↑1.2MB / ↓340KB    Conns: 3

════════════════════════════════════════════════════════════════
VERDICT: CRITICAL — hidden cryptominer detected
  1 process(es) talking to mining pools while spoofing kernel-thread names.
════════════════════════════════════════════════════════════════
```

It reads top to bottom as a narrowing funnel: everything the host did, then the crypto-relevant subset, then the mimicry subset, then the alerts, then one verdict. Empty sections are omitted, so a clean run is short. `Top destinations by bandwidth` prints even on a clean host, which is deliberate: it is how you tell "scanned and found nothing" from "the probe never attached."

The live dashboard stacks four panels and repaints every 200ms:

```
 ▌ POOLNARC · crypto-mining traffic detector ────────────────────────────────────────────────────────
● LIVE 00:24   3 conn   ▲180KB/s ▼42KB/s   ⛏ 96% mining   ⚠ 1 CRITICAL · 0 susp

  ⚠ HIDDEN MINER ALERTS · process names spoofing kernel threads / daemons ────────────────────────────
  CRITICAL  pid 8821 kworker/u4:2     → Ethereum Stratum         1.2MB↑ 340KB↓        12s

  MINING ACTIVITY · ⛏ confirmed  ⛏! kernel-thread mimicry  ⛏? daemon mimicry ─────────────────────────
   ⛏! kworker/u4:2     pid 8821    160KB/s   38KB/s    1 pool   12s
   ⛏  xmrig            pid 4231    18KB/s    4KB/s     1 pool   24s

  POOLS · sorted by current bandwidth · 2.4MB↑ 720KB↓ mining bytes total ─────────────────────────────
   ⛏ 142.93.124.5:2020         Ethereum Stratum    ▲160KB/s ▼38KB/s   1 miner
   ⛏ 65.21.198.20:14444        Monero Stratum      ▲18KB/s  ▼4KB/s    1 miner

  CONNECTION FEED · opens and closes, newest first ───────────────────────────────────────────────────
   00:24  ⛏ ● OPEN  10.0.0.12:51932          → 142.93.124.5:2020    pid 8821 kworker/u4:2
   00:24  ⛏ ● OPEN  10.0.0.12:51931          → 65.21.198.20:14444   pid 4231 xmrig
────────────────────────────────────────────────────────────────────────────────────────────────────
```

| panel | what it carries |
| --- | --- |
| Status bar | elapsed time, live connection count, current throughput, the share of it going to mining destinations, and the alert tally by tier |
| `HIDDEN MINER ALERTS` | present only when a spoofed process is mining. Red-bordered lead panel: tier, pid, the name it chose, the pool it reached, bytes moved, and how long it has been at it |
| `MINING ACTIVITY` | every process on a mining or Stratum-class port, mimicry hits first and then by bandwidth. `⛏!` is kernel-thread mimicry, `⛏?` daemon mimicry, `⛏` no spoofing |
| `POOLS` | destinations rather than processes, by current bandwidth, annotated with the coin and protocol inferred from the port |
| `CONNECTION FEED` | raw opens and closes across all traffic, not just mining. This is the panel that proves the probe is alive on a quiet host |

Rates in both modes are per-second sums over the last five 200ms ticks, so they respond within about a second. Byte totals are cumulative. Processes and pools idle for 60 seconds are reaped from the live view; audit mode keeps every destination it saw for the whole window.

## Verdicts

One line at the bottom of every audit, and the field to branch on in `--json`. Most severe wins:

| verdict | what triggered it | what to do |
| --- | --- | --- |
| `CRITICAL` | a process on a mining port whose `comm` matches a kernel-thread prefix. There is no benign explanation | treat as a live compromise; the pid and pool are in the report |
| `MINING` | a process confirmed talking to a known pool, with no name spoofing | confirm it is not a miner you run deliberately, then investigate |
| `SUSPICIOUS` | a process whose `comm` matches a system-daemon prefix on a Stratum-class port | review. Daemon names on those ports are odd but not impossible |
| `CLEAN` | no pool connections and no mimicry during the window | nothing found *in this window*. Not proof of absence; see [what it can't see](#what-it-cant-see) |

Crypto P2P hits (Bitcoin's 8333, Ethereum's 30303) are counted and reported but never escalate a verdict, because running a full node is not mining.

## Reading it without a TTY

The dashboard refuses to start without a terminal, and even with one it repaints rather than emitting text. Audit mode is the answer, and it exists for agents, cron, and CI:

```sh
yeet run gh:yeet-src/poolnarc -- --audit --duration 20            # human-readable, pipe-safe
yeet run gh:yeet-src/poolnarc -- --audit --duration 20 --json     # structured
```

Both write scrolling stdout and exit on their own, so neither needs a TTY, a `timeout`, or a `Ctrl-C`. In the JSON, `verdict` is the field to branch on; `alerts[]` carries pid, `comm`, level, pool address and port; `top_destinations[]` gives the 20 busiest with their classification. Timestamps are ISO 8601, and `poolnarc_audit_version` is there so a consumer can detect a shape change.

This is also the command an agent should run to verify the tool works, which is why [Have an agent set it up](#have-an-agent-set-it-up) ends on it: a `CRITICAL` verdict with the simulator running proves the probes attached, and nothing short of that does.

## How it works

The split is deliberate and it is why adding a pool port is a one-line patch: **the kernel side knows nothing about mining.** It observes outbound TCP, attributes it to a process, counts bytes, and streams events. Every judgment happens in JavaScript, where it can change without touching the verifier.

### The BPF side

| program | hook | what it captures |
| --- | --- | --- |
| `on_set_state` | `tp_btf/inet_sock_set_state` | connection lifecycle: creates per-socket state at `TCP_ESTABLISHED`, emits `CLOSE` and reaps at `TCP_CLOSE` |
| `on_sendmsg` | `fentry/tcp_sendmsg` | bytes sent, plus the pid fixup that makes attribution trustworthy |
| `on_cleanup_rbuf` | `fentry/tcp_cleanup_rbuf` | bytes received, plus the same fixup |

Two maps. `conns` is a `BPF_MAP_TYPE_HASH` keyed by the `struct sock` pointer, holding 65536 entries of per-connection state: timestamps, addresses, ports, byte counters, attribution flags. `events` is a 256 KiB `BPF_MAP_TYPE_RINGBUF` carrying three event kinds: `OPEN` once attribution settles, `BYTES` every 64 KiB, `CLOSE` at teardown. Addresses come off the socket through `BPF_CORE_READ` accessors, so the object relocates against whatever kernel it lands on instead of baking in struct offsets.

The 64 KiB threshold is the reason this is cheap on a busy host: a connection moving a gigabyte produces about sixteen thousand events rather than one per packet, and an idle one produces none.

### The JS side

| file | responsibility |
| --- | --- |
| `render.js` | the port database (10 high-confidence, 12 Stratum-class, 7 crypto P2P), the kernel-thread and daemon prefix lists, and every formatter. Adding a pool port is one line here |
| `state.js` | ingests the three event kinds, maintains connections, miners, pools, alerts and all-destinations tables, ages them out, builds the audit snapshot and the verdict |
| `audit.js` | formats that snapshot as text or JSON. Pure presentation over pure data |
| `dashboard.js` | panel layout and sizing for live mode |
| `main.js` | entry point: binds the ringbuf, dispatches live vs audit |

Classification is a destination-port lookup in three tiers. High-confidence ports (Monero's 14444, Ethereum's 12020, NiceHash's 3357 and 9200) are close to exclusively mining. Stratum-class ports (the repdigits, plus 2020 and 8008) are commonly mining but plausible for a generic JSON-RPC service, so they are surfaced as Stratum-class rather than confirmed. Crypto P2P ports are context only.

Mimicry detection is a prefix match on `comm` against two lists. Kernel-thread prefixes (`kworker`, `ksoftirqd`, `swapper`, `kthreadd`, `rcu_`, `migration` and a dozen more) are CRITICAL, for the reason in [the lie that can't survive app context](#the-lie-that-cant-survive-app-context). Daemon prefixes (`systemd`, `dbus`, `cron`, `sshd`, `udevd`) are SUSPICIOUS: those are lies too, but less absolute ones, since a real `sshd` owning a socket is ordinary and only the destination makes it odd.

### Why fentry, not a kprobe

`fentry` attaches through BTF rather than to a symbol address, which buys two things this detector needs. It reads arguments as typed values instead of unpacking a `pt_regs` by architecture convention, so the same source works on x86_64 and aarch64 without a register-name branch. And it is measurably cheaper than a kprobe on the same function, which matters on `tcp_sendmsg`: that is one of the hottest paths in the kernel, and a detector that taxes every write on the box will be turned off long before it catches anything.

The tradeoff is the kernel floor. `fentry` and `tp_btf` both need 5.5 and BTF, so there is no falling back to a kprobe on an ancient kernel; on those, this simply does not load.

## Requirements

> [!IMPORTANT]
> - **Linux 5.5 or newer.** `fentry` and `tp_btf` both need it. Debian 12+, Ubuntu 22.04+, Fedora 36+ and current Arch all qualify.
> - **Kernel BTF** (`CONFIG_DEBUG_INFO_BTF=y`), on by default on all of the above. Confirm `/sys/kernel/btf/vmlinux` exists.
> - **`clang` and `bpftool`** to build the object. `yeet run` fetches the toolchain itself; only a manual `make` needs them present.
> - **`CAP_BPF` and `CAP_PERFMON`.** The yeet daemon holds these and performs the privileged load, so `yeet run` is unprivileged and never takes `sudo`.
> - CO-RE relocation means one build runs across kernel versions, with no per-kernel recompile.

## What it can't see

> [!NOTE]
> poolnarc observes. It does not stop, kill, quarantine, or block anything: it tells you a process is mining and leaves the response to you.

Real ways to defeat it, in roughly the order they will bite you:

- **A private pool on a non-standard port.** The database covers published public-pool defaults, so a pool on 443 looks like HTTPS and never classifies. This is the biggest gap, and the honest mitigation is allowlist-based egress filtering rather than expecting detection to cover it. Mining proxied through a legitimate-looking CDN endpoint fails the same way.
- **A miner that doesn't lie about its name.** Something calling itself `nginx-worker` trips no mimicry rule. It still appears under MINING ACTIVITY when the port classifies, but it stays `MINING` and never escalates to `CRITICAL`.
- **Connections established before the scan started.** Attribution happens at `ESTABLISHED` and the first event waits for bytes, so a socket opened before the probe attached surfaces on its next 64 KiB and not before. A miner idling between work units can sit out a short window entirely, which is why `--duration` matters more on a quiet host than a busy one.
- **Anything that isn't TCP.** The hooks are `tcp_sendmsg` and `tcp_cleanup_rbuf`. UDP-based protocols and raw sockets are invisible.
- **What's inside the connection.** Classification is by destination port and no payload is ever read, so poolnarc cannot confirm a connection is really Stratum rather than something else on that port, and it cannot recover the wallet address. For actual bytes on the wire, [`pktscope`](https://github.com/yeet-src/pktscope) does packet-level decoding; for plaintext inside TLS, that needs an `SSL_write` uprobe, which is [`wssnoop`](https://github.com/yeet-src/wssnoop)'s territory.
- **Which container an alert belongs to.** Events carry the host-namespace pid and nothing resolves a cgroup or namespace, so mapping an alert to a container is a lookup you do afterward. [`container-traffic`](https://github.com/yeet-src/container-traffic) starts from the container view instead.
- **Process names past 15 characters.** `comm` is a 16-byte kernel field, so the name is truncated before poolnarc ever sees it. Prefix matching is unaffected, which is what the prefix lists are for, but the name printed in a report is the truncated one.
- **Browser-based cryptojacking.** A mining script in a page connects from the browser over a WebSocket, typically on 443. Wrong port, wrong shape, not detected.

## FAQ

**A `CLEAN` verdict came back. Am I safe?**
It means nothing matching the two rules happened during that window. A longer `--duration`, or a scan on a schedule, is worth more than one clean run. [What it can't see](#what-it-cant-see) lists what a clean verdict cannot rule out.

**I got a `SUSPICIOUS` on `systemd` and I don't think anything is wrong.**
Likely a real service on a Stratum-class port. Those ports see genuine use by JSON-RPC services unrelated to mining, which is exactly why a daemon name on one is `SUSPICIOUS` rather than `CRITICAL`. Check what the destination is; if it is yours, that is a false positive by design rather than a bug.

**Why is the same process listed twice with different pids?**
Miners are commonly restarted by a supervisor, and aggregation is keyed on pid plus name so a restart appears as a new row instead of silently merging. In audit mode both survive the window; in live mode a row disappears 60 seconds after its last activity.

**Can I add my own pool ports or name rules?**
Yes, and it is a one-line change. `MINING_HIGH_CONF_PORTS`, `MINING_LIKELY_PORTS`, `CRYPTO_P2P_PORTS`, `KERNEL_THREAD_PREFIXES` and `SYSTEM_DAEMON_PREFIXES` all sit at the top of `render.js`. Nothing in the BPF object needs rebuilding, because the kernel side has no idea what a mining pool is.

**Does this catch Kinsing, TeamTNT, or Sysrv-hello?**
It catches the behavior those families share: outbound to public pools on published ports with `comm` renamed via `prctl(PR_SET_NAME)` to look like a kernel thread. `tests/simulate_attack.sh` reproduces that exact pattern so you can watch it fire. What it will not do is name a family, since there is no signature database to match against.

## Building from source

```sh
make            # build bin/poolnarc.bpf.o
make clean      # remove bin/
make distclean  # also remove include/vmlinux.h
```

`make` runs `bpftool btf dump file /sys/kernel/btf/vmlinux format c` to generate `include/vmlinux.h` from the running kernel, then compiles `poolnarc.bpf.c` with `clang -O2 -g -target bpf` into one loadable object. `ARCH` is derived from `uname -m`, so x86_64 and aarch64 both work without configuration. Both `bin/` and `include/` are build artifacts.

`yeet run gh:yeet-src/poolnarc` does all of this for you on first launch; the `make` path is for working on the probe locally.

## Testing across kernels

A BPF program that loads on your laptop can still be rejected by an older kernel's verifier, and CO-RE does not save you from that: relocation fixes struct offsets, not instruction counts or the verifier's view of a bounded loop.

`poolnarc` has no `veristat` target and no kernel matrix in CI yet, so today the check is manual: build on the oldest kernel you intend to support and confirm both `fentry` programs load. The floor that matters is 5.5, since `fentry` and `tp_btf` are the two attach types with no fallback.

## Try it without real traffic

`tests/simulate_attack.sh` reproduces the Kinsing-style pattern end to end, using the same `prctl(PR_SET_NAME)` call the real families use. It starts a fake pool listener on `127.0.0.1:14444` and a Python process that renames itself to `kworker/u4:2` and pumps Stratum-shaped traffic at it. It needs `python3`, and `PORT=` overrides the port.

```sh
# shell 1
yeet run . -- --audit --duration 20

# shell 2
./tests/simulate_attack.sh
```

After 20 seconds the audit prints:

```
VERDICT: CRITICAL — hidden cryptominer detected
  1 process(es) talking to mining pools while spoofing kernel-thread names.
```

`Ctrl-C` the simulator when you are done; the listener and client both die with it. Running the dashboard instead of the audit shows the HIDDEN MINER ALERTS panel turn red within about two seconds. Either way you have verified the detection path without touching real malware.

## License

GPL-2.0.

---

Built with [yeet](https://yeet.cx/docs/?utm_source=github&utm_medium=readme&utm_campaign=poolnarc&utm_content=footer), a JS runtime for writing eBPF programs on Linux machines. Join us on [discord](https://discord.gg/JxVseaAVAU).
