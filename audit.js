/* audit.js — one-shot scan + report.
 *
 * The live dashboard repaints in place. Audit mode writes scrolling
 * output, safe to pipe or redirect. Two output formats: human
 * (default, colored) or JSON (--json).
 */

import {
  auditSnapshot,
  advance,
} from "./state.js";

import {
  fmtAddr, fmtEndpoint, formatBytes, fmtDuration,
  fg, bold, ital, dim, RESET,
  C_ALERT, C_MINING, C_CRYPTO, C_OK, C_DIM, C_NORMAL,
} from "./render.js";

/* Drive state.advance() at dashboard cadence so audit reports get
 * the same rate-history compaction. */
function startAdvanceTicker(intervalMs) {
  return setInterval(() => { try { advance(); } catch (_) {} }, intervalMs);
}

/* Plain ASCII so it survives non-Unicode terminals and chat paste. */
function banner() {
  const lines = [
    "════════════════════════════════════════════════════════════════",
    "  poolnarc audit · behavioral hidden-cryptominer scan",
    "════════════════════════════════════════════════════════════════",
  ];
  return lines.join("\n");
}

function timestamp() {
  const d = new Date();
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/* Verdict line. CLEAN is green, the rest escalate visually. */
function verdictLine(verdict, snapshot) {
  switch (verdict) {
    case "CRITICAL":
      return bold + fg(C_ALERT) +
             "VERDICT: CRITICAL — hidden cryptominer detected" + RESET +
             "\n  " + fg(C_ALERT) +
             snapshot.critical_alerts +
             " process(es) talking to mining pools while spoofing kernel-thread names." +
             RESET;
    case "MINING":
      return bold + fg(C_MINING) +
             "VERDICT: MINING ACTIVITY DETECTED" + RESET +
             "\n  " + fg(C_MINING) +
             snapshot.miners.length +
             " process(es) confirmed talking to known mining pools (no comm spoofing observed)." +
             RESET;
    case "SUSPICIOUS":
      return bold + fg(C_MINING) +
             "VERDICT: SUSPICIOUS — review recommended" + RESET +
             "\n  " + fg(C_MINING) +
             snapshot.suspicious_alerts +
             " process(es) with daemon-like names exhibiting mining-like patterns." +
             RESET;
    case "CLEAN":
    default:
      return bold + fg(C_OK) +
             "VERDICT: NO MINING ACTIVITY DETECTED" + RESET +
             "\n  " + fg(C_OK) +
             "No connections to known mining pools or Stratum-class ports." +
             " No processes mimicking kernel-thread names with outbound TCP." +
             RESET;
  }
}

/* ---------------------------------------------------------------------- *
 * Human-readable report.                                                 *
 * ---------------------------------------------------------------------- */

export function printHumanReport(snapshot) {
  const lines = [];

  lines.push(banner());
  lines.push("");
  lines.push("  Scan started: " + new Date(snapshot.started_at).toISOString());
  lines.push("  Scan ended:   " + timestamp());
  lines.push("  Duration:     " + fmtDuration(snapshot.scan_duration_ms));
  lines.push("");

  /* ---- Connections observed ---- */
  lines.push(fg(C_DIM) + "── Connections observed ────────────────────────────────────────" + RESET);
  lines.push("  TCP events seen:          " + snapshot.total_events);
  lines.push("  Connections opened:       " + snapshot.total_opens);
  lines.push("  Connections closed:       " + snapshot.total_closes);
  lines.push("  Distinct destinations:    " + snapshot.distinct_destinations);
  lines.push("  Total bytes ↑/↓:          " +
              formatBytes(snapshot.total_bytes_tx) + " / " +
              formatBytes(snapshot.total_bytes_rx));
  lines.push("");

  /* ---- Mining pool detection ---- */
  const miningHits = snapshot.mining_pool_hits + snapshot.stratum_likely_hits;
  const miningLabel = miningHits === 0
    ? fg(C_OK) + "✓ NONE" + RESET
    : fg(C_MINING) + "✗ " + miningHits + " HIT" + (miningHits === 1 ? "" : "S") + RESET;
  lines.push(fg(C_DIM) + "── Mining pool detection ───────────────────────────────────────" + RESET);
  lines.push("  High-confidence mining ports:  " +
              (snapshot.mining_pool_hits > 0
                ? fg(C_ALERT) + snapshot.mining_pool_hits + " destination(s)" + RESET
                : fg(C_OK) + "0" + RESET));
  lines.push("  Likely Stratum ports:          " +
              (snapshot.stratum_likely_hits > 0
                ? fg(C_MINING) + snapshot.stratum_likely_hits + " destination(s)" + RESET
                : fg(C_OK) + "0" + RESET));
  lines.push("  Crypto P2P ports (BTC/ETH):    " +
              (snapshot.crypto_p2p_hits > 0
                ? fg(C_CRYPTO) + snapshot.crypto_p2p_hits + " destination(s)" + RESET
                : fg(C_DIM) + "0" + RESET) +
                fg(C_DIM) + "  (informational, not mining)" + RESET);
  lines.push("  Mining traffic ↑/↓:            " +
              formatBytes(snapshot.mining_bytes_tx) + " / " +
              formatBytes(snapshot.mining_bytes_rx));
  lines.push("  Overall:                       " + miningLabel);
  lines.push("");

  /* ---- Mimicry detection ---- */
  const mimicryClean = snapshot.critical_alerts + snapshot.suspicious_alerts === 0;
  lines.push(fg(C_DIM) + "── Comm-name mimicry detection ─────────────────────────────────" + RESET);
  lines.push("  Kernel-thread name spoofing:   " +
              (snapshot.critical_alerts > 0
                ? fg(C_ALERT) + bold + snapshot.critical_alerts + " process(es)" + RESET
                : fg(C_OK) + "0" + RESET));
  lines.push("  System-daemon name spoofing:   " +
              (snapshot.suspicious_alerts > 0
                ? fg(C_MINING) + snapshot.suspicious_alerts + " process(es)" + RESET
                : fg(C_OK) + "0" + RESET));
  lines.push("  Overall:                       " +
              (mimicryClean
                ? fg(C_OK) + "✓ NO MIMICRY OBSERVED" + RESET
                : fg(C_ALERT) + "✗ MIMICRY DETECTED — see alerts below" + RESET));
  lines.push("");

  /* ---- Alerts (if any) ---- */
  if (snapshot.alerts.length > 0) {
    lines.push(fg(C_DIM) + "── ALERTS ──────────────────────────────────────────────────────" + RESET);
    for (const a of snapshot.alerts) {
      const color = a.level === "critical" ? C_ALERT : C_MINING;
      const mark = a.level === "critical" ? "⚠" : "?";
      const addrBytes = hexToBytes(a.pool_addr);
      const family = addrBytes.every((b, i) => i >= 4 ? b === 0 : true) ? 2 : 10;
      lines.push("  " + fg(color) + bold + mark + " " + a.level.toUpperCase() + RESET +
                  fg(color) + " · pid " + a.pid + " (" + a.comm + ")" + RESET);
      lines.push("    Talked to: " + fmtEndpoint(family, addrBytes, a.pool_port) +
                  "  (" + a.classification + ")");
      lines.push("    Bytes:     ↑" + formatBytes(a.bytes_tx) +
                  " / ↓" + formatBytes(a.bytes_rx) +
                  "    Conns: " + a.conn_count);
      lines.push("");
    }
  }

  /* ---- Miners (if any) ---- */
  if (snapshot.miners.length > 0) {
    lines.push(fg(C_DIM) + "── Processes talking to mining pools ───────────────────────────" + RESET);
    for (const m of snapshot.miners) {
      const mimMark = m.mimicry
        ? fg(C_ALERT) + " ⚠ " + m.mimicry.toUpperCase() + RESET
        : "";
      lines.push("  pid " + m.pid + " (" + m.comm + ")" + mimMark);
      lines.push("    Classification: " + m.classification +
                  "   Pools: " + m.pool_count +
                  "   Conns: " + m.conn_count);
      lines.push("    Bytes: ↑" + formatBytes(m.bytes_tx) +
                  " / ↓" + formatBytes(m.bytes_rx));
      lines.push("");
    }
  }

  /* ---- Pools (if any) ---- */
  if (snapshot.pools.length > 0) {
    lines.push(fg(C_DIM) + "── Mining pool destinations observed ───────────────────────────" + RESET);
    for (const p of snapshot.pools) {
      const info = p.info ? " (" + p.info.coin + " " + p.info.proto + ")" : "";
      lines.push("  " + fmtEndpoint(p.family, p.addr, p.port) + info);
      lines.push("    " + fg(C_DIM) + "↑" + formatBytes(p.bytes_tx) +
                  " ↓" + formatBytes(p.bytes_rx) +
                  "  miners: " + p.miner_count +
                  "  conns: " + p.conn_count + RESET);
    }
    lines.push("");
  }

  /* ---- Top destinations (always show — context for clean verdicts) ---- */
  if (snapshot.top_destinations.length > 0) {
    lines.push(fg(C_DIM) + "── Top destinations by bandwidth ───────────────────────────────" + RESET);
    const max = Math.min(10, snapshot.top_destinations.length);
    for (let i = 0; i < max; i++) {
      const d = snapshot.top_destinations[i];
      const tag = d.classification === "mining"     ? fg(C_ALERT)  + " [MINING]"     + RESET
                : d.classification === "stratum"    ? fg(C_MINING) + " [STRATUM]"    + RESET
                : d.classification === "crypto-p2p" ? fg(C_CRYPTO) + " [CRYPTO-P2P]" + RESET
                : "";
      lines.push("  " + String(i + 1).padStart(2) + ". " +
                  fmtEndpoint(d.family, d.addr, d.port) + tag);
      lines.push("      " + fg(C_DIM) + "↑" + formatBytes(d.bytes_tx) +
                  " / ↓" + formatBytes(d.bytes_rx) +
                  "   conns: " + d.conn_count + RESET);
    }
    lines.push("");
  } else if (snapshot.total_events === 0) {
    lines.push(fg(C_DIM) + ital +
      "  (no TCP activity observed during the scan window)" + RESET);
    lines.push("");
  }

  /* ---- Verdict ---- */
  lines.push("════════════════════════════════════════════════════════════════");
  lines.push(verdictLine(snapshot.verdict, snapshot));
  lines.push("════════════════════════════════════════════════════════════════");

  return lines.join("\n") + "\n";
}

/* Convert hex string back to Uint8Array(16) for the alert renderer.
 * The alerts table stores pool_addr as a hex string (set in state.js
 * via addrToHexStr), so we have to round-trip back to bytes here. */
function hexToBytes(hex) {
  const out = new Uint8Array(16);
  if (!hex || typeof hex !== "string") return out;
  for (let i = 0; i < 16 && i * 2 + 1 < hex.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16) | 0;
  }
  return out;
}

/* ---------------------------------------------------------------------- *
 * JSON report (machine-readable).                                        *
 * ---------------------------------------------------------------------- */

export function printJSONReport(snapshot) {
  /* Strip Uint8Array addrs — JSON.stringify renders them as objects with
   * numeric string keys, which is ugly and not what scripting consumers
   * want. Replace with proper formatted address strings. */
  const safe = {
    poolnarc_audit_version: 1,
    scan_started_at: new Date(snapshot.started_at).toISOString(),
    scan_duration_ms: snapshot.scan_duration_ms,
    verdict: snapshot.verdict,
    total_events: snapshot.total_events,
    total_opens: snapshot.total_opens,
    total_closes: snapshot.total_closes,
    total_bytes_tx: snapshot.total_bytes_tx,
    total_bytes_rx: snapshot.total_bytes_rx,
    mining_bytes_tx: snapshot.mining_bytes_tx,
    mining_bytes_rx: snapshot.mining_bytes_rx,
    distinct_destinations: snapshot.distinct_destinations,
    mining_pool_hits: snapshot.mining_pool_hits,
    stratum_likely_hits: snapshot.stratum_likely_hits,
    crypto_p2p_hits: snapshot.crypto_p2p_hits,
    critical_alerts: snapshot.critical_alerts,
    suspicious_alerts: snapshot.suspicious_alerts,
    alerts: snapshot.alerts.map((a) => {
      const addrBytes = hexToBytes(a.pool_addr);
      /* Heuristic: if first 4 bytes are non-zero and the rest is zero,
       * treat as v4. Otherwise v6. The state model stores both as the
       * 16-byte buffer where v4 lives in the first 4 bytes. */
      const isV4 = addrBytes.slice(4).every((b) => b === 0) &&
                   !addrBytes.slice(0, 4).every((b) => b === 0);
      return {
        pid: a.pid,
        comm: a.comm,
        level: a.level,
        classification: a.classification,
        pool_address: isV4
          ? `${addrBytes[0]}.${addrBytes[1]}.${addrBytes[2]}.${addrBytes[3]}`
          : fmtAddr(10, addrBytes),
        pool_port: a.pool_port,
        conn_count: a.conn_count,
        bytes_tx: a.bytes_tx,
        bytes_rx: a.bytes_rx,
        first_seen: new Date(a.first_seen).toISOString(),
        last_seen: new Date(a.last_seen).toISOString(),
      };
    }),
    miners: snapshot.miners.map((m) => ({
      pid: m.pid,
      comm: m.comm,
      classification: m.classification,
      bytes_tx: m.bytes_tx,
      bytes_rx: m.bytes_rx,
      conn_count: m.conn_count,
      pool_count: m.pool_count,
      mimicry: m.mimicry,
      first_seen: new Date(m.first_seen).toISOString(),
      last_seen: new Date(m.last_seen).toISOString(),
    })),
    pools: snapshot.pools.map((p) => ({
      address: fmtAddr(p.family, p.addr),
      port: p.port,
      family: p.family === 10 ? "ipv6" : "ipv4",
      classification: p.classification,
      coin: p.info?.coin ?? null,
      proto: p.info?.proto ?? null,
      bytes_tx: p.bytes_tx,
      bytes_rx: p.bytes_rx,
      conn_count: p.conn_count,
      miner_count: p.miner_count,
    })),
    top_destinations: snapshot.top_destinations.map((d) => ({
      address: fmtAddr(d.family, d.addr),
      port: d.port,
      family: d.family === 10 ? "ipv6" : "ipv4",
      classification: d.classification,
      bytes_tx: d.bytes_tx,
      bytes_rx: d.bytes_rx,
      total_bytes: d.total_bytes,
      conn_count: d.conn_count,
    })),
  };

  return JSON.stringify(safe, null, 2) + "\n";
}

/* ---------------------------------------------------------------------- *
 * Runner.                                                                *
 * ---------------------------------------------------------------------- *
 *
 * opts:
 *   durationMs   scan window length
 *   asJSON       JSON output if true, human if false
 *   write        injection for testing; defaults to tty or stdout
 *   onComplete   optional post-report callback
 *
 * Returns the snapshot so callers can inspect it programmatically. */
export function runAudit(opts) {
  opts = opts || {};
  const durationMs = opts.durationMs || 60_000;
  const asJSON     = !!opts.asJSON;
  const write      = opts.write || ((s) => {
    if (globalThis.tty?.write) globalThis.tty.write(s);
    else process.stdout.write(s);
  });
  const onComplete = opts.onComplete;

  if (!asJSON) {
    write(banner() + "\n");
    write("  Watching all TCP activity for " +
          fmtDuration(durationMs) + "...\n");
    write("  " + fg(C_DIM) + ital +
          "(quiet output during scan — full report at the end)" + RESET + "\n\n");
  }

  const ticker = startAdvanceTicker(200);

  return new Promise((resolve) => {
    setTimeout(() => {
      clearInterval(ticker);
      const snap = auditSnapshot();
      const out = asJSON ? printJSONReport(snap) : printHumanReport(snap);
      write(out);
      resolve(snap);
      if (onComplete) onComplete(snap);
    }, durationMs);
  });
}
