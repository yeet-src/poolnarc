/* Dashboard composition for poolnarc. Same layout idioms as
 * xtop / blktop / flowtop / bytetop / airtop, with mining-detection-
 * specific panels.
 *
 * Panel order:
 *   • HIDDEN MINER ALERTS — only shown if alerts exist. When present,
 *     it's the lead panel (red border, attention-grabbing). The whole
 *     point of the tool is to surface these immediately.
 *   • MINING ACTIVITY — list of processes confirmed talking to mining
 *     pools, sorted with mimicry hits first then by bandwidth.
 *   • POOLS — destination mining pools active right now, by bandwidth.
 *   • CONNECTION FEED — opens/closes, mining-highlighted. */

import {
  fg, bold, dim, ital, RESET, EOL,
  C_AXIS, C_DIM, C_MINING, C_ALERT, C_CRYPTO, C_NORMAL, C_OK, C_TX, C_RX,
  classifyPort, portInfo, portColor, portMark, detectMimicry,
  formatBytes, formatBps, compactNum,
  fmtEndpoint, mmss, fmtDuration,
  vlen, clipAnsi, fixw, padVis,
  sparkline, hbar,
} from "./render.js";

import {
  tot, totalTxHist, totalRxHist, miningTxHist, miningRxHist,
  liveRates, listMiners, listPools, listAlerts, recentEvents, counts,
  aName, aAddr, startTime,
  TICK_MS, WINDOW_MS,
} from "./state.js";

const MIN_COLS = 80;
const MIN_ROWS = 28;

/* ---- chrome helpers (mirror sibling projects) --------------------- */
function topRule(C, title) {
  const head = ` ▌ ${title} `;
  return bold + fg(C_MINING) + head + RESET + fg(C_AXIS) +
    "─".repeat(Math.max(0, C - head.length)) + RESET + EOL;
}
function botRule(C) { return fg(C_AXIS) + "─".repeat(C) + RESET + EOL; }
function sectionBar(C, text, accent = 45) {
  const prefix = fg(accent) + "  " + text + " ";
  const tail = fg(C_AXIS) + "─".repeat(Math.max(0, C - vlen(prefix))) + RESET;
  return clipAnsi(prefix + tail, C) + EOL;
}
/* Alert variant: red bar, bold, attention-grabbing */
function alertBar(C, text) {
  const prefix = bold + fg(C_ALERT) + "  ⚠ " + text + " " + RESET;
  const tail = fg(C_ALERT) + "─".repeat(Math.max(0, C - vlen(prefix))) + RESET;
  return clipAnsi(prefix + tail, C) + EOL;
}

/* ---- header line --------------------------------------------------- */
function headerLine(C) {
  const r = liveRates();
  const c = counts();
  const live = bold + fg(46) + "●" + RESET + fg(252) + " LIVE " + RESET;
  const up = fg(C_DIM) + mmss(Date.now() - startTime) + RESET;
  const active = fg(252) + compactNum(r.active) + RESET + fg(C_DIM) + " conn" + RESET;
  const totalBw = fg(C_TX) + "▲" + RESET + fg(252) + formatBps(r.total_tx_bps) + RESET +
                  fg(C_DIM) + " " + RESET +
                  fg(C_RX) + "▼" + RESET + fg(252) + formatBps(r.total_rx_bps) + RESET;
  /* mining share: percent of current bytes flowing on mining ports */
  const totBw = r.total_tx_bps + r.total_rx_bps;
  const minBw = r.mining_tx_bps + r.mining_rx_bps;
  const pct = totBw > 0 ? Math.round((minBw / totBw) * 100) : 0;
  const mineColor = pct >= 50 ? C_MINING : pct >= 5 ? C_CRYPTO : C_OK;
  const mineStr = fg(mineColor) + "⛏ " + pct + "% mining" + RESET;
  /* alerts */
  let alertStr;
  if (c.critical_alerts > 0) {
    alertStr = bold + fg(C_ALERT) + "⚠ " + c.critical_alerts + " CRITICAL" + RESET;
    if (c.suspicious_alerts > 0) {
      alertStr += fg(C_DIM) + " · " + c.suspicious_alerts + " susp" + RESET;
    }
  } else if (c.suspicious_alerts > 0) {
    alertStr = fg(C_MINING) + "⚠ " + c.suspicious_alerts + " suspicious" + RESET;
  } else {
    alertStr = fg(C_OK) + "✓ no hidden miners" + RESET;
  }
  const SEP = fg(C_DIM) + "   " + RESET;
  const parts = [live + up, active, totalBw, mineStr, alertStr];
  let line = parts.join(SEP);
  if (vlen(line) > C) line = parts.join(" ");
  return clipAnsi(line, C) + EOL;
}

/* ---- HIDDEN MINER ALERTS panel ------------------------------------ */
function panelAlerts(C, H) {
  const list = listAlerts(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no hidden-miner alerts (mimicked process names talking to mining pools)" + RESET];
  }
  /* Adaptive column widths: comm + level + pool + coin + bytes */
  const commW = Math.min(18, Math.max(12, Math.floor(C * 0.20)));
  const showSpark = false;   /* alerts are too important to be flanked by sparklines */
  const out = [];
  for (const a of list) {
    if (out.length >= H) break;
    const levelStr = a.level === "critical"
      ? bold + fg(C_ALERT) + "CRITICAL " + RESET
      : fg(C_MINING) + "suspicious" + RESET;
    const pidComm = fixw(
      fg(C_DIM) + ("pid " + a.pid).padEnd(9) + RESET +
      fg(252) + aName(a.comm) + RESET,
      commW + 10);
    /* describe the pool the miner is talking to */
    const info = portInfo(a.pool_port);
    const coinTxt = info
      ? fg(C_MINING) + info.coin + " " + info.proto + RESET
      : fg(C_NORMAL) + "Stratum:" + a.pool_port + RESET;
    /* bytes summary */
    const bytesTxt = fg(C_DIM) +
      formatBytes(a.bytes_tx) + "↑ " + formatBytes(a.bytes_rx) + "↓" + RESET;
    const dur = fg(C_DIM) + fmtDuration(Date.now() - a.first_seen) + RESET;
    const line = "  " + levelStr + " " + pidComm + " → " +
                 fixw(coinTxt, 22) + " " +
                 fixw(bytesTxt, 22) + " " + dur;
    out.push(clipAnsi(line, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- MINING ACTIVITY panel (signature) --------------------------- */
function panelMiners(C, H) {
  const list = listMiners(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no mining traffic detected yet — open a miner or wait for one to phone home." + RESET];
  }
  const commW   = Math.min(18, Math.max(12, Math.floor(C * 0.18)));
  const showSpark = C >= 100;
  const sparkW = showSpark
    ? Math.max(8, C - (2 + 1 + commW + 1 + 9 + 1 + 9 + 1 + 9 + 1 + 9 + 4))
    : 0;
  const out = [];
  for (const item of list) {
    if (out.length >= H) break;
    const m = item.m;
    /* mimicry badge */
    let badge;
    if (m.mimicry === "critical")
      badge = bold + fg(C_ALERT) + "⛏!" + RESET;
    else if (m.mimicry === "suspicious")
      badge = fg(C_MINING) + "⛏?" + RESET;
    else
      badge = fg(C_MINING) + "⛏ " + RESET;
    const pidStr = fg(C_DIM) + ("pid " + m.pid).padEnd(9) + RESET;
    const commCell = fixw(fg(252) + aName(m.comm) + RESET, commW);
    const txCell = fg(C_TX) + fixw(formatBps(item.tx_bps), 9) + RESET;
    const rxCell = fg(C_RX) + fixw(formatBps(item.rx_bps), 9) + RESET;
    const poolsCell = fg(C_DIM) + fixw(m.pools.size + " pool" + (m.pools.size === 1 ? "" : "s"), 9) + RESET;
    const durCell = fg(C_DIM) + fixw(fmtDuration(Date.now() - m.first_seen), 9) + RESET;
    let spark = "";
    if (showSpark && sparkW >= 4) {
      spark = " " + sparkline(m.tx_rate_hist, sparkW, C_MINING);
    }
    const line = " " + badge + " " + commCell + " " + pidStr + " " +
                 txCell + " " + rxCell + " " + poolsCell + " " + durCell + spark;
    out.push(clipAnsi(line, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- POOLS panel -------------------------------------------------- */
function panelPools(C, H) {
  const list = listPools(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no mining pools observed yet…" + RESET];
  }
  const ENDP_W = Math.min(30, Math.max(22, Math.floor(C * 0.30)));
  const COIN_W = 22;
  const RATE_W = 10;
  const showSpark = C >= 100;
  const sparkW = showSpark
    ? Math.max(8, C - (2 + 1 + ENDP_W + 1 + COIN_W + 1 + RATE_W*2 + 2 + 12 + 4))
    : 0;
  const out = [];
  for (const item of list) {
    if (out.length >= H) break;
    const p = item.p;
    const ep = aAddr(fmtEndpoint(p.family, p.addr, p.port));
    const cls = p.classification;
    const color = cls === "mining" ? C_MINING
                : cls === "stratum" ? C_MINING
                : cls === "crypto-p2p" ? C_CRYPTO
                : C_NORMAL;
    const mark = fg(color) + portMark(p.port) + RESET;
    const epCell = fixw(fg(color) + ep + RESET, ENDP_W);
    const coinTxt = p.info
      ? fg(color) + p.info.coin + " " + p.info.proto + RESET
      : fg(C_DIM) + "(unrecognized)" + RESET;
    const coinCell = fixw(coinTxt, COIN_W);
    const tx = fg(C_TX) + "▲" + RESET + fixw(formatBps(item.tx_bps), RATE_W - 1);
    const rx = fg(C_RX) + "▼" + RESET + fixw(formatBps(item.rx_bps), RATE_W - 1);
    const miners = fg(C_DIM) + fixw(p.miners.size + " miner" + (p.miners.size === 1 ? "" : "s"), 10) + RESET;
    let spark = "";
    if (showSpark && sparkW >= 4) {
      spark = " " + sparkline(p.tx_rate_hist, sparkW, color);
    }
    const line = " " + mark + " " + epCell + " " + coinCell + " " +
                 tx + " " + rx + " " + miners + spark;
    out.push(clipAnsi(line, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- CONNECTION FEED panel ---------------------------------------- */
function panelFeed(C, H) {
  const list = recentEvents(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no events yet…" + RESET];
  }
  const epW = Math.max(20, Math.min(28, Math.floor((C - 50) / 2)));
  const out = [];
  for (let i = 0; i < Math.min(H, list.length); i++) {
    const e = list[i];
    const ts = fg(C_DIM) + mmss(Math.max(0, e.ts - startTime)) + RESET;
    const cls = e.classification;
    const color = cls === "mining" || cls === "stratum" ? C_MINING
                : cls === "crypto-p2p" ? C_CRYPTO
                : C_NORMAL;
    const mark = fg(color) + portMark(e.dport) + RESET;
    const local = aAddr(fmtEndpoint(e.family, e.saddr, e.sport));
    const remote = aAddr(fmtEndpoint(e.family, e.daddr, e.dport));
    let middle;
    if (e.kind === "open") {
      middle = fg(color) + bold + fixw("● OPEN", 8) + RESET + " " +
               fg(252) + fixw(local, epW) + RESET +
               fg(C_DIM) + " → " + RESET +
               fg(color) + fixw(remote, epW) + RESET;
    } else {
      const bytes = fg(C_DIM) + fixw(
        formatBytes(e.bytes_tx) + "/" + formatBytes(e.bytes_rx),
        16) + RESET;
      middle = fg(C_DIM) + fixw("✕ CLOSE", 8) + RESET + " " +
               fg(252) + fixw(local, epW) + RESET +
               fg(C_DIM) + " → " + RESET +
               fg(248) + fixw(remote, epW) + RESET +
               " " + bytes;
    }
    const proc = (e.pid > 0)
      ? fg(C_DIM) + "  pid " + e.pid + " " + RESET + fg(248) + aName(e.comm) + RESET
      : "";
    const line = " " + ts + "  " + mark + " " + middle + proc;
    out.push(clipAnsi(line, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- composition --------------------------------------------------- */
export function renderDashboard(C, R) {
  if (C < MIN_COLS || R < MIN_ROWS) return smallTerm(C, R);

  const rows = [];
  rows.push(topRule(C, "POOLNARC · crypto-mining traffic detector"));
  rows.push(headerLine(C));
  rows.push("");

  const cnt = counts();
  const hasAlerts = (cnt.critical_alerts + cnt.suspicious_alerts) > 0;

  /* chrome accounting (panels = rows that aren't content strips):
   *   top + header + blank
   *   + (hasAlerts ? alert-title + blank : 0)
   *   + miners-title
   *   + blank + pools-title
   *   + blank + feed-title
   *   + bottom-rule */
  const chrome = 2 + 1
               + (hasAlerts ? 2 : 0)
               + 1
               + 2
               + 2
               + 1;

  const content = R - chrome;
  let alertsH = 0, minersH, poolsH, feedH;
  if (hasAlerts) {
    alertsH = Math.min(4, Math.max(2, Math.ceil(content * 0.18)));
  }
  const remaining = content - alertsH;
  minersH = Math.max(4, Math.round(remaining * 0.36));
  poolsH  = Math.max(3, Math.round(remaining * 0.28));
  feedH   = Math.max(3, remaining - minersH - poolsH);

  /* HIDDEN MINER ALERTS first (if any) — this is the headline */
  if (hasAlerts) {
    rows.push(alertBar(C, "HIDDEN MINER ALERTS · process names spoofing kernel threads / daemons"));
    const ax = panelAlerts(C, alertsH);
    for (let i = 0; i < alertsH; i++) rows.push(ax[i] ?? " ".repeat(C));
    rows.push("");
  }

  /* MINING ACTIVITY */
  rows.push(sectionBar(C, "MINING ACTIVITY · " +
                          fg(C_MINING) + "⛏ confirmed" + fg(45) + "  " +
                          fg(C_ALERT) + "⛏! kernel-thread mimicry" + fg(45) + "  " +
                          fg(C_MINING) + "⛏? daemon mimicry" + fg(45)));
  const mx = panelMiners(C, minersH);
  for (let i = 0; i < minersH; i++) rows.push(mx[i] ?? " ".repeat(C));

  /* POOLS */
  rows.push("");
  rows.push(sectionBar(C, "POOLS · sorted by current bandwidth · "
                          + formatBytes(tot.bytes_tx_mining) + "↑ "
                          + formatBytes(tot.bytes_rx_mining) + "↓ mining bytes total"));
  const px = panelPools(C, poolsH);
  for (let i = 0; i < poolsH; i++) rows.push(px[i] ?? " ".repeat(C));

  /* CONNECTION FEED */
  rows.push("");
  rows.push(sectionBar(C, "CONNECTION FEED · opens and closes, newest first"));
  const fd = panelFeed(C, feedH);
  for (let i = 0; i < feedH; i++) rows.push(fd[i] ?? " ".repeat(C));

  rows.push(botRule(C));

  /* finalize: ensure every row has an EOL or erase-to-end */
  const trimmed = rows.slice(0, R).map(
    (l) => (l && (l.endsWith(EOL) || l.includes("\x1b[K"))) ? l : l + EOL);
  return clearScreen() + trimmed.join("\n");
}

export function clearScreen() { return "\x1b[H\x1b[2J"; }

function smallTerm(C, R) {
  const lines = [
    `poolnarc: terminal too small`,
    `need ≥ ${MIN_COLS}×${MIN_ROWS}`,
    `have ${C}×${R}`,
  ];
  return lines.map((l) => l.slice(0, Math.max(1, C))).join("\n") + "\n";
}
