/* Application state + event ingest for poolnarc.
 *
 * BPF emits three event kinds on one ringbuf:
 *   kind 0  OPEN   new connection observed
 *   kind 1  BYTES  periodic byte delta on a tracked connection
 *   kind 2  CLOSE  connection terminating
 *
 * The model adds mining-detection state on top of the bytetop model:
 *   • connections classified at OPEN by destination port
 *   • miners: Map<pid, MinerStat> of processes confirmed to be mining
 *   • alerts: Map<pid, AlertRec> of "hidden miner" mimicry hits */

import { classifyPort, portInfo, detectMimicry } from "./render.js";

export const TICK_MS    = 200;
export const WINDOW_MS  = 10_000;
export const HIST_LEN   = 240;
const   CLOSE_FADE_MS   = 5_000;
const   PROC_STALE_MS   = 60_000;
const   POOL_STALE_MS   = 60_000;
const   FEED_KEEP       = 200;

/* ---- global counters + history ------------------------------------ */
export const startTime = Date.now();
export const tot = {
  events: 0,
  opens: 0,
  closes: 0,
  bytes_tx_mining: 0,    /* bytes flowing on confirmed mining ports     */
  bytes_rx_mining: 0,
  bytes_tx_total: 0,     /* across all connections                      */
  bytes_rx_total: 0,
  alerts_critical: 0,    /* counted by alert events fired               */
  alerts_suspicious: 0,
};

let tickMiningTx = 0, tickMiningRx = 0;
let tickTotalTx = 0,  tickTotalRx = 0;
let tickOpens = 0;
export const miningTxHist = [];
export const miningRxHist = [];
export const totalTxHist  = [];
export const totalRxHist  = [];
export const opensHist    = [];
export const activeHist   = [];
function pushHist(arr, v) { arr.push(v); if (arr.length > HIST_LEN) arr.shift(); }

/* ---- anonymize ---------------------------------------------------- */
const anon = !!globalThis.yeet?.args?.anonymize;
const aliasMaps = { name: new Map(), addr: new Map() };
function aliasGen(kind, key, prefix) {
  const m = aliasMaps[kind];
  let a = m.get(key);
  if (!a) { a = prefix + String(m.size + 1).padStart(2, "0"); m.set(key, a); }
  return a;
}
export function aName(s) { return anon && s ? aliasGen("name", s, "proc-") : s; }
export function aAddr(s) { return anon && s ? aliasGen("addr", s, "host-") : s; }

/* ---- connection table --------------------------------------------- */
const conns = new Map();   /* sk_hex → ConnInfo */

/* ---- aggregators -------------------------------------------------- */
/* MinerStat: a process currently mining (classification = mining|stratum).
 * Keyed by "pid:comm" so distinct procs don't collapse. */
const miners = new Map();

/* AlertRec: a hidden-miner hit. Keyed by "pid:comm". */
const alerts = new Map();

/* PoolStat: a destination pool currently active. Keyed by
 * "family:addr-hex:port". Carries the inferred coin/proto. */
const pools = new Map();

/* allDests: every destination seen during the scan, regardless of
 * classification. Used by audit mode to count "I saw N destinations,
 * M were mining." No TTL since audit windows are short. The live
 * dashboard doesn't read this map. */
const allDests = new Map();

function getAllDest(family, daddr, dport, classification) {
  let k = String(family) + "\x00";
  for (let i = 0; i < 16; i++) k += daddr[i].toString(16).padStart(2, "0");
  k += "\x00" + dport;
  let d = allDests.get(k);
  if (!d) {
    const addrCopy = new Uint8Array(16);
    for (let i = 0; i < 16; i++) addrCopy[i] = daddr[i] | 0;
    d = {
      family, addr: addrCopy, port: dport,
      classification,
      bytes_tx: 0, bytes_rx: 0,
      conn_count: 0,
      first_seen: Date.now(),
      last_seen:  Date.now(),
    };
    allDests.set(k, d);
  }
  return d;
}

function minerKey(pid, comm) { return pid + "\x00" + comm; }

function getMiner(pid, comm, cls) {
  const key = minerKey(pid, comm);
  let m = miners.get(key);
  if (!m) {
    m = {
      pid, comm,
      classification: cls,                 /* "mining" or "stratum"     */
      bytes_tx: 0, bytes_rx: 0,
      tx_rate_hist: [], rx_rate_hist: [],
      conn_count: 0,
      pools: new Set(),                    /* set of pool keys           */
      first_seen: Date.now(),
      last_seen:  Date.now(),
      mimicry: detectMimicry(comm),        /* "critical"|"suspicious"|null */
    };
    miners.set(key, m);
  }
  return m;
}

function getPool(family, daddr, dport) {
  let k = String(family) + ":";
  for (let i = 0; i < 16; i++) k += daddr[i].toString(16).padStart(2, "0");
  k += ":" + dport;
  let p = pools.get(k);
  if (!p) {
    const addrCopy = new Uint8Array(16);
    for (let i = 0; i < 16; i++) addrCopy[i] = daddr[i] | 0;
    p = {
      family, addr: addrCopy, port: dport,
      classification: classifyPort(dport),
      info: portInfo(dport),
      bytes_tx: 0, bytes_rx: 0,
      tx_rate_hist: [], rx_rate_hist: [],
      conn_count: 0,
      miners: new Set(),                   /* set of miner keys */
      first_seen: Date.now(),
      last_seen:  Date.now(),
    };
    pools.set(k, p);
  }
  return p;
}

function recordAlert(pid, comm, cls, level, pool_addr_str, pool_port) {
  const key = minerKey(pid, comm);
  let a = alerts.get(key);
  if (!a) {
    a = {
      pid, comm,
      level,                              /* "critical" | "suspicious" */
      classification: cls,
      pool_addr: pool_addr_str,
      pool_port,
      first_seen: Date.now(),
      last_seen:  Date.now(),
      conn_count: 0,
      bytes_tx: 0, bytes_rx: 0,
    };
    alerts.set(key, a);
    if (level === "critical") tot.alerts_critical++;
    else tot.alerts_suspicious++;
  }
  a.conn_count++;
  a.last_seen = Date.now();
  return a;
}

/* ---- live event feed ---------------------------------------------- */
const feed = [];
function pushFeed(rec) { feed.push(rec); if (feed.length > FEED_KEEP) feed.shift(); }

/* ---- decoders ----------------------------------------------------- */
function num(v) { return typeof v === "bigint" ? Number(v) : v; }
function bigKey(v) { return typeof v === "bigint" ? v.toString(16) : String(v); }
function bytesAsArray(b) {
  const out = new Uint8Array(16);
  if (!b) return out;
  for (let i = 0; i < 16; i++) out[i] = b[i] | 0;
  return out;
}
function addrToHexStr(daddr) {
  let s = "";
  for (let i = 0; i < 16; i++) s += daddr[i].toString(16).padStart(2, "0");
  return s;
}

/* ---- ingest ------------------------------------------------------- */
export function onEvent(e) {
  if (!e) return;
  tot.events++;
  const kind = num(e.kind) | 0;
  const now = Date.now();
  const sk = bigKey(e.sk);
  const family = num(e.family) | 0;
  const sport  = num(e.sport) & 0xffff;
  const dport  = num(e.dport) & 0xffff;
  const pid    = num(e.pid) | 0;
  const comm   = String(e.comm || "?");
  const saddr  = bytesAsArray(e.saddr);
  const daddr  = bytesAsArray(e.daddr);
  const bytes_tx = num(e.bytes_tx) || 0;
  const bytes_rx = num(e.bytes_rx) || 0;
  const delta_tx = num(e.delta_tx) || 0;
  const delta_rx = num(e.delta_rx) || 0;

  const cls = classifyPort(dport);

  if (kind === 0) {
    tot.opens++; tickOpens++;
    let c = conns.get(sk);
    if (!c) {
      c = {
        sk, family, saddr, sport, daddr, dport,
        pid, comm,
        bytes_tx: 0, bytes_rx: 0,
        first_seen: now, last_active: now, closed: 0,
        classification: cls,
      };
      conns.set(sk, c);
    } else {
      /* Repeat OPEN — accept new attribution but preserve byte counters
       * so in-flight accounting isn't dropped. */
      c.pid = pid; c.comm = comm; c.last_active = now;
    }
    /* Mining-aware aggregation */
    if (cls === "mining" || cls === "stratum") {
      const m = getMiner(c.pid, c.comm, cls);
      m.conn_count++; m.last_seen = now;
      const p = getPool(c.family, c.daddr, c.dport);
      p.conn_count++; p.last_seen = now;
      p.miners.add(minerKey(c.pid, c.comm));
      m.pools.add(addrToHexStr(c.daddr) + ":" + c.dport);
      /* Hidden-miner detection: if the process name is a kernel-thread
       * or system-daemon prefix AND it's talking mining, flag it. */
      if (m.mimicry) {
        recordAlert(c.pid, c.comm, cls, m.mimicry,
                    addrToHexStr(c.daddr), c.dport);
      }
    }
    /* Track EVERY destination (not just mining) for audit mode. */
    const d = getAllDest(c.family, c.daddr, c.dport, cls);
    d.conn_count++; d.last_seen = now;
    pushFeed({
      ts: now, kind: "open", sk,
      family: c.family,
      saddr: c.saddr, sport: c.sport,
      daddr: c.daddr, dport: c.dport,
      pid: c.pid, comm: c.comm,
      classification: cls,
    });
    return;
  }

  if (kind === 1) {
    let c = conns.get(sk);
    if (!c) {
      /* missed OPEN — create stub so bytes aren't lost */
      c = {
        sk, family, saddr, sport, daddr, dport,
        pid, comm,
        bytes_tx: 0, bytes_rx: 0,
        first_seen: now, last_active: now, closed: 0,
        classification: cls,
      };
      conns.set(sk, c);
      /* If the missed-OPEN is mining, retroactively register */
      if (cls === "mining" || cls === "stratum") {
        const m = getMiner(c.pid, c.comm, cls);
        m.conn_count++;
        const p = getPool(c.family, c.daddr, c.dport);
        p.conn_count++;
        p.miners.add(minerKey(c.pid, c.comm));
        m.pools.add(addrToHexStr(c.daddr) + ":" + c.dport);
        if (m.mimicry) recordAlert(c.pid, c.comm, cls, m.mimicry,
                                   addrToHexStr(c.daddr), c.dport);
      }
      /* Always register destination for audit. */
      const dStub = getAllDest(c.family, c.daddr, c.dport, cls);
      dStub.conn_count++; dStub.last_seen = now;
    }
    c.bytes_tx += delta_tx;
    c.bytes_rx += delta_rx;
    c.last_active = now;

    tickTotalTx += delta_tx; tickTotalRx += delta_rx;
    tot.bytes_tx_total += delta_tx; tot.bytes_rx_total += delta_rx;

    /* Track every destination's bandwidth for audit mode. */
    const d = getAllDest(c.family, c.daddr, c.dport, c.classification);
    d.bytes_tx += delta_tx; d.bytes_rx += delta_rx; d.last_seen = now;

    if (c.classification === "mining" || c.classification === "stratum") {
      tickMiningTx += delta_tx; tickMiningRx += delta_rx;
      tot.bytes_tx_mining += delta_tx; tot.bytes_rx_mining += delta_rx;

      const m = getMiner(c.pid, c.comm, c.classification);
      m.bytes_tx += delta_tx; m.bytes_rx += delta_rx; m.last_seen = now;
      const p = getPool(c.family, c.daddr, c.dport);
      p.bytes_tx += delta_tx; p.bytes_rx += delta_rx; p.last_seen = now;

      if (m.mimicry) {
        const a = alerts.get(minerKey(c.pid, c.comm));
        if (a) { a.bytes_tx += delta_tx; a.bytes_rx += delta_rx; a.last_seen = now; }
      }
    }
    return;
  }

  if (kind === 2) {
    let c = conns.get(sk);
    if (c) {
      tot.closes++;
      /* final delta from kernel cumulative we may have missed */
      const extraTx = Math.max(0, bytes_tx - c.bytes_tx);
      const extraRx = Math.max(0, bytes_rx - c.bytes_rx);
      if (extraTx + extraRx > 0) {
        c.bytes_tx += extraTx; c.bytes_rx += extraRx;
        tickTotalTx += extraTx; tickTotalRx += extraRx;
        tot.bytes_tx_total += extraTx; tot.bytes_rx_total += extraRx;
        if (c.classification === "mining" || c.classification === "stratum") {
          tickMiningTx += extraTx; tickMiningRx += extraRx;
          tot.bytes_tx_mining += extraTx; tot.bytes_rx_mining += extraRx;
          const m = getMiner(c.pid, c.comm, c.classification);
          m.bytes_tx += extraTx; m.bytes_rx += extraRx; m.last_seen = now;
          const p = getPool(c.family, c.daddr, c.dport);
          p.bytes_tx += extraTx; p.bytes_rx += extraRx; p.last_seen = now;
          /* Also update the alert's byte counters if one was raised
           * for this miner — without this, alerts under-report bytes
           * that arrived only at the close-time reconciliation. */
          if (m.mimicry) {
            const a = alerts.get(minerKey(c.pid, c.comm));
            if (a) {
              a.bytes_tx += extraTx; a.bytes_rx += extraRx;
              a.last_seen = now;
            }
          }
        }
      }
      c.closed = now;
      pushFeed({
        ts: now, kind: "close", sk,
        family: c.family,
        saddr: c.saddr, sport: c.sport,
        daddr: c.daddr, dport: c.dport,
        pid: c.pid, comm: c.comm,
        bytes_tx: c.bytes_tx, bytes_rx: c.bytes_rx,
        classification: c.classification,
        duration_ms: now - c.first_seen,
      });
    }
    return;
  }
}

/* ---- per-tick advance + reaping ----------------------------------- */
export function advance() {
  const now = Date.now();

  pushHist(miningTxHist, tickMiningTx); tickMiningTx = 0;
  pushHist(miningRxHist, tickMiningRx); tickMiningRx = 0;
  pushHist(totalTxHist,  tickTotalTx);  tickTotalTx  = 0;
  pushHist(totalRxHist,  tickTotalRx);  tickTotalRx  = 0;
  pushHist(opensHist,    tickOpens);    tickOpens    = 0;

  let active = 0;
  for (const c of conns.values()) if (!c.closed) active++;
  pushHist(activeHist, active);

  /* per-miner / per-pool rate history (delta-from-prev-tick) */
  for (const m of miners.values()) {
    const lastTx = m._lastTx ?? m.bytes_tx;
    const lastRx = m._lastRx ?? m.bytes_rx;
    pushHist(m.tx_rate_hist, m.bytes_tx - lastTx);
    pushHist(m.rx_rate_hist, m.bytes_rx - lastRx);
    m._lastTx = m.bytes_tx; m._lastRx = m.bytes_rx;
  }
  for (const p of pools.values()) {
    const lastTx = p._lastTx ?? p.bytes_tx;
    const lastRx = p._lastRx ?? p.bytes_rx;
    pushHist(p.tx_rate_hist, p.bytes_tx - lastTx);
    pushHist(p.rx_rate_hist, p.bytes_rx - lastRx);
    p._lastTx = p.bytes_tx; p._lastRx = p.bytes_rx;
  }

  /* reaping */
  for (const [sk, c] of conns) {
    if (c.closed && now - c.closed > CLOSE_FADE_MS) conns.delete(sk);
  }
  for (const [k, m] of miners) if (now - m.last_seen > PROC_STALE_MS) miners.delete(k);
  for (const [k, p] of pools)  if (now - p.last_seen > POOL_STALE_MS) pools.delete(k);

  while (feed.length && now - feed[0].ts > 60_000) feed.shift();
}

/* ---- accessors ---------------------------------------------------- */
const oneSecTicks = Math.max(1, Math.round(1000 / TICK_MS));
function sumTail(arr, n) {
  const start = Math.max(0, arr.length - n);
  let s = 0;
  for (let i = start; i < arr.length; i++) s += arr[i];
  return s;
}

export function liveRates() {
  return {
    total_tx_bps:  sumTail(totalTxHist,  oneSecTicks),
    total_rx_bps:  sumTail(totalRxHist,  oneSecTicks),
    mining_tx_bps: sumTail(miningTxHist, oneSecTicks),
    mining_rx_bps: sumTail(miningRxHist, oneSecTicks),
    active:        activeHist.length ? activeHist[activeHist.length - 1] : 0,
  };
}

export function listMiners(n) {
  const out = [];
  for (const m of miners.values()) {
    const tx = sumTail(m.tx_rate_hist, oneSecTicks);
    const rx = sumTail(m.rx_rate_hist, oneSecTicks);
    out.push({ m, tx_bps: tx, rx_bps: rx, total: tx + rx });
  }
  /* "critical" mimicry sorted first, then "suspicious", then by current bandwidth */
  const mimicryRank = (mim) => mim === "critical" ? 0 : mim === "suspicious" ? 1 : 2;
  out.sort((a, b) => {
    const ra = mimicryRank(a.m.mimicry), rb = mimicryRank(b.m.mimicry);
    if (ra !== rb) return ra - rb;
    return b.total - a.total;
  });
  return out.slice(0, n);
}

export function listPools(n) {
  const out = [];
  for (const p of pools.values()) {
    const tx = sumTail(p.tx_rate_hist, oneSecTicks);
    const rx = sumTail(p.rx_rate_hist, oneSecTicks);
    out.push({ p, tx_bps: tx, rx_bps: rx, total: tx + rx });
  }
  out.sort((a, b) => b.total - a.total);
  return out.slice(0, n);
}

export function listAlerts(n) {
  const out = Array.from(alerts.values());
  /* critical first, then by recency */
  out.sort((a, b) => {
    if (a.level !== b.level) return a.level === "critical" ? -1 : 1;
    return b.last_seen - a.last_seen;
  });
  return out.slice(0, n);
}

export function recentEvents(n) { return feed.slice(-n).reverse(); }

export function counts() {
  let critical = 0, suspicious = 0;
  for (const a of alerts.values()) {
    if (a.level === "critical") critical++; else suspicious++;
  }
  return {
    miners: miners.size,
    pools:  pools.size,
    critical_alerts: critical,
    suspicious_alerts: suspicious,
  };
}

/* ==================================================================== */
/* Audit mode accessor                                                  */
/* ==================================================================== */

/* Structured snapshot for audit reports. Pure data. audit.js handles
 * formatting. Fields: scan_duration_ms, total_events, total_opens,
 * total_closes, total_bytes_tx/rx, mining_bytes_tx/rx,
 * distinct_destinations, {mining_pool,stratum_likely,crypto_p2p}_hits,
 * miners[], pools[], alerts[], top_destinations[],
 * critical_alerts, suspicious_alerts, verdict. */
export function auditSnapshot() {
  const now = Date.now();

  let mining_pool_hits = 0;
  let stratum_likely_hits = 0;
  let crypto_p2p_hits = 0;
  for (const d of allDests.values()) {
    if (d.classification === "mining")     mining_pool_hits++;
    else if (d.classification === "stratum")    stratum_likely_hits++;
    else if (d.classification === "crypto-p2p") crypto_p2p_hits++;
  }

  /* Top destinations by total bandwidth across the scan window. */
  const dests = [];
  for (const d of allDests.values()) {
    dests.push({
      family: d.family,
      addr: d.addr,
      port: d.port,
      classification: d.classification,
      bytes_tx: d.bytes_tx,
      bytes_rx: d.bytes_rx,
      total_bytes: d.bytes_tx + d.bytes_rx,
      conn_count: d.conn_count,
    });
  }
  dests.sort((a, b) => b.total_bytes - a.total_bytes);

  /* Aggregate miners + alerts + pools — copy what audit.js needs.
   * We intentionally don't expose internal Maps; the snapshot is a
   * one-shot read meant for printing. */
  const minerList = [];
  for (const m of miners.values()) {
    minerList.push({
      pid: m.pid,
      comm: m.comm,
      classification: m.classification,
      bytes_tx: m.bytes_tx,
      bytes_rx: m.bytes_rx,
      conn_count: m.conn_count,
      pool_count: m.pools.size,
      mimicry: m.mimicry,
      first_seen: m.first_seen,
      last_seen: m.last_seen,
    });
  }

  const poolList = [];
  for (const p of pools.values()) {
    poolList.push({
      family: p.family,
      addr: p.addr,
      port: p.port,
      classification: p.classification,
      info: p.info,
      bytes_tx: p.bytes_tx,
      bytes_rx: p.bytes_rx,
      conn_count: p.conn_count,
      miner_count: p.miners.size,
      first_seen: p.first_seen,
      last_seen: p.last_seen,
    });
  }

  const alertList = [];
  let critical = 0, suspicious = 0;
  for (const a of alerts.values()) {
    alertList.push({
      pid: a.pid,
      comm: a.comm,
      level: a.level,
      classification: a.classification,
      pool_addr: a.pool_addr,
      pool_port: a.pool_port,
      conn_count: a.conn_count,
      bytes_tx: a.bytes_tx,
      bytes_rx: a.bytes_rx,
      first_seen: a.first_seen,
      last_seen: a.last_seen,
    });
    if (a.level === "critical") critical++; else suspicious++;
  }
  alertList.sort((a, b) => {
    /* critical first, then by recency */
    if (a.level !== b.level) return a.level === "critical" ? -1 : 1;
    return b.last_seen - a.last_seen;
  });

  /* Verdict ladder. The order matters — most severe wins. */
  let verdict;
  if (critical > 0)              verdict = "CRITICAL";
  else if (minerList.length > 0) verdict = "MINING";
  else if (suspicious > 0)       verdict = "SUSPICIOUS";
  else                           verdict = "CLEAN";

  return {
    scan_duration_ms: now - startTime,
    started_at: startTime,
    total_events: tot.events,
    total_opens: tot.opens,
    total_closes: tot.closes,
    total_bytes_tx: tot.bytes_tx_total,
    total_bytes_rx: tot.bytes_rx_total,
    mining_bytes_tx: tot.bytes_tx_mining,
    mining_bytes_rx: tot.bytes_rx_mining,
    distinct_destinations: allDests.size,
    mining_pool_hits,
    stratum_likely_hits,
    crypto_p2p_hits,
    miners: minerList,
    pools: poolList,
    alerts: alertList,
    top_destinations: dests.slice(0, 20),
    critical_alerts: critical,
    suspicious_alerts: suspicious,
    verdict,
  };
}
