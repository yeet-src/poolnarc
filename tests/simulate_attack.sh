#!/usr/bin/env bash
# simulate_attack.sh
#
# Reproduces the Kinsing-style attack pattern for testing poolnarc:
#  1. Fake mining pool listener on 127.0.0.1:14444 (Monero default)
#  2. Python process renames itself to "kworker/u4:2" via prctl(PR_SET_NAME)
#  3. The spoofed process pumps Stratum-shaped traffic at the pool
#
# Start poolnarc FIRST, then this. That order is required, not a
# convenience: poolnarc creates per-connection state on the
# TCP_ESTABLISHED transition, so a connection that is already open when
# the probe attaches is never tracked and the scan reports CLEAN.
#
#     yeet run main.js
#
# Within ~2 seconds the HIDDEN MINER ALERTS panel turns red.
#
# Audit equivalent:
#     yeet run main.js -- --audit --duration 15
#
# Ctrl-C to stop. Listener and client both die.

set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "simulate_attack.sh: python3 not found in PATH" >&2
  echo "  install python3 and try again" >&2
  exit 1
fi

PORT="${PORT:-14444}"

cleanup() {
  echo "" >&2
  echo "simulate_attack.sh: stopping..." >&2
  # kill all our background jobs
  jobs -p | xargs -r kill 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

echo "simulate_attack.sh — fake mining pool on 127.0.0.1:$PORT" >&2
echo "                    + kworker-spoofed client connecting in a loop" >&2
echo "" >&2

# ---- background: fake mining pool listener -------------------------------
# Tries nc first (universally available); falls back to a python listener
# if nc isn't installed.
# A threaded accept loop, not `nc -l`. netcat serves one connection at a
# time and re-listens between clients, which leaves a window where the
# client's reconnect is refused. Those connections die in SYN-SENT and
# never reach TCP_ESTABLISHED, which is the only state poolnarc creates
# tracking from, so the scan reports CLEAN while the simulator claims to
# be running. Accepting concurrently keeps the connection established.
start_listener() {
  python3 -c "
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $PORT)); s.listen(16)

def handle(c):
    try:
        while True:
            d = c.recv(4096)
            if not d: break
            # A real pool answers; replying keeps bytes moving both ways.
            c.sendall(b'{\"id\":1,\"result\":{\"job\":{\"blob\":\"ab\"}}}\n')
    except Exception: pass
    finally: c.close()

while True:
    try:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()
    except KeyboardInterrupt: break
    except Exception: pass
" &
  echo "  [listener] up on 127.0.0.1:$PORT (pid $!)" >&2
}

start_listener
sleep 0.3   # give the listener a moment to bind

# ---- foreground: kworker-spoofed client ----------------------------------
# prctl(PR_SET_NAME, "kworker/u4:2") makes /proc/<pid>/comm read "kworker/u4:2"
# — the same hiding technique used by the Kinsing malware family. poolnarc
# detects this in BPF because the kernel reports the spoofed comm via
# bpf_get_current_comm() in tcp_sendmsg, but the process is still
# observably opening TCP connections — something real kernel threads
# never do.
echo "  [client]   starting kworker-spoofed loop..." >&2
echo "  watch your poolnarc dashboard now." >&2
echo "  press Ctrl-C here to stop." >&2

python3 -c "
import socket, ctypes, time, sys, os
ctypes.CDLL('libc.so.6').prctl(15, b'kworker/u4:2', 0, 0, 0)
print('  [client]   comm spoofed to kworker/u4:2 (pid', os.getpid(), ')', file=sys.stderr, flush=True)

# Hold one long-lived connection rather than reconnecting in a loop. A real
# miner keeps its pool socket open, and a connection that opens and closes
# repeatedly races the listener. Reconnect only if the socket actually drops,
# and say so, rather than failing quietly into a CLEAN verdict.
def connect():
    s = socket.socket()
    s.connect(('127.0.0.1', $PORT))
    print('  [client]   established to 127.0.0.1:$PORT', file=sys.stderr, flush=True)
    return s

try:
    s = connect()
except Exception as e:
    print('  [client]   FAILED to connect:', e, file=sys.stderr, flush=True)
    print('  [client]   is the listener up? try: ss -tln | grep $PORT', file=sys.stderr, flush=True)
    sys.exit(1)

sub = b'{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"mining.subscribe\",\"params\":[]}\n'
while True:
    try:
        s.sendall(sub + b'x' * 4096)
        s.recv(4096)
        time.sleep(0.05)
    except KeyboardInterrupt:
        break
    except Exception as e:
        print('  [client]   connection dropped (', e, '), reconnecting', file=sys.stderr, flush=True)
        time.sleep(0.5)
        try: s = connect()
        except Exception: time.sleep(1)
"
