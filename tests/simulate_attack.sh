#!/usr/bin/env bash
# simulate_attack.sh
#
# Reproduces the Kinsing-style attack pattern for testing poolnarc:
#  1. Fake mining pool listener on 127.0.0.1:14444 (Monero default)
#  2. Python process renames itself to "kworker/u4:2" via prctl(PR_SET_NAME)
#  3. The spoofed process pumps Stratum-shaped traffic at the pool
#
# Run poolnarc first:
#     yeet run main.js
# Then this. Within ~2 seconds the HIDDEN MINER ALERTS panel turns red.
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
start_listener() {
  if command -v nc >/dev/null 2>&1; then
    # The -k flag (keep-open) varies between netcat flavors. Use a loop
    # so we re-listen after each client disconnect.
    ( while true; do
        nc -l -p "$PORT" -q 1 > /dev/null 2>&1 || true
      done ) &
  else
    python3 -c "
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $PORT)); s.listen(8)
while True:
    try:
        c, _ = s.accept()
        # drain forever; we don't reply, we just absorb
        while True:
            d = c.recv(4096)
            if not d: break
    except KeyboardInterrupt: break
    except Exception: pass
" &
  fi
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
import socket, ctypes, time, sys
ctypes.CDLL('libc.so.6').prctl(15, b'kworker/u4:2', 0, 0, 0)
print('  [client]   comm spoofed to kworker/u4:2 (pid', __import__('os').getpid(), ')', file=sys.stderr, flush=True)
while True:
    try:
        s = socket.socket()
        s.connect(('127.0.0.1', $PORT))
        # Fake Stratum 'subscribe' message — the real protocol shape
        # malware would use. Doesn't matter that the listener doesn't
        # respond; poolnarc is observing the connection + bytes only.
        for _ in range(30):
            s.send(b'{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"mining.subscribe\",\"params\":[]}\n')
            time.sleep(0.1)
        s.close()
        time.sleep(0.4)
    except KeyboardInterrupt:
        break
    except Exception as e:
        time.sleep(0.5)
"
