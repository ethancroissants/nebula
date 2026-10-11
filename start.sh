#!/usr/bin/env bash
# ==============================================================================
#  start.sh  --  run your app and get a public URL (via Cloudflare Tunnel)
#
#  SparkCloud spaces do NOT expose web ports to the internet directly, so to view
#  a web app you run it here and tunnel it out. This script starts your app, opens
#  a FREE Cloudflare "quick tunnel" to it, and prints a public
#  https://<something>.trycloudflare.com URL. Press Ctrl-C to stop -- it shuts down
#  both your app and the tunnel automatically.
#
#  >>> Easiest: ask Sparky  ->  "configure start.sh for my app"
#  >>> Or do it yourself: set PORT and APP_CMD below (uncomment one example), save,
#      then run:   ./start.sh        (first time:  chmod +x start.sh && ./start.sh)
# ==============================================================================

# ----- 1) CONFIGURE YOUR APP -- uncomment these two and edit -------------------
# PORT=3000
# APP_CMD="npm start"

# ----- Examples by stack (copy one up to the two lines above, then tweak) ------
#   Node / Express:            PORT=3000 ; APP_CMD="node server.js"
#   npm script:                PORT=3000 ; APP_CMD="npm start"
#   Vite / React (dev):        PORT=5173 ; APP_CMD="npm run dev -- --host 0.0.0.0 --port 5173"
#   SvelteKit (dev):           PORT=5173 ; APP_CMD="npm run dev -- --host 0.0.0.0 --port 5173"
#   SvelteKit (adapter-node):  PORT=3000 ; APP_CMD="node build"          # after: npm run build
#   Next.js (dev):             PORT=3000 ; APP_CMD="npm run dev -- -p 3000"
#   Astro (dev):               PORT=4321 ; APP_CMD="npm run dev -- --host 0.0.0.0 --port 4321"
#   Flask:                     PORT=5000 ; APP_CMD="flask --app app run --host 0.0.0.0 --port 5000"
#   Django:                    PORT=8000 ; APP_CMD="python manage.py runserver 0.0.0.0:8000"
#   FastAPI / uvicorn:         PORT=8000 ; APP_CMD="uvicorn main:app --host 0.0.0.0 --port 8000"
#   Static folder:             PORT=8080 ; APP_CMD="python3 -m http.server 8080"
#   Go:                        PORT=8080 ; APP_CMD="go run ."
#   Ruby / Rails:              PORT=3000 ; APP_CMD="bin/rails server -b 0.0.0.0 -p 3000"
#   PHP:                       PORT=8000 ; APP_CMD="php -S 0.0.0.0:8000"
#
#  Tip: your app MUST listen on 0.0.0.0 (not just 127.0.0.1) and on $PORT.
#
#  ALLOW ALL HOSTS (read this if you see "Blocked request. This host is not allowed.")
#  Dev servers reject requests whose Host header they don't recognise, so the public tunnel
#  domain (*.trycloudflare.com) gets blocked. Allow ALL hosts in your app's config:
#     • Vite (vite.config.js):   server: { host: true, allowedHosts: true }
#     • Next.js (dev):           next dev -H 0.0.0.0   (Next 14+: experimental.allowedDevOrigins)
#     • Nuxt:                    set NITRO_HOST=0.0.0.0 / vite.server.allowedHosts: true
#     • webpack / CRA:           devServer.allowedHosts: 'all'  (or DANGEROUSLY_DISABLE_HOST_CHECK=true)
#     • Most servers/APIs:       no change needed — they don't host-check.
#  >>> Or just ask Sparky: "allow all hosts so my app works through the tunnel".
#  (As a fallback this script also rewrites the tunnel's Host header to localhost, but setting
#   allowedHosts in your config is the reliable fix — especially for live reload / HMR.)
# ------------------------------------------------------------------------------

set -uo pipefail

if [ -z "${PORT:-}" ] || [ -z "${APP_CMD:-}" ]; then
  cat <<'MSG'
start.sh isn't configured yet.

Open start.sh and set PORT + APP_CMD (uncomment one of the examples near the top)
to match your app -- or just ask Sparky: "configure start.sh for my app".

Then run:   ./start.sh
MSG
  exit 1
fi

# Reach the app from any host through the tunnel. The Cloudflare --http-host-header below is the
# primary, framework-agnostic mechanism; these env vars additionally relax host checks for dev
# servers that read them (Create React App / webpack-dev-server). Harmless to frameworks that ignore
# them. (This governs dev-server HOST allow-listing; true CORS response headers are app-level.)
export DANGEROUSLY_DISABLE_HOST_CHECK=true

APP_PID=""
TUNNEL_PID=""
TUNNEL_LOG="$(mktemp)"

cleanup() {
  echo ""
  echo "==> Stopping app + tunnel..."
  [ -n "$TUNNEL_PID" ] && kill "$TUNNEL_PID" 2>/dev/null
  [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null
  pkill -P $$ 2>/dev/null
  rm -f "$TUNNEL_LOG" 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "==> Starting your app:  $APP_CMD"
bash -c "$APP_CMD" &
APP_PID=$!

# One clear status line. The app boot and the tunnel handshake happen together in the background
# (~10-15s); we print the live URL the moment it's ready, rather than a misleading "waiting on
# port" message (which is also confusing when a dev server hops to a different port if $PORT is busy).
echo "==> Loading your public link…  (starting the app and opening a secure tunnel, ~10-15s)"
for _ in $(seq 1 40); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then exec 3>&-; break; fi
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    echo "ERROR: your app exited before binding port $PORT. Check APP_CMD and the logs above."
    exit 1
  fi
  sleep 1
done

# --http-host-header rewrites the Host the app sees to localhost:$PORT, so the app is reachable from
# ANY host through the public *.trycloudflare.com tunnel. Without it, dev servers that validate the
# Host header reject the tunnel hostname ("Blocked request. This host is not allowed." — Vite,
# webpack, Next). This is the framework-agnostic way to allow all hosts.
cloudflared tunnel --no-autoupdate --url "http://localhost:$PORT" --http-host-header "localhost:$PORT" >"$TUNNEL_LOG" 2>&1 &
TUNNEL_PID=$!

URL=""
for _ in $(seq 1 40); do
  URL="$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$TUNNEL_LOG" | head -n1)"
  [ -n "$URL" ] && break
  sleep 1
done

echo ""
if [ -n "$URL" ]; then
  echo "============================================================"
  echo "  Your app is live at:   $URL"
  echo "============================================================"
  echo "  Press Ctrl-C to stop the app and tear down the tunnel."
else
  echo "WARNING: couldn't read a tunnel URL yet. Recent tunnel output:"
  tail -n 20 "$TUNNEL_LOG"
fi
echo ""

# Run until the app exits (or Ctrl-C triggers cleanup).
wait "$APP_PID"
