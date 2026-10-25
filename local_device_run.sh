#!/usr/bin/env bash
# local_device_run.sh — Frida gadget analysis on unrooted Android device
#
# Prerequisites:
#   pip3 install objection frida-tools
#   adb in PATH  (brew install android-platform-tools  OR  Android SDK platform-tools)
#
# Usage:
#   ./local_device_run.sh                               # use default APK URL
#   ./local_device_run.sh /path/to/app.apk              # local APK file
#   ./local_device_run.sh https://example.com/app.apk   # download URL
#   ./local_device_run.sh <apk> <package_name> <seconds>

set -euo pipefail

DEFAULT_APK_URL="https://drive.usercontent.google.com/download?id=1mPZsjY0frTZlpLFMU9nc2RAZ559mmvBZ&export=download&confirm=t"
APK_INPUT="${1:-$DEFAULT_APK_URL}"
PKG="${2:-com.zhiliaoapp.musically.go}"
DURATION="${3:-180}"
JS="$(dirname "$0")/frida_scripts/android_http.js"
OUT="$(dirname "$0")/out"

log()  { echo "[device] $*"; }
err()  { echo "[device] ERROR: $*" >&2; exit 1; }

mkdir -p apk "$OUT"

# ────────────────────────────────────────────────────── prerequisites
log "Checking prerequisites..."

command -v adb  &>/dev/null || err "adb not found. Install: brew install android-platform-tools"
command -v python3 &>/dev/null || err "python3 not found"

if ! command -v objection &>/dev/null; then
  log "Installing objection + frida-tools..."
  pip3 install -q objection frida-tools
fi
if ! command -v frida &>/dev/null; then
  pip3 install -q frida-tools
fi

# ────────────────────────────────────────────────────── device check
log "Checking ADB device..."
DEVICE_COUNT=$(adb devices | grep -c 'device$' || true)
[[ "$DEVICE_COUNT" -ge 1 ]] || err "No ADB device found. Connect phone via USB and allow USB debugging."
log "Device found (${DEVICE_COUNT} device(s))"

# ────────────────────────────────────────────────────── get APK
if [[ -f apk/orig.apk ]]; then
  log "Reusing cached apk/orig.apk"
elif [[ "$APK_INPUT" == http* ]]; then
  log "Downloading APK from URL..."
  curl -fL --retry 3 --retry-delay 3 -o apk/orig.apk "$APK_INPUT"
  log "Downloaded: $(wc -c < apk/orig.apk | tr -d ' ') bytes"
elif [[ -f "$APK_INPUT" ]]; then
  log "Using local file: $APK_INPUT"
  cp "$APK_INPUT" apk/orig.apk
else
  err "APK not found: $APK_INPUT"
fi

# ────────────────────────────────────────────────────── patch APK with gadget
if [[ -f apk/patched.apk ]]; then
  log "Reusing cached apk/patched.apk"
else
  log "Injecting Frida gadget (arm64) into APK..."
  objection patchapk -s apk/orig.apk -a arm64 -o apk/patched.apk
  log "Gadget injection done"
fi

# ────────────────────────────────────────────────────── install
log "Installing patched APK on device..."
# Force-stop existing instance first to avoid signature conflict prompts
adb shell am force-stop "$PKG" 2>/dev/null || true
if ! adb install -r -g -t apk/patched.apk 2>&1 | tee "$OUT/install.log" | grep -q '^Success'; then
  # If signature mismatch, uninstall original first
  log "Signature conflict — uninstalling original app first"
  adb uninstall "$PKG" 2>/dev/null || true
  adb install -r -g -t apk/patched.apk 2>&1 | tee -a "$OUT/install.log" | grep -q '^Success' \
    || err "Install failed. Check $OUT/install.log"
fi
log "Install succeeded"

# ────────────────────────────────────────────────────── launch + hook
log "Launching $PKG (app will FREEZE — that's normal, waiting for Frida)"
adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
sleep 2

echo ""
echo "┌─────────────────────────────────────────────────────┐"
echo "│ Frida attached. App will resume.                    │"
echo "│                                                    │"
echo "│ On the phone, navigate to:                        │"
echo "│   Profile → Invite Friends                        │"
echo "│                                                    │"
echo "│ Hooks watching for:                               │"
echo "│   [AF] logInvite       <- fires when you tap share │"
echo "│   [AF] onAttribution   <- fires on referral click  │"
echo "│                                                    │"
echo "│ Capturing for ${DURATION}s. Ctrl+C to stop early.       │"
echo "└─────────────────────────────────────────────────────┘"
echo ""

frida -U -l "$JS" Gadget --runtime=v8 \
  2>&1 | timeout "$DURATION" cat > "$OUT/frida_output.txt" || true

# ────────────────────────────────────────────────────── results
echo ""
grep -oE 'https?://[^[:space:]"'"'"'<>]+' "$OUT/frida_output.txt" \
  | sort -u > "$OUT/urls.txt" 2>/dev/null || true

FLINES=$(wc -l < "$OUT/frida_output.txt" 2>/dev/null || echo 0)
URLINES=$(wc -l < "$OUT/urls.txt" 2>/dev/null || echo 0)

log "Done: ${FLINES} frida lines, ${URLINES} URLs"
log "Output: $OUT/frida_output.txt"
echo ""
log "── AF invite events ──"
grep '\[AF\]' "$OUT/frida_output.txt" || log "(none captured)"
echo ""
log "── AF attribution events ──"
grep 'onAttributionDataReceived\|u_code' "$OUT/frida_output.txt" || log "(none captured)"
