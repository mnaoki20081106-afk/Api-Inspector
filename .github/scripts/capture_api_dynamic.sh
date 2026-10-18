#!/usr/bin/env bash
# Runs on the CI host while the emulator is up (called from android-emulator-runner).
# Installs a mitmproxy CA as a user cert, points the device's HTTP(S) proxy at mitmdump,
# installs the target APK, launches + monkey-taps it, and (if frida-tools / frida-server
# are present) runs the passive Java-layer observer alongside.
#
# Env: APK_URL, APK_PATH, PACKAGE_NAME, DURATION (sec), OUT_DIR, USE_FRIDA (0/1)
set -uo pipefail

OUT_DIR="${OUT_DIR:-out}"
APK_URL="${APK_URL:-}"
APK_PATH="${APK_PATH:-}"
PKG="${PACKAGE_NAME:-}"
DURATION="${DURATION:-60}"
USE_FRIDA="${USE_FRIDA:-0}"
[[ "$DURATION" =~ ^[0-9]+$ ]] || DURATION=60
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DYNAMIC="$HERE/../../tools/dynamic"
PROXY_PORT=8080

log() { echo "[dynamic] $*"; }
adb_sh() { adb shell "$@" | tr -d '\r'; }

resolve_apk() {
  mkdir -p apk
  if [[ -n "$APK_PATH" ]]; then
    [[ "$APK_PATH" != /* && "$APK_PATH" != *..* && -f "$APK_PATH" ]] || { log "apk_path not found: $APK_PATH"; return 1; }
    cp "$APK_PATH" apk/target.bin; return 0
  fi
  if [[ -n "$APK_URL" ]]; then
    curl -fL --retry 3 --retry-delay 2 -o apk/target.bin "$APK_URL" || { log "download failed"; return 1; }
    return 0
  fi
  log "need apk_path or apk_url for dynamic capture"; return 1
}

install_apk() {
  local f=apk/target.bin res
  if unzip -l "$f" 2>/dev/null | grep -q ' AndroidManifest.xml$'; then
    res=$(adb install -r -g -t "$f" 2>&1)
  else
    mkdir -p apk/splits && unzip -qo "$f" -d apk/splits
    mapfile -t splits < <(find apk/splits -name '*.apk' | sort)
    [[ ${#splits[@]} -gt 0 ]] || { log "no .apk inside bundle"; return 1; }
    res=$(adb install-multiple -r -g -t "${splits[@]}" 2>&1)
  fi
  echo "$res" | tee "$OUT_DIR/install.log"
  grep -q '^Success' <<<"$res"
}

start_mitm() {
  log "starting mitmdump on :$PROXY_PORT"
  FLOWS_OUT="$OUT_DIR/flows.jsonl" BODY_LIMIT=4096 \
    mitmdump -q -s "$TOOLS_DYNAMIC/mitm_addon.py" -p "$PROXY_PORT" --set confdir="$OUT_DIR/.mitmproxy" \
    > "$OUT_DIR/mitmdump.log" 2>&1 &
  MITM_PID=$!
  # wait for the CA cert to materialize
  for _ in $(seq 1 20); do [[ -f "$OUT_DIR/.mitmproxy/mitmproxy-ca-cert.cer" ]] && break; sleep 0.5; done
}

install_ca_and_set_proxy() {
  local cer="$OUT_DIR/.mitmproxy/mitmproxy-ca-cert.cer"
  [[ -f "$cer" ]] || { log "mitmproxy CA cert not found, proxy will fail TLS for every host"; }
  if [[ -f "$cer" ]]; then
    # Android wants certs named by subject-hash-old.0 in /system/etc/security/cacerts (root) or
    # pushed as a user cert via Settings; emulator images let us remount /system on API<=28 /
    # or use the "adb install-cert"-style push for a user CA on newer ones. Try root push first.
    local hash
    hash=$(openssl x509 -inform DER -in "$cer" -subject_hash_old -noout 2>/dev/null | head -1) || hash=""
    openssl x509 -inform DER -in "$cer" -out "$OUT_DIR/mitm-ca.pem" 2>/dev/null
    if [[ -n "$hash" ]]; then
      adb root 2>/dev/null || true
      adb remount 2>/dev/null || true
      if adb_sh "test -w /system/etc/security/cacerts && echo ok" | grep -q ok; then
        adb push "$OUT_DIR/mitm-ca.pem" "/system/etc/security/cacerts/${hash}.0" && log "CA installed as system root ${hash}.0"
      else
        log "/system not writable, falling back to global proxy only (user-CA pinned apps will fail TLS - expected, reported as tls_fail)"
      fi
    fi
  fi
  adb_sh settings put global http_proxy "$(adb_sh ip route | awk '{print $9; exit}' 2>/dev/null || echo 10.0.2.2):$PROXY_PORT" 2>/dev/null || true
  adb shell settings put global http_proxy "10.0.2.2:$PROXY_PORT"
}

clear_proxy() { adb shell settings put global http_proxy :0; }

launch_and_tap() {
  adb_sh monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >> "$OUT_DIR/monkey.log" 2>&1 || true
  sleep 8
  local end=$((SECONDS + DURATION))
  while (( SECONDS < end )); do
    adb_sh pidof "$PKG" >/dev/null || { adb_sh monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >> "$OUT_DIR/monkey.log" 2>&1 || true; sleep 3; }
    adb_sh monkey -p "$PKG" --throttle 400 --pct-syskeys 0 --pct-appswitch 0 --pct-nav 0 \
      --ignore-crashes --ignore-timeouts --ignore-security-exceptions -s "$RANDOM" 25 >> "$OUT_DIR/monkey.log" 2>&1 || true
  done
}

run_frida() {
  [[ "$USE_FRIDA" == "1" ]] || return 0
  command -v python3 >/dev/null || return 0
  python3 -c 'import frida' 2>/dev/null || { log "frida-tools not installed, skipping java-layer observer"; return 0; }
  log "starting passive Frida observer for ${DURATION}s"
  python3 "$TOOLS_DYNAMIC/frida_run.py" "$PKG" "$DURATION" "$OUT_DIR/java_events.jsonl" > "$OUT_DIR/frida.log" 2>&1 &
  FRIDA_PID=$!
}

main() {
  mkdir -p "$OUT_DIR"
  : > "$OUT_DIR/monkey.log"
  : > "$OUT_DIR/flows.jsonl"
  adb wait-for-device
  adb_sh settings put global package_verifier_enable 0 || true
  adb_sh settings put global verifier_verify_adb_installs 0 || true

  resolve_apk || exit 1
  local before after
  before=$(adb_sh pm list packages -3 | sort)
  install_apk || { log "install failed"; exit 1; }
  if [[ -z "$PKG" ]]; then
    after=$(adb_sh pm list packages -3 | sort)
    PKG=$(comm -13 <(echo "$before") <(echo "$after") | head -1 | sed 's/^package://')
    [[ -n "$PKG" ]] || { log "could not detect package name, pass package_name"; exit 1; }
  fi
  log "target package: $PKG"

  start_mitm
  install_ca_and_set_proxy
  trap 'clear_proxy; kill "${MITM_PID:-0}" "${FRIDA_PID:-0}" 2>/dev/null || true' EXIT

  run_frida
  launch_and_tap

  sleep 2
  clear_proxy
  kill "$MITM_PID" 2>/dev/null || true; wait "$MITM_PID" 2>/dev/null || true
  [[ -n "${FRIDA_PID:-}" ]] && { wait "$FRIDA_PID" 2>/dev/null || true; }
  trap - EXIT

  {
    echo "package=$PKG"
    echo "versionName=$(adb_sh dumpsys package "$PKG" | grep -m1 versionName | sed 's/^ *//')"
    echo "android=$(adb_sh getprop ro.build.version.release) sdk=$(adb_sh getprop ro.build.version.sdk)"
    echo "duration_sec=$DURATION"
    echo "flows=$(wc -l < "$OUT_DIR/flows.jsonl" 2>/dev/null || echo 0)"
    echo "date_utc=$(date -u +%FT%TZ)"
  } > "$OUT_DIR/meta.txt"

  if [[ -s "$OUT_DIR/flows.jsonl" || -s "$OUT_DIR/java_events.jsonl" ]]; then
    python3 "$TOOLS_DYNAMIC/summarize_flows.py" "$OUT_DIR/flows.jsonl" \
      $( [[ -s "$OUT_DIR/java_events.jsonl" ]] && echo "$OUT_DIR/java_events.jsonl" ) \
      > "$OUT_DIR/summary.md" 2>"$OUT_DIR/summarize.err" || log "summarize_flows.py failed, see summarize.err"
  else
    echo "# no flows captured" > "$OUT_DIR/summary.md"
  fi
  log "done: flows=$(wc -l < "$OUT_DIR/flows.jsonl" 2>/dev/null) summary=$(wc -l < "$OUT_DIR/summary.md" 2>/dev/null)"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
