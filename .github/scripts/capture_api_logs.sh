#!/usr/bin/env bash
# Runs on the CI host while the emulator is up (called from android-emulator-runner).
# Env: APK_URL, PACKAGE_NAME, DURATION (sec), OUT_DIR
set -uo pipefail

OUT_DIR="${OUT_DIR:-out}"
APK_URL="${APK_URL:-}"
APK_PATH="${APK_PATH:-}"
PKG="${PACKAGE_NAME:-}"
DURATION="${DURATION:-60}"
[[ "$DURATION" =~ ^[0-9]+$ ]] || DURATION=60

# lowercase ERE, matched against tolower(line)
KEYWORDS='https?://|okhttp|retrofit|volley|cronet|grpc|websocket|graphql|httpurlconnection|http|api|url|json|connect|socket|ssl|tls|dns|hostname|request|response|endpoint|header|bearer|token'
# system tags that match KEYWORDS but say nothing about the app (only applied to non-app lines)
NOISE_TAGS='connectivity|networkmonitor|wifi|netd|dnsresolver|conscrypt|telephony|systemui|inputmethod|gms|vending|chatty|audio|surfaceflinger|netstats|nsd|ethernet|vpn|tethering'

log() { echo "[capture] $*"; }

adb_sh() { adb shell "$@" | tr -d '\r'; }

# ---------------------------------------------------------------- filtering
# filter_logs <full_logcat> <pid_file> <out_all> <out_strict>
#   out_all    : every line from the app's PIDs, plus keyword lines from other procs (minus noise tags)
#   out_strict : keyword lines from the app's PIDs only
# logcat -v threadtime: "MM-DD HH:MM:SS.mmm  PID  TID L TAG: msg" -> $3=PID, $6=TAG
filter_logs() {
  local full="$1" pidfile="$2" out_all="$3" out_strict="$4"
  : > "$out_all"; : > "$out_strict"
  [[ -s "$full" ]] || return 0
  awk -v pidfile="$pidfile" -v kw="$KEYWORDS" -v noise="$NOISE_TAGS" \
      -v out_all="$out_all" -v out_strict="$out_strict" '
    BEGIN { while ((getline p < pidfile) > 0) pids[p] = 1 }
    $3 ~ /^[0-9]+$/ {
      isapp = ($3 in pids)
      low = tolower($0)
      hit = (low ~ kw)
      if (isapp) {
        print >> out_all
        if (hit) print >> out_strict
      } else if (hit && tolower($6) !~ noise) {
        print >> out_all
      }
    }' "$full"
}

# ---------------------------------------------------------------- app helpers
collect_pids() {
  # all processes whose name contains the package (main + :service/:remote)
  adb_sh ps -A -o PID,NAME | awk -v p="$PKG" 'index($2, p) == 1 { print $1 }' >> "$OUT_DIR/app_pids.raw"
  sort -un "$OUT_DIR/app_pids.raw" > "$OUT_DIR/app_pids.txt"
}

app_alive() { [[ -n "$(adb_sh pidof "$PKG")" ]]; }

launch_app() {
  adb_sh monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >> "$OUT_DIR/monkey.log" 2>&1 || true
}

resolve_apk() {
  mkdir -p apk
  if [[ -n "$APK_PATH" ]]; then
    [[ "$APK_PATH" != /* && "$APK_PATH" != *..* && -f "$APK_PATH" ]] || { log "apk_path not found in checkout: $APK_PATH"; return 1; }
    log "using repo file $APK_PATH"
    cp "$APK_PATH" apk/target.apk
    return 0
  fi
  if [[ -n "$APK_URL" ]]; then
    log "downloading $APK_URL"
    curl -fL --retry 3 --retry-delay 2 -o apk/target.apk "$APK_URL" || { log "download failed"; return 1; }
    return 0
  fi
  if [[ -n "$PKG" ]]; then
    # no URL: fall back to F-Droid (open-source apps only)
    log "no apk_url, trying F-Droid for $PKG"
    local vc
    vc=$(curl -fsSL "https://f-droid.org/api/v1/packages/$PKG" \
         | python3 -c 'import sys,json; print(json.load(sys.stdin)["suggestedVersionCode"])' 2>/dev/null) || true
    if [[ -n "${vc:-}" ]]; then
      curl -fL --retry 3 -o apk/target.apk "https://f-droid.org/repo/${PKG}_${vc}.apk" && return 0
    fi
    # last resort: maybe it's already on the image
    if adb_sh pm list packages | grep -qx "package:$PKG"; then
      log "$PKG already installed on image"
      return 2
    fi
    log "no APK source for $PKG (not on F-Droid, not preinstalled) - pass apk_url"
    return 1
  fi
  log "need apk_path, apk_url or package_name"
  return 1
}

install_apk() {
  local f=apk/target.apk res
  # Try direct install first — handles plain APK regardless of internal layout
  res=$(adb install -r -g -t "$f" 2>&1)
  if grep -q '^Success' <<<"$res"; then
    echo "$res" | tee "$OUT_DIR/install.log"
    return 0
  fi
  log "direct install failed: $(echo "$res" | tail -1)"
  # Fall back: unzip bundle and install-multiple splits (.apk or .apks)
  log "trying bundle install"
  mkdir -p apk/splits && unzip -qo "$f" -d apk/splits 2>/dev/null || true
  log "bundle contents: $(find apk/splits -type f | head -20 | tr '\n' ' ')"
  mapfile -t splits < <(find apk/splits \( -name '*.apk' -o -name '*.apks' \) | sort)
  if [[ ${#splits[@]} -eq 0 ]]; then
    log "no .apk/.apks inside bundle"
    echo "$res" | tee "$OUT_DIR/install.log"
    return 1
  fi
  res=$(adb install-multiple -r -g -t "${splits[@]}" 2>&1)
  echo "$res" | tee "$OUT_DIR/install.log"
  grep -q '^Success' <<<"$res"
}

# ---------------------------------------------------------------- main
main() {
  mkdir -p "$OUT_DIR"
  : > "$OUT_DIR/monkey.log"; : > "$OUT_DIR/app_pids.raw"

  adb wait-for-device
  adb_sh settings put global package_verifier_enable 0 || true
  adb_sh settings put global verifier_verify_adb_installs 0 || true

  local rc=0
  resolve_apk || rc=$?
  if [[ $rc -eq 1 ]]; then exit 1; fi

  if [[ $rc -eq 0 ]]; then
    local before after
    before=$(adb_sh pm list packages -3 | sort)
    install_apk || { log "install failed"; exit 1; }
    if [[ -z "$PKG" ]]; then
      after=$(adb_sh pm list packages -3 | sort)
      PKG=$(comm -13 <(echo "$before") <(echo "$after") | head -1 | sed 's/^package://')
      [[ -n "$PKG" ]] || { log "could not detect package name, pass package_name"; exit 1; }
    fi
  fi
  log "target package: $PKG"

  {
    echo "package=$PKG"
    echo "versionName=$(adb_sh dumpsys package "$PKG" | grep -m1 versionName | sed 's/^ *//')"
    echo "android=$(adb_sh getprop ro.build.version.release) sdk=$(adb_sh getprop ro.build.version.sdk) abi=$(adb_sh getprop ro.product.cpu.abi)"
    [[ -f apk/target.apk ]] && echo "sha256=$(shasum -a 256 apk/target.apk | cut -d' ' -f1)"
    echo "apk_url=$APK_URL"
    echo "apk_path=$APK_PATH"
    echo "duration_sec=$DURATION"
    echo "date_utc=$(date -u +%FT%TZ)"
  } > "$OUT_DIR/meta.txt"

  adb logcat -b all -c
  adb logcat -b all -v threadtime > "$OUT_DIR/logcat_full.txt" 2>/dev/null &
  local lc_pid=$!
  trap 'kill "$lc_pid" 2>/dev/null || true' EXIT

  log "launching, capturing ${DURATION}s"
  launch_app
  sleep 8   # let the app finish cold start / first requests

  local end=$((SECONDS + DURATION))
  while (( SECONDS < end )); do
    collect_pids
    app_alive || { log "app not running, relaunch"; launch_app; sleep 3; }
    adb_sh monkey -p "$PKG" --throttle 400 --pct-syskeys 0 --pct-appswitch 0 --pct-nav 0 \
      --ignore-crashes --ignore-timeouts --ignore-security-exceptions \
      -s "$RANDOM" 25 >> "$OUT_DIR/monkey.log" 2>&1 || true
  done
  collect_pids
  sleep 2

  kill "$lc_pid" 2>/dev/null || true
  wait "$lc_pid" 2>/dev/null || true
  trap - EXIT

  filter_logs "$OUT_DIR/logcat_full.txt" "$OUT_DIR/app_pids.txt" \
              "$OUT_DIR/api_logs.txt" "$OUT_DIR/api_logs_strict.txt"

  grep -aoE "https?://[^[:space:]\"'<>]+" "$OUT_DIR/api_logs.txt" | sort -u > "$OUT_DIR/urls.txt" || true

  log "pids: $(tr '\n' ' ' < "$OUT_DIR/app_pids.txt")"
  log "full=$(wc -l < "$OUT_DIR/logcat_full.txt") api_logs=$(wc -l < "$OUT_DIR/api_logs.txt") strict=$(wc -l < "$OUT_DIR/api_logs_strict.txt") urls=$(wc -l < "$OUT_DIR/urls.txt")"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
