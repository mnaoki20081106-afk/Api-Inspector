#!/usr/bin/env bash
# Static APK analysis via jadx. No emulator required.
# Env: APK_URL, APK_PATH, PACKAGE_NAME, OUT_DIR
set -euo pipefail

OUT_DIR="${OUT_DIR:-out}"
APK_URL="${APK_URL:-}"
APK_PATH_IN="${APK_PATH:-}"
PKG="${PACKAGE_NAME:-}"

log() { echo "[static] $*"; }

# ---------------------------------------------------------------- download
resolve_apk() {
  mkdir -p apk
  if [[ -n "$APK_PATH_IN" ]]; then
    [[ -f "$APK_PATH_IN" ]] || { log "file not found: $APK_PATH_IN"; return 1; }
    cp "$APK_PATH_IN" apk/target.apk
    log "using repo file $APK_PATH_IN"
    return 0
  fi
  if [[ -n "$APK_URL" ]]; then
    log "downloading $APK_URL"
    curl -fL --retry 3 --retry-delay 3 -o apk/target.apk "$APK_URL" || { log "download failed"; return 1; }
    return 0
  fi
  if [[ -n "$PKG" ]]; then
    log "no url, trying F-Droid for $PKG"
    local vc
    vc=$(curl -fsSL "https://f-droid.org/api/v1/packages/$PKG" \
         | python3 -c 'import sys,json; print(json.load(sys.stdin)["suggestedVersionCode"])' 2>/dev/null) || true
    if [[ -n "${vc:-}" ]]; then
      curl -fL --retry 3 -o apk/target.apk "https://f-droid.org/repo/${PKG}_${vc}.apk" && return 0
    fi
  fi
  log "need apk_path, apk_url or package_name with F-Droid entry"
  return 1
}

# ---------------------------------------------------------------- jadx
install_jadx() {
  if command -v jadx &>/dev/null; then
    log "jadx already available: $(jadx --version 2>&1 | head -1)"
    return 0
  fi
  log "installing jadx 1.5.0"
  local url="https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip"
  curl -fL --retry 3 -o /tmp/jadx.zip "$url"
  unzip -q /tmp/jadx.zip -d /tmp/jadx-bin
  chmod +x /tmp/jadx-bin/bin/jadx
  export PATH="/tmp/jadx-bin/bin:$PATH"
  log "jadx installed: $(jadx --version 2>&1 | head -1)"
}

# ---------------------------------------------------------------- unzip xapk/bundle
prepare_apk() {
  local f=apk/target.apk
  log "apk size: $(wc -c < "$f") bytes"
  if unzip -l "$f" 2>/dev/null | grep -q "base.apk"; then
    log "bundle detected, extracting base.apk"
    unzip -qo "$f" "base.apk" -d apk/extracted 2>/dev/null || true
    if [[ -f apk/extracted/base.apk ]]; then
      cp apk/extracted/base.apk apk/base.apk
      f=apk/base.apk
      log "using base.apk for jadx"
    fi
  fi
  echo "$f"
}

# ---------------------------------------------------------------- search helpers
section() { echo; echo "=== $1 ==="; }

grep_ic() {
  grep -rn --include="*.java" -i "$1" "$JADX_OUT" 2>/dev/null | head -n "${2:-60}" || true
}

extract_urls() {
  grep -roh --include="*.java" 'https\?://[^"'"'"'[:space:]>]*' "$JADX_OUT" 2>/dev/null \
    | sort -u | grep -v '//schemas\|//www\.w3\|xmlns\|schema\.org\|android\.googlesource\|example\.com' || true
}

# ---------------------------------------------------------------- main
main() {
  mkdir -p "$OUT_DIR"

  resolve_apk
  install_jadx

  local apk_file
  apk_file=$(prepare_apk)

  SHA=$(sha256sum "$apk_file" | cut -d' ' -f1)
  log "decompiling $apk_file (sha256=$SHA)"

  JADX_OUT="$OUT_DIR/src"
  mkdir -p "$JADX_OUT"

  jadx --threads-count 4 --no-debug-info -d "$JADX_OUT" "$apk_file" 2>&1 \
    | tail -20 | tee "$OUT_DIR/jadx.log" || true

  log "decompile done — $(find "$JADX_OUT" -name '*.java' | wc -l) java files"

  if [[ -z "$PKG" ]]; then
    PKG=$(grep -roh 'package="[^"]*"' "$JADX_OUT/resources/AndroidManifest.xml" 2>/dev/null \
          | head -1 | sed 's/package="//;s/"//' || true)
  fi

  {
    echo "package=$PKG"
    echo "apk_file=$apk_file"
    echo "sha256=$SHA"
    echo "java_files=$(find "$JADX_OUT" -name '*.java' | wc -l)"
    echo "apk_url=$APK_URL"
    echo "date_utc=$(date -u +%FT%TZ)"
  } > "$OUT_DIR/meta.txt"

  {
    echo "# TikTok Lite Static Analysis"
    echo "package: $PKG | sha256: ${SHA:0:16}... | $(date -u +%FT%TZ)"
    echo

    section "1. ALL HTTPS ENDPOINTS"
    extract_urls

    section "2. ATTRIBUTION / APPSFLYER / MMP"
    grep_ic "appsflyer\|attribution\|install_referrer\|installreferrer\|referrer\|gcdsdk\|launches\.appsflyer" 80

    section "3. PLAY INSTALL REFERRER API"
    grep_ic "InstallReferrerClient\|installReferrer\|getReferrerDetails\|getInstallReferrer" 40

    section "4. FIRST-LAUNCH BINDING / REFERRAL API"
    grep_ic "referral\|share_page_data\|u_code\|invite\|first_install\|is_new_user\|binding" 80

    section "5. KEY REQUEST PARAMETERS"
    grep_ic "u_code\|share_page_data\|device_id\|install_id\|openudid\|aid=\|app_id\|iid=" 80

    section "6. SIGNING HEADERS (x-gorgon / x-argus / x-ladon / x-khronos)"
    grep_ic "x-gorgon\|x-argus\|x-ladon\|x-khronos\|gorgon\|argus\|ladon\|khronos" 60

    section "7. DEVICE FINGERPRINT FIELDS"
    grep_ic "fingerprint\|device_id\|openudid\|idfa\|adid\|gaid\|android_id\|serial\|imei\|mac_address\|ssid\|bssid\|cpu_abi\|sim_serial" 60

    section "8. ACCOUNT CREATION / LOGIN API"
    grep_ic "register\|signup\|sign_up\|create_account\|login\|passport\|account/create\|user/create" 60

    section "9. REWARD / COIN / INCENTIVE API"
    grep_ic "reward\|coin\|incentive\|gift\|point\|cash\|invite_bonus\|referral_reward\|wallet" 60

    section "10. REGION / SIM / COUNTRY CHECKS"
    grep_ic "sim_country\|network_country\|locale\|region\|country_code\|sim_operator\|telephony_manager\|mcc\|mnc\|getCountry\|getSimCountry" 60

    section "11. RATE LIMIT / THROTTLE"
    grep_ic "rate_limit\|ratelimit\|throttle\|429\|too_many_requests\|retry_after\|backoff\|quota" 40

    section "12. CERTIFICATE PINNING"
    grep_ic "certificatePinner\|CertificatePinner\|pinning\|ssl_pin\|PublicKeyPin\|TrustManager\|X509TrustManager\|checkServerTrusted\|hostnameVerifier" 60

    section "13. API HOST PATTERNS"
    extract_urls | grep -i "tiktok\|bytedance\|musical\|snssdk\|ibytedaos\|tiktokv\|muscdn\|lark" || true
    grep_ic "api[0-9]*\.tiktok\|api[0-9]*\.musical\|api[0-9]*\.bytedance\|AppLog\|EventTracker\|api/aweme\|aweme/v[0-9]" 60

  } > "$OUT_DIR/analysis.txt"

  log "analysis written: $(wc -l < "$OUT_DIR/analysis.txt") lines"

  extract_urls > "$OUT_DIR/urls.txt" || true
  log "urls: $(wc -l < "$OUT_DIR/urls.txt")"
}

export JADX_OUT=""
main "$@"
