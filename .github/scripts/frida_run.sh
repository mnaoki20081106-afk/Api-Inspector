#!/usr/bin/env bash
# Frida-based dynamic analysis for Android APKs.
# Phase "prepare": download APK, strip arm64 libs, re-sign, install Frida tools.
# Phase "run":     push frida-server, install APK, hook, capture.
# Env: APK_URL, APK_PATH, PACKAGE_NAME, DURATION_SEC, OUT_DIR
set -euo pipefail

OUT_DIR="${OUT_DIR:-out}"
APK_URL="${APK_URL:-}"
APK_PATH_IN="${APK_PATH:-}"
PKG="${PACKAGE_NAME:-}"
DURATION="${DURATION_SEC:-90}"
[[ "$DURATION" =~ ^[0-9]+$ ]] || DURATION=90

FRIDA_VERSION="16.5.9"

log() { echo "[frida] $*" >&2; }
phase="${1:-prepare}"

# ── prepare ──────────────────────────────────────────────────────────────────
prepare() {
  mkdir -p "$OUT_DIR" apk

  # 1. Fetch APK
  if [[ -n "$APK_PATH_IN" && -f "$APK_PATH_IN" ]]; then
    log "using repo file $APK_PATH_IN"
    cp "$APK_PATH_IN" apk/orig.apk
  elif [[ -n "$APK_URL" ]]; then
    log "downloading $APK_URL"
    curl -fL --retry 3 --retry-delay 3 -o apk/orig.apk "$APK_URL"
  else
    log "need apk_url or apk_path"; exit 1
  fi

  SHA=$(sha256sum apk/orig.apk | cut -d' ' -f1)
  SIZE=$(wc -c < apk/orig.apk)
  log "apk sha256=$SHA size=$SIZE"

  # Detect package name from manifest if not supplied
  if [[ -z "$PKG" ]]; then
    PKG=$(unzip -p apk/orig.apk AndroidManifest.xml 2>/dev/null \
          | strings | grep -oE 'com\.[a-z0-9._]{4,}' | head -1 || echo "unknown")
    log "detected package: $PKG"
  fi

  # 2. Strip all ARM native libs — x86_64 emulator has no houdini translation;
  #    JNI UnsatisfiedLinkErrors are suppressed by the Frida script so Java
  #    bytecode keeps running.
  log "stripping arm native libs"
  cp apk/orig.apk apk/stripped.apk
  zip -d apk/stripped.apk \
    'lib/arm64-v8a/*' 'lib/armeabi-v7a/*' 'lib/armeabi/*' 2>/dev/null || true

  # 3. Zipalign + re-sign with debug key
  sudo apt-get install -y -q zipalign apksigner 2>/dev/null || true

  log "aligning"
  zipalign -f 4 apk/stripped.apk apk/aligned.apk 2>/dev/null \
    || cp apk/stripped.apk apk/aligned.apk

  log "generating debug keystore"
  keytool -genkey -v \
    -keystore apk/debug.keystore -alias debug \
    -keyalg RSA -keysize 2048 -validity 1 \
    -dname "CN=Debug,OU=Debug,O=Debug,L=Debug,ST=Debug,C=US" \
    -storepass debugkey -keypass debugkey -noprompt 2>/dev/null

  log "signing"
  apksigner sign \
    --ks apk/debug.keystore --ks-key-alias debug \
    --ks-pass pass:debugkey --key-pass pass:debugkey \
    --out apk/signed.apk apk/aligned.apk

  # 4. Download frida-server (x86_64 for the emulator)
  log "downloading frida-server $FRIDA_VERSION (x86_64)"
  curl -fL --retry 3 \
    "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz" \
    | xz -d > apk/frida-server
  chmod +x apk/frida-server

  # 5. Install frida Python tools
  log "installing frida-tools"
  pip install -q "frida==${FRIDA_VERSION}" frida-tools

  {
    echo "package=$PKG"
    echo "sha256_orig=$SHA"
    echo "size_bytes=$SIZE"
    echo "frida_version=$FRIDA_VERSION"
    echo "apk_url=$APK_URL"
    echo "date_utc=$(date -u +%FT%TZ)"
  } > "$OUT_DIR/meta.txt"

  log "prepare done"
}

# ── run (inside android-emulator-runner context) ─────────────────────────────
run() {
  local js=frida_scripts/android_http.js
  [[ -f "$js" ]] || { log "missing $js"; exit 1; }

  adb wait-for-device
  # adb root restarts adbd — wait for device to come back before proceeding
  adb root || log "adb root skipped (non-root image?)"
  adb wait-for-device
  sleep 5

  # Push frida-server
  log "pushing frida-server"
  adb push apk/frida-server /data/local/tmp/frida-server
  adb shell chmod 755 /data/local/tmp/frida-server
  # Use nohup+& so adb shell returns immediately instead of hanging
  adb shell "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &" \
    || log "frida-server start attempted (exit ignored)"
  sleep 5

  # Disable package verifier
  adb shell settings put global package_verifier_enable 0 || true
  adb shell settings put global verifier_verify_adb_installs 0 || true

  # Install APK
  log "installing APK"
  local install_log="$OUT_DIR/install.log"
  if adb install -r -g -t apk/signed.apk 2>&1 | tee "$install_log" | grep -q '^Success'; then
    log "install succeeded"
  else
    log "install failed — trying base.apk from bundle if present"
    if unzip -l apk/orig.apk 2>/dev/null | grep -q 'base.apk'; then
      mkdir -p apk/bundle
      unzip -qo apk/orig.apk base.apk -d apk/bundle 2>/dev/null || true
      if [[ -f apk/bundle/base.apk ]]; then
        zip -d apk/bundle/base.apk 'lib/arm64-v8a/*' 2>/dev/null || true
        adb install -r -g -t apk/bundle/base.apk 2>&1 | tee -a "$install_log" || true
      fi
    fi
  fi

  # Re-detect PKG if needed
  if [[ -z "$PKG" || "$PKG" == "unknown" ]]; then
    PKG=$(adb shell pm list packages -3 2>/dev/null | head -1 \
          | sed 's/^package://' | tr -d '\r')
  fi
  log "target package: $PKG"

  # Spawn Frida: -f starts the process itself with hooks loaded from the start.
  # The script suppresses JNI load errors so Java bytecode runs on x86_64.
  log "spawning frida for ${DURATION}s"
  frida -U -f "$PKG" -l "$js" --runtime=v8 \
    2>&1 | timeout "$DURATION" cat > "$OUT_DIR/frida_output.txt" || true

  # Extract unique URLs
  grep -oE 'https?://[^[:space:]"'"'"'<>]+' "$OUT_DIR/frida_output.txt" \
    | sort -u > "$OUT_DIR/urls.txt" 2>/dev/null || true

  local flines=0 ulines=0
  [[ -f "$OUT_DIR/frida_output.txt" ]] && flines=$(wc -l < "$OUT_DIR/frida_output.txt")
  [[ -f "$OUT_DIR/urls.txt" ]]         && ulines=$(wc -l < "$OUT_DIR/urls.txt")
  log "done: ${flines} frida lines, ${ulines} urls"
}

case "$phase" in
  prepare) prepare ;;
  run)     run ;;
  *)       log "unknown phase: $phase"; exit 1 ;;
esac
