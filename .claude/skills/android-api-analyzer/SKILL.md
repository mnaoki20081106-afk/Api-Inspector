---
name: android-api-analyzer
description: Dynamic API-traffic analysis of an Android APK. Use when the user hands over an APK (or says "このアプリを解析して", "APIを調べて", "analyze this apk") — runs it in a GitHub Actions Android emulator, captures logcat, and reports endpoints/hosts/auth/payload shapes.
allowed-tools: Bash(git:*), Bash(gh:*), Bash(ls:*), Bash(sha256sum:*), Bash(mkdir:*), Bash(cp:*), Read, Grep, Glob
---

# Android API analyzer

Claude runs this end to end. The user only supplies the APK (uploaded to the session, a path, or a URL).
Pipeline: APK → commit to a branch → `android_api_analysis.yml` (API 33 x86_64 emulator, monkey + logcat, 60s) → read results → report.

## Files
- `.github/workflows/android_api_analysis.yml` — workflow_dispatch, inputs: `apk_path`, `apk_url`, `package_name`, `duration_sec`, `runner`
- `.github/scripts/capture_api_logs.sh` — install, launch, monkey, logcat capture + filtering
- Outputs (artifact `android-api-logs-<run_id>` AND echoed into the job log): `meta.txt`, `install.log`, `urls.txt`, `api_logs_strict.txt` (keyword lines from the app's PIDs), `api_logs.txt` (app PID lines + keyword lines from others), `logcat_full.txt`, `monkey.log`

## Procedure

1. **Scope check.** Only analyze APKs the user owns / is authorized to test. If it's obviously someone else's protected service and no authorization is implied, say so in one line and continue only if the user confirms.
2. **Place the APK.** Put it at `apks/<name>.apk` (or `.xapk`/`.apks`). Limit: 100MB per git file. If larger, ask for a direct URL and use `apk_url` instead.
   - If a URL was given, skip committing and use `apk_url`.
3. **Make sure the workflow is on the default branch.** `workflow_dispatch` only works for workflows that exist on the default branch. If it isn't there yet, commit/push the three workflow files to the default branch first (ask the user before merging/pushing to the default branch).
4. **Push the APK on a work branch** (`analysis/<name>-<yyyymmdd>`), never the default branch:
   ```bash
   git checkout -b analysis/<name>-<date>
   git add apks/<name>.apk && git commit -m "Add APK for analysis" && git push -u origin HEAD
   ```
5. **Trigger.**
   - With `gh`:
     ```bash
     gh workflow run android_api_analysis.yml --ref analysis/<name>-<date> \
       -f apk_path=apks/<name>.apk -f package_name=<pkg-if-known> -f duration_sec=60 -f runner=macos-15-intel
     sleep 8
     gh run list --workflow android_api_analysis.yml --branch analysis/<name>-<date> --limit 1 --json databaseId,status
     gh run watch <run_id> --exit-status
     ```
   - No `gh` (cloud/phone sessions): use the GitHub MCP tools — `mcp__github__actions_run_trigger` (workflow `android_api_analysis.yml`, `ref` = work branch, `inputs` as above), then `mcp__github__actions_list` to find the run, `mcp__github__actions_get` to poll status. Don't busy-poll; check every ~2 minutes (a run takes ~8–15 min incl. emulator boot).
6. **Fetch results.**
   - Primary: job log — `mcp__github__get_job_logs` (or `gh run view <run_id> --log`); the "Print results" step has collapsed groups for `meta.txt`, `install.log`, `urls.txt`, `api_logs_strict.txt`, `api_logs.txt` (first 800 lines each).
   - Full copy, if tooling allows: `gh run download <run_id> -p 'android-api-logs-*' -D analysis/<run_id>`.
7. **Analyze** (see below) and write the report to `analysis/<run_id>/REPORT.md` if the user wants it kept.
8. **Cleanup.** Don't leave the APK on the default branch. Offer to delete the work branch.

## Analysis checklist
- Group `urls.txt` by host → base URLs; separate app backend from third-party SDKs (firebase, google, facebook, sentry, adjust, appsflyer, crashlytics…).
- From `api_logs_strict.txt`: HTTP method + path, query params, header names, auth scheme (Bearer / cookie / custom header), request/response JSON shapes, status codes, errors, retry patterns, WebSocket/gRPC use.
- Note libraries seen (okhttp, retrofit, volley, cronet, grpc) from log tags.
- Redact secrets in the report (tokens, API keys, cookies, PII) — show only prefix/suffix. Never commit raw logs containing live credentials.
- Classify confidence: **seen in logs** vs **inferred**. 

## Limits — say these when relevant
- logcat only shows what the app (or its HTTP library) chooses to log. Release builds usually log nothing about requests; `urls.txt` may be sparse or empty. HTTPS bodies are not visible.
- When that happens, report it plainly; the next step would be a MITM proxy (mitmproxy with a system-trusted CA) or Frida hooks, which need a different workflow — propose, don't improvise.
- Random monkey input won't pass login screens; features behind auth aren't exercised. Offer a scripted `adb shell input` flow if the user supplies test credentials.
- x86_64 emulator: apps with ARM-only native libs may crash at start (`monkey.log` / `logcat_full.txt` will show `UnsatisfiedLinkError` / `INSTALL_FAILED_NO_MATCHING_ABIS`). Google Play services dependent apps may misbehave on the `google_apis` image.
- `macos-13` is retired; default runner is `macos-15-intel`. `ubuntu-latest` (KVM) also works and is free on public repos; macOS minutes are 10× on private repos.

## Troubleshooting
| Symptom | Fix |
|---|---|
| `apk_path not found in checkout` | dispatched `ref` doesn't contain the APK — push the branch first, pass that `ref` |
| `Workflow does not have 'workflow_dispatch' trigger` / 404 | workflow file not on default branch yet (step 3) |
| `INSTALL_FAILED_*` | read `install.log`; ABI mismatch, minSdk > 33, or missing split → use `.xapk` with all splits |
| `could not detect package name` | pass `package_name` |
| empty `api_logs_strict.txt` but non-empty `api_logs.txt` | app logs nothing itself; analysis falls back to system-side lines |
| emulator boot timeout | rerun once; then switch `runner` |
