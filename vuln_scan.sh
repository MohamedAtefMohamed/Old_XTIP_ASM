#!/usr/bin/env bash
# =============================================================================
#  vuln_scan.sh  —  Old_XTIP_ASM Vulnerability Scanning Orchestrator
#
#  Usage:
#    bash vuln_scan.sh [OPTIONS]
#
#  Options:
#    --asset PATH       Path to asm_asset.json (default: ./asm_asset.json)
#    --workspace PATH   Output directory (default: ./scan_workspace)
#    --module NAME      Run only a specific module
#    --dry-run          Print commands without executing
#    --deep             Enable DEEP mode (no URL count limits)
#    --check-tools      Validate all tool dependencies then exit
#    --no-parallel      Run all modules serially
#    --cookie VALUE     Cookie header value for authenticated scans
#    -h, --help         Show this help
#
#  Architecture (mirrors XTIP_ASM_v2.0 8-phase pipeline):
#    Phase 0: URL Discovery   (katana + waybackurls + gf classification)
#    Phase 1: Target Prep     (asm_asset.json → scan-ready lists)
#    Phase 2: Tech Routing    (technology → per-tech target lists)
#    Phase 3: Web Misconfiguration checks (parallel)
#    Phase 4: DAST fuzzing    (parallel)
#    Phase 5: Nuclei sweeps   (parallel)
#    Phase 6: Tech-specific   (parallel)
#    Phase 7: Access control  (serial)
#    Phase 8: Reporting
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Self-location
# ---------------------------------------------------------------------------
SCRIPT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1; pwd -P )"

# ---------------------------------------------------------------------------
# Default paths (overridable via CLI flags)
# ---------------------------------------------------------------------------
ASSET_JSON="${SCRIPT_DIR}/asm_asset.json"
WORKSPACE="${SCRIPT_DIR}/scan_workspace"
DRY_RUN=false
SINGLE_MODULE=""
NO_PARALLEL=false
CHECK_TOOLS_ONLY=false

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --asset)      ASSET_JSON="$2";      shift 2 ;;
        --workspace)  WORKSPACE="$2";       shift 2 ;;
        --module)     SINGLE_MODULE="$2";   shift 2 ;;
        --dry-run)    DRY_RUN=true;         shift   ;;
        --deep)       DEEP=true;            shift   ;;
        --check-tools) CHECK_TOOLS_ONLY=true; shift ;;
        --no-parallel) NO_PARALLEL=true;    shift   ;;
        --cookie)     COOKIE_HEADER="$2";   shift 2 ;;
        -h|--help)
            sed -n '/^#  Usage:/,/^# ====/p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            echo "[WARN] Unknown option: $1" >&2
            shift
            ;;
    esac
done

export ASSET_JSON WORKSPACE DRY_RUN

# ---------------------------------------------------------------------------
# Load config then libraries
# ---------------------------------------------------------------------------
# shellcheck source=./vuln_scan.cfg
source "${SCRIPT_DIR}/vuln_scan.cfg"

# Allow CLI flags to override config
[[ "${DRY_RUN}"   == "true" ]] && export DRY_RUN=true
[[ -n "${DEEP:-}" ]]           && export DEEP=true

# Colour vars exported so child scripts can use them
export bred bblue bgreen byellow red blue green cyan yellow reset

# shellcheck source=./lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=./lib/parallel.sh
source "${SCRIPT_DIR}/lib/parallel.sh"

# ---------------------------------------------------------------------------
# Workspace directory tree
# ---------------------------------------------------------------------------
ensure_dirs \
    "${WORKSPACE}/.tmp/tech_routing" \
    "${WORKSPACE}/targets" \
    "${WORKSPACE}/urls" \
    "${WORKSPACE}/gf" \
    "${WORKSPACE}/results/raw" \
    "${WORKSPACE}/results/normalized" \
    "${WORKSPACE}/results/tech_scans" \
    "${WORKSPACE}/results/nuclei_output" \
    "${WORKSPACE}/results/reports" \
    "${WORKSPACE}/logs" \
    "${WORKSPACE}/.fn_done"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOGFILE="${WORKSPACE}/logs/vuln_scan_$(date +'%Y%m%d_%H%M%S').log"
set_logfile "$LOGFILE"
set_called_fn_dir "${WORKSPACE}/.fn_done"

# Initialise findings file
FINDINGS_FILE="${WORKSPACE}/results/normalized/all_findings.jsonl"
touch "$FINDINGS_FILE"

log_info "╔══════════════════════════════════════════════════════╗"
log_info "║   Old_XTIP_ASM — Vulnerability Scanning Pipeline    ║"
log_info "╚══════════════════════════════════════════════════════╝"
log_info "  Asset JSON : $ASSET_JSON"
log_info "  Workspace  : $WORKSPACE"
log_info "  Deep mode  : ${DEEP:-false}"
log_info "  Dry run    : $DRY_RUN"
log_info "  Log file   : $LOGFILE"
log_info ""

# ---------------------------------------------------------------------------
# Load modules
# ---------------------------------------------------------------------------
source "${SCRIPT_DIR}/modules/target_prep.sh"
source "${SCRIPT_DIR}/modules/tech_router.sh"
source "${SCRIPT_DIR}/modules/url_discovery.sh"
source "${SCRIPT_DIR}/modules/vuln_web.sh"
source "${SCRIPT_DIR}/modules/vuln_network.sh"
source "${SCRIPT_DIR}/modules/vuln_nuclei.sh"
source "${SCRIPT_DIR}/modules/vuln_tech.sh"

# ---------------------------------------------------------------------------
# --check-tools: validate all dependencies
# ---------------------------------------------------------------------------
if [[ "$CHECK_TOOLS_ONLY" == "true" ]]; then
    log_info "=== Tool Dependency Check ==="
    declare -a REQUIRED_TOOLS=(jq httpx nuclei katana waybackurls gf dalfox ffuf)
    declare -a OPTIONAL_TOOLS=(
        testssl.sh crlfuzz sqlmap commix brutespray wpscan trufflehog
        qsreplace anew interactsh-client Gxss urless ppfuzz TInjA sstimap
        nomore403 smugglex Web-Cache-Vulnerability-Scanner
    )
    local_ok=true
    for t in "${REQUIRED_TOOLS[@]}"; do
        if command -v "$t" >/dev/null 2>&1; then
            log_ok  "  [REQUIRED] $t ✔"
        else
            log_fail "  [REQUIRED] $t ✘ — MISSING"
            local_ok=false
        fi
    done
    for t in "${OPTIONAL_TOOLS[@]}"; do
        if command -v "$t" >/dev/null 2>&1; then
            log_ok   "  [OPTIONAL] $t ✔"
        else
            log_warn "  [OPTIONAL] $t ✘ (missing — related module will skip)"
        fi
    done
    [[ "$local_ok" == "true" ]] && exit 0 || exit 1
fi

# ---------------------------------------------------------------------------
# Cleanup on exit
# ---------------------------------------------------------------------------
_SCAN_START=$(date +%s)
trap '_scan_finish' EXIT

_scan_finish() {
    local rc=$?
    local elapsed=$(( $(date +%s) - _SCAN_START ))
    echo "" >&2
    if [[ $rc -eq 0 ]]; then
        log_ok  "Scan completed in $(format_duration $elapsed)"
    else
        log_fail "Scan exited with code $rc after $(format_duration $elapsed)"
    fi
    # Clean up temp named pipe if parallel runner left it
    [[ -n "${_PARA_PIPE:-}" ]] && rm -f "$_PARA_PIPE" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# --module: single module shortcut
# ---------------------------------------------------------------------------
if [[ -n "$SINGLE_MODULE" ]]; then
    log_info "Running single module: $SINGLE_MODULE"
    "$SINGLE_MODULE"
    exit $?
fi

# ---------------------------------------------------------------------------
# PHASE 1 — Target preparation  (serial, always)
# ---------------------------------------------------------------------------
log_info ""
log_info "══ Phase 1: Target Preparation ══════════════════════"
run_serial "prepare_targets" prepare_targets

# Verify we have something to scan
if [[ ! -s "${WORKSPACE}/targets/web_targets.txt" ]]; then
    log_fail "No HTTP-alive targets found in ${ASSET_JSON} — aborting"
    exit 1
fi
WEB_COUNT=$(count_lines "${WORKSPACE}/targets/web_targets.txt")
log_info "  HTTP-alive targets: $WEB_COUNT"

# ---------------------------------------------------------------------------
# PHASE 2 — Technology routing  (serial)
# ---------------------------------------------------------------------------
log_info ""
log_info "══ Phase 2: Technology Routing ══════════════════════"
run_serial "route_by_technology" route_by_technology

# ---------------------------------------------------------------------------
# PHASE 0 — URL Discovery  (serial: katana → waybackurls → merge → gf)
#  (Run after phase 2 so routing is ready, but before vuln scanning)
# ---------------------------------------------------------------------------
run_url_discovery

# ---------------------------------------------------------------------------
# PHASE 3 — Web misconfiguration checks  (parallel)
# ---------------------------------------------------------------------------
if [[ "$NO_PARALLEL" == "true" ]]; then
    log_info ""
    log_info "══ Phase 3: Web Misconfiguration (serial) ════════════"
    run_serial "cors_check"              run_cors_check
    run_serial "open_redirect"           run_open_redirect
    run_serial "host_header_injection"   run_host_header_injection
    run_serial "crlf_check"              run_crlf_check
    run_serial "webcache_check"          run_webcache_check
else
    run_parallel_group "Phase 3: Web Misconfiguration" \
        "cors_check"            run_cors_check \
        "open_redirect"         run_open_redirect \
        "host_header_injection" run_host_header_injection \
        "crlf_check"            run_crlf_check \
        "webcache_check"        run_webcache_check
fi

# ---------------------------------------------------------------------------
# PHASE 4 — DAST parameter fuzzing  (parallel)
# ---------------------------------------------------------------------------
if [[ "$NO_PARALLEL" == "true" ]]; then
    log_info ""
    log_info "══ Phase 4: DAST Fuzzing (serial) ════════════════════"
    run_serial "xss"                run_xss
    run_serial "ssrf_check"         run_ssrf_check
    run_serial "lfi"                run_lfi
    run_serial "ssti"               run_ssti
    run_serial "sqli"               run_sqli
    run_serial "command_injection"  run_command_injection
else
    run_parallel_group "Phase 4: DAST Fuzzing" \
        "xss"               run_xss \
        "ssrf_check"        run_ssrf_check \
        "lfi"               run_lfi \
        "ssti"              run_ssti \
        "sqli"              run_sqli \
        "command_injection" run_command_injection
fi

# ---------------------------------------------------------------------------
# PHASE 5 — Nuclei + Network  (parallel)
# ---------------------------------------------------------------------------
if [[ "$NO_PARALLEL" == "true" ]]; then
    log_info ""
    log_info "══ Phase 5: Nuclei & Network (serial) ════════════════"
    run_serial "nuclei_generic"       run_nuclei_generic
    run_serial "nuclei_dast"          run_nuclei_dast
    run_serial "ssl_test"             run_ssl_test
    run_serial "api_key_validation"   run_api_key_validation
else
    run_parallel_group "Phase 5: Nuclei & Network" \
        "nuclei_generic"      run_nuclei_generic \
        "nuclei_dast"         run_nuclei_dast \
        "ssl_test"            run_ssl_test \
        "api_key_validation"  run_api_key_validation
fi

# ---------------------------------------------------------------------------
# PHASE 6 — Tech-specific scanners  (parallel)
# ---------------------------------------------------------------------------
run_parallel_group "Phase 6: Tech-Specific Scanners" \
    "tech_scanners" run_tech_specific_scanners

# ---------------------------------------------------------------------------
# PHASE 7 — Access control (serial — depends on prior phases)
# ---------------------------------------------------------------------------
log_info ""
log_info "══ Phase 7: Access Control ══════════════════════════"
run_serial "4xx_bypass"   run_4xx_bypass
run_serial "spraying"     run_password_spray
run_serial "smuggling"    run_smuggling

# ---------------------------------------------------------------------------
# PHASE 8 — Reporting
# ---------------------------------------------------------------------------
log_info ""
log_info "══ Phase 8: Report Generation ═══════════════════════"
_generate_reports() {
    local fn="_generate_reports"
    local reports="${WORKSPACE}/results/reports"
    ensure_dirs "$reports"

    if [[ ! -s "$FINDINGS_FILE" ]]; then
        log_warn "  No findings to report"
        return 0
    fi

    local total; total=$(count_lines "$FINDINGS_FILE")

    # --- By severity ---
    local by_sev="${reports}/findings_by_severity.txt"
    {
        echo "=== Findings by Severity ==="
        for sev in critical high medium low info; do
            local cnt; cnt=$(grep -c "\"severity\":\"$sev\"" "$FINDINGS_FILE" 2>/dev/null || echo 0)
            printf "  %-10s %d\n" "$sev" "$cnt"
        done
        echo "  TOTAL      $total"
    } > "$by_sev"

    # --- By tool ---
    local by_tool="${reports}/findings_by_tool.txt"
    {
        echo "=== Findings by Tool ==="
        jq -r '.tool' "$FINDINGS_FILE" 2>/dev/null \
            | sort | uniq -c | sort -rn \
            | awk '{printf "  %-30s %d\n", $2, $1}'
    } > "$by_tool"

    # --- By host ---
    local by_host="${reports}/findings_by_host.json"
    jq -s 'group_by(.asset) | map({asset: .[0].asset, count: length, findings: .})' \
        "$FINDINGS_FILE" 2>/dev/null > "$by_host" || true

    # --- Summary ---
    local summary="${reports}/summary.txt"
    {
        echo "========================================"
        echo "  Old_XTIP_ASM Vulnerability Scan Report"
        echo "  Generated: $(date)"
        echo "========================================"
        echo ""
        cat "$by_sev"
        echo ""
        cat "$by_tool"
        echo ""
        echo "=== Output Files ==="
        echo "  All findings (JSONL): $(realpath "$FINDINGS_FILE")"
        echo "  By host (JSON):       $(realpath "$by_host")"
        echo "  By severity:          $(realpath "$by_sev")"
        echo "  By tool:              $(realpath "$by_tool")"
        echo "  Raw outputs:          $(realpath "${WORKSPACE}/results/raw/")"
        echo "  Tech scans:           $(realpath "${WORKSPACE}/results/tech_scans/")"
        echo ""
        echo "Log: $LOGFILE"
    } > "$summary"

    cat "$summary" >&2
    log_ok "Reports written to ${reports}"
}

_generate_reports
log_ok ""
log_ok "═══════════════════════════════════════════════"
log_ok "  Scan complete. Workspace: ${WORKSPACE}"
log_ok "═══════════════════════════════════════════════"
