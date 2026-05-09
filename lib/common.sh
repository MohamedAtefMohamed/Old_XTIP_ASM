#!/usr/bin/env bash
# =============================================================================
#  lib/common.sh  —  Shared helper functions for Old_XTIP_ASM vuln pipeline
#  Ported from XTIP_ASM_v2.0/lib/common.sh — simplified for standalone Bash
# =============================================================================

[[ -n "${_XTIP_COMMON_LOADED:-}" ]] && return 0
readonly _XTIP_COMMON_LOADED=1

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------
_LOG_FILE=""   # Set by parent after WORKSPACE is known

set_logfile() { _LOG_FILE="$1"; }

log_msg() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts=$(date +'%Y-%m-%d %H:%M:%S')
    local color=""
    case "$level" in
        INFO)  color="${bblue:-}"  ;;
        OK)    color="${bgreen:-}" ;;
        WARN)  color="${byellow:-}";;
        FAIL)  color="${bred:-}"   ;;
        *)     color="${reset:-}"  ;;
    esac

    # Always write to log file if set
    if [[ -n "$_LOG_FILE" ]]; then
        printf "[%s] [%s] %s\n" "$ts" "$level" "$msg" >> "$_LOG_FILE"
    fi

    # Print to terminal
    printf "%b[%s]%b %s\n" "$color" "$level" "${reset:-}" "$msg" >&2
}

log_info()  { log_msg INFO  "$@"; }
log_ok()    { log_msg OK    "$@"; }
log_warn()  { log_msg WARN  "$@"; }
log_fail()  { log_msg FAIL  "$@"; }

# ---------------------------------------------------------------------------
# FUNCTION LIFECYCLE  (mirrors start_func / end_func from v2.0)
# ---------------------------------------------------------------------------

# Sentinel directory: each completed function leaves a marker file
_CALLED_FN_DIR=""
set_called_fn_dir() { _CALLED_FN_DIR="$1"; mkdir -p "$_CALLED_FN_DIR"; }

start_func() {
    local name="$1"
    local title="${2:-$name}"
    local ts; ts=$(date +'%Y-%m-%d %H:%M:%S')
    log_info "[$ts] ▶  Starting: $title"
    # Store start time in marker dir for duration tracking
    if [[ -n "$_CALLED_FN_DIR" ]]; then
        echo "$ts" > "${_CALLED_FN_DIR}/.start_${name}"
    fi
}

end_func() {
    local msg="$1"
    local name="$2"
    local ts; ts=$(date +'%Y-%m-%d %H:%M:%S')
    local start_ts=""
    local duration_str=""
    if [[ -n "$_CALLED_FN_DIR" && -f "${_CALLED_FN_DIR}/.start_${name}" ]]; then
        start_ts=$(cat "${_CALLED_FN_DIR}/.start_${name}" 2>/dev/null || true)
    fi
    if [[ -n "$start_ts" ]]; then
        local start_epoch end_epoch
        start_epoch=$(date -d "$start_ts" +%s 2>/dev/null || date -j -f '%Y-%m-%d %H:%M:%S' "$start_ts" +%s 2>/dev/null || echo 0)
        end_epoch=$(date +%s)
        local secs=$(( end_epoch - start_epoch ))
        duration_str=" ($(format_duration $secs))"
    fi
    log_ok "[$ts] ✔  Done: ${msg}${duration_str}"
    # Write completion marker
    if [[ -n "$_CALLED_FN_DIR" && -n "$name" ]]; then
        touch "${_CALLED_FN_DIR}/.${name}" 2>/dev/null || true
    fi
}

# Check if a function has already been processed (marker file exists)
already_done() {
    local name="$1"
    [[ -n "$_CALLED_FN_DIR" ]] && [[ -f "${_CALLED_FN_DIR}/.${name}" ]]
}

# Skip message helper
skip_func() {
    local name="$1"
    local reason="${2:-disabled}"
    log_warn "  ↷  Skipping ${name}: ${reason}"
}

# ---------------------------------------------------------------------------
# DIRECTORY MANAGEMENT
# ---------------------------------------------------------------------------
ensure_dirs() {
    if [[ $# -eq 0 ]]; then return 0; fi
    if ! mkdir -p "$@" 2>/dev/null; then
        log_fail "Failed to create directories: $*"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# FILE HELPERS
# ---------------------------------------------------------------------------

# Append unique lines — uses anew if available, else sort-based fallback
dedupe_append() {
    local file="$1"
    if command -v anew >/dev/null 2>&1; then
        anew -q "$file" 2>/dev/null
    else
        cat >> "$file"
        sort -u "$file" -o "$file"
    fi
}

# Count non-empty lines in a file
count_lines() {
    local file="$1"
    if [[ -s "$file" ]]; then
        grep -c . "$file" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# Safe, non-empty line count from stdin
count_stdin() { grep -c . 2>/dev/null || echo 0; }

# ---------------------------------------------------------------------------
# TOOL EXECUTION
# ---------------------------------------------------------------------------

# Run a command with logging, timeout, and error capture
# Usage: run_tool NAME [args...]
run_tool() {
    local name="$1"; shift

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "  [DRY-RUN] Would run: $name $*"
        return 0
    fi

    if [[ -n "${_LOG_FILE:-}" ]]; then
        printf "[%s] CMD: %s %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$name" "$*" >> "$_LOG_FILE"
    fi

    local timeout_sec="${TOOL_TIMEOUT:-3600}"
    if command -v timeout >/dev/null 2>&1; then
        timeout "$timeout_sec" "$name" "$@"
    else
        "$name" "$@"
    fi
    local rc=$?
    if [[ $rc -ne 0 && $rc -ne 1 ]]; then   # rc=1 = "no results" — not an error
        log_warn "  Tool '$name' exited with code $rc"
    fi
    return $rc
}

# Check if a tool is available; warn once if not
_WARNED_TOOLS=()
require_tool() {
    local tool="$1"
    if command -v "$tool" >/dev/null 2>&1; then
        return 0
    fi
    # Warn only once per tool
    local already_warned=false
    local t
    for t in "${_WARNED_TOOLS[@]:-}"; do
        [[ "$t" == "$tool" ]] && already_warned=true && break
    done
    if [[ "$already_warned" != "true" ]]; then
        log_warn "  Tool not found in PATH: $tool — module skipped"
        _WARNED_TOOLS+=("$tool")
    fi
    return 1
}

# ---------------------------------------------------------------------------
# FORMATTING
# ---------------------------------------------------------------------------
format_duration() {
    local secs="${1:-0}"
    local mins=$(( secs / 60 ))
    local rem=$(( secs % 60 ))
    if (( mins > 0 )); then
        printf "%dm %02ds" "$mins" "$rem"
    else
        printf "%ds" "$secs"
    fi
}

# ---------------------------------------------------------------------------
# SAFE TEMP FILES
# ---------------------------------------------------------------------------
# Create a temp file inside the workspace (cleaned up on EXIT by caller trap)
make_tmp() {
    local workspace="${WORKSPACE:-/tmp}"
    local prefix="${1:-xtip}"
    mktemp "${workspace}/.tmp/${prefix}_XXXXXX"
}

# ---------------------------------------------------------------------------
# SEVERITY NORMALIZER
# ---------------------------------------------------------------------------
# Map tool-specific severity strings to canonical levels
normalize_severity() {
    local raw; raw=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    case "$raw" in
        critical|crit)           echo "critical" ;;
        high)                    echo "high"     ;;
        medium|med|moderate)     echo "medium"   ;;
        low)                     echo "low"      ;;
        info|informational|note) echo "info"     ;;
        *)                       echo "info"     ;;
    esac
}

# Severity to numeric score (for sorting)
severity_score() {
    case "$(normalize_severity "$1")" in
        critical) echo 4 ;;
        high)     echo 3 ;;
        medium)   echo 2 ;;
        low)      echo 1 ;;
        *)        echo 0 ;;
    esac
}

# ---------------------------------------------------------------------------
# FINDING EMITTER
# ---------------------------------------------------------------------------
# Emit a normalised JSONL finding record
# Usage: emit_finding ASSET TOOL SEVERITY TITLE MATCHED_AT [DETAIL]
emit_finding() {
    local asset="$1"
    local tool="$2"
    local severity; severity=$(normalize_severity "$3")
    local title="$4"
    local matched_at="${5:-$asset}"
    local detail="${6:-}"
    local ts; ts=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
    local findings_file="${WORKSPACE}/results/normalized/all_findings.jsonl"

    # Build JSONL record (jq not required for emission — pure bash printf)
    printf '{"asset":"%s","tool":"%s","severity":"%s","title":"%s","matched_at":"%s","detail":"%s","timestamp":"%s"}\n' \
        "$asset" "$tool" "$severity" \
        "$(echo "$title"   | sed 's/"/\\"/g')" \
        "$(echo "$matched_at" | sed 's/"/\\"/g')" \
        "$(echo "$detail"  | sed 's/"/\\"/g')" \
        "$ts" >> "$findings_file"
}
