#!/usr/bin/env bash
# =============================================================================
#  lib/parallel.sh  —  Lightweight parallel job runner
#  Named-pipe semaphore approach — no external deps required
#  Ported from XTIP_ASM_v2.0/lib/parallel.sh (simplified for standalone use)
# =============================================================================

[[ -n "${_XTIP_PARALLEL_LOADED:-}" ]] && return 0
readonly _XTIP_PARALLEL_LOADED=1

# ---------------------------------------------------------------------------
# SEMAPHORE — named-pipe based, compatible with bash 4+
# ---------------------------------------------------------------------------

_PARA_PIPE=""      # path to named pipe
_PARA_MAX="${PARALLEL_MAX_JOBS:-4}"

# Initialise the semaphore: fill pipe with N tokens
para_init() {
    local max="${1:-${PARALLEL_MAX_JOBS:-4}}"
    _PARA_MAX="$max"
    _PARA_PIPE="$(mktemp -u "${WORKSPACE:-/tmp}/.tmp/para_pipe_XXXXXX")"
    mkfifo "$_PARA_PIPE"
    # Open pipe on fd 9 for reading and writing (keeps it open)
    exec 9<>"$_PARA_PIPE"
    # Fill with tokens
    local i
    for (( i=0; i<max; i++ )); do printf '.' >&9; done
}

# Acquire a token (block until one is free)
para_acquire() { read -r -n1 -u 9; }

# Release a token
para_release() { printf '.' >&9; }

# Close and clean up semaphore
para_cleanup() {
    exec 9>&-
    [[ -e "${_PARA_PIPE:-}" ]] && rm -f "$_PARA_PIPE"
}

# ---------------------------------------------------------------------------
# JOB TRACKING
# ---------------------------------------------------------------------------
declare -a _PARA_PIDS=()
declare -a _PARA_NAMES=()
declare -a _PARA_LOGS=()

# Run a function in the background, limited by the semaphore
# Usage: para_run JOB_NAME FUNC_NAME [args...]
para_run() {
    local job_name="$1"
    local func_name="$2"
    shift 2

    # Skip if workspace says already done
    if already_done "$func_name"; then
        log_warn "  ↷  Skipping $job_name (already processed)"
        return 0
    fi

    para_acquire
    local log_file="${WORKSPACE}/.tmp/para_${job_name}.log"
    (
        # Each subshell gets the semaphore; releases on exit
        trap 'para_release' EXIT
        "$func_name" "$@" >"$log_file" 2>&1
    ) &
    local pid=$!
    _PARA_PIDS+=("$pid")
    _PARA_NAMES+=("$job_name")
    _PARA_LOGS+=("$log_file")
    log_info "  ⟳  Launched: $job_name (pid=$pid)"
}

# Wait for all background jobs launched via para_run; collect exit codes
para_wait() {
    local all_ok=true
    local i
    for i in "${!_PARA_PIDS[@]}"; do
        local pid="${_PARA_PIDS[$i]}"
        local name="${_PARA_NAMES[$i]}"
        local logf="${_PARA_LOGS[$i]}"

        if wait "$pid"; then
            log_ok "  ✔  Completed: $name"
        else
            local rc=$?
            log_fail "  ✘  Failed: $name (exit $rc)"
            if [[ -s "$logf" ]]; then
                log_warn "     Last 5 lines from $name log:"
                tail -n5 "$logf" | while IFS= read -r l; do log_warn "       $l"; done
            fi
            all_ok=false
        fi
    done
    # Reset tracking arrays
    _PARA_PIDS=()
    _PARA_NAMES=()
    _PARA_LOGS=()

    if [[ "$all_ok" == "true" ]]; then return 0; else return 1; fi
}

# ---------------------------------------------------------------------------
# HIGH-LEVEL GROUP RUNNER
# ---------------------------------------------------------------------------
# Run a list of (name, function) pairs in parallel up to PARALLEL_MAX_JOBS
# Usage:
#   run_parallel_group \
#     "cors_check"   run_cors_check \
#     "crlf"         run_crlf_check \
#     ...
run_parallel_group() {
    local group_name="${1:-group}"
    shift

    log_info ""
    log_info "══ Parallel group: $group_name ════════════════════════"
    para_init "$_PARA_MAX"
    trap 'para_cleanup' RETURN

    while [[ $# -ge 2 ]]; do
        local job_name="$1"
        local func_name="$2"
        shift 2
        para_run "$job_name" "$func_name"
    done

    para_wait
    local rc=$?
    para_cleanup
    trap - RETURN
    return $rc
}

# ---------------------------------------------------------------------------
# SIMPLE SERIAL RUNNER with skip-if-done check
# ---------------------------------------------------------------------------
run_serial() {
    local job_name="$1"
    local func_name="$2"
    shift 2

    if already_done "$func_name"; then
        log_warn "  ↷  Skipping $job_name (already processed)"
        return 0
    fi
    log_info "  →  Running (serial): $job_name"
    "$func_name" "$@"
}
