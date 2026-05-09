#!/usr/bin/env bash
# modules/vuln_nuclei.sh — Nuclei-based scanning
# Ports: nucleicheck (generic sweep), nuclei_dast, tag-based tech scans

RAW="${WORKSPACE}/results/raw"
TMP="${WORKSPACE}/.tmp"

_ensure_nuclei() {
    require_tool nuclei || return 1
    if [[ ! -d "${NUCLEI_TEMPLATES_PATH:-}" ]]; then
        log_warn "nuclei: NUCLEI_TEMPLATES_PATH not found: '${NUCLEI_TEMPLATES_PATH}'"
        log_warn "  Run: nuclei -update-templates"
        return 1
    fi
    return 0
}

_maybe_update_nuclei() {
    local marker="${TMP}/.nuclei_updated"
    [[ -f "$marker" ]] && return 0
    if [[ "${NUCLEI_AUTO_UPDATE:-false}" == "true" ]]; then
        nuclei -update-templates -silent 2>/dev/null || true
    fi
    touch "$marker"
}

# ---------------------------------------------------------------------------
run_nuclei_generic() {
    local fn="run_nuclei_generic"
    [[ "${NUCLEICHECK:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    _ensure_nuclei || return 0

    local web_targets="${WORKSPACE}/targets/web_targets.txt"
    [[ ! -s "$web_targets" ]] && { log_warn "nuclei_generic: no web targets"; return 0; }

    start_func "$fn" "Nuclei Generic Sweep"
    _maybe_update_nuclei

    ensure_dirs "${WORKSPACE}/results/nuclei_output"
    local out_json="${WORKSPACE}/results/nuclei_output/generic_json.txt"
    local out_txt="${RAW}/nuclei_generic.txt"

    run_tool nuclei \
        -l "$web_targets" \
        -severity "${NUCLEI_SEVERITY:-info,low,medium,high,critical}" \
        -nh -silent -retries 2 \
        -rl "${NUCLEI_RATELIMIT:-150}" \
        ${NUCLEI_EXTRA_ARGS} \
        -j -o "$out_json" \
        2>>"${WORKSPACE}/logs/nuclei_generic.log" || true

    if [[ -s "$out_json" ]]; then
        jq -r '"["+.info.severity+"] ["+.["template-id"]+"] "+(."matched-at"//.host)' \
            "$out_json" 2>/dev/null > "$out_txt" || true
        jq -c '.' "$out_json" 2>/dev/null | while IFS= read -r rec; do
            local sev;  sev=$(echo "$rec"  | jq -r '.info.severity // "info"'         2>/dev/null)
            local tid;  tid=$(echo "$rec"  | jq -r '.["template-id"] // "unknown"'    2>/dev/null)
            local mat;  mat=$(echo "$rec"  | jq -r '."matched-at" // .host // empty'  2>/dev/null)
            local name; name=$(echo "$rec" | jq -r '.info.name // $tid'               2>/dev/null --argjson tid "\"$tid\"")
            emit_finding "$mat" "nuclei" "$sev" "$name" "$mat" "$tid"
        done
        for s in info low medium high critical; do
            jq -c "select(.info.severity == \"$s\")" "$out_json" > "${WORKSPACE}/results/nuclei_output/generic_${s}.json" 2>/dev/null || true
            [[ ! -s "${WORKSPACE}/results/nuclei_output/generic_${s}.json" ]] && rm -f "${WORKSPACE}/results/nuclei_output/generic_${s}.json"
        done
    fi

    end_func "$(count_lines "$out_txt") nuclei findings → ${out_txt}" "$fn"
}

# ---------------------------------------------------------------------------
# Collect all URL sources for DAST scanning (mirrors _nuclei_dast_collect_targets)
_collect_dast_targets() {
    local dast_targets="${TMP}/nuclei_dast_targets.txt"
    : > "$dast_targets"

    for src in \
        "${WORKSPACE}/targets/web_targets.txt" \
        "${WORKSPACE}/urls/url_extract_nodupes.txt" \
        "${WORKSPACE}/gf/xss.txt" \
        "${WORKSPACE}/gf/sqli.txt" \
        "${WORKSPACE}/gf/ssrf.txt" \
        "${WORKSPACE}/gf/lfi.txt" \
        "${WORKSPACE}/gf/ssti.txt" \
        "${WORKSPACE}/gf/rce.txt"; do
        [[ -s "$src" ]] && grep -aE '^https?://' "$src" >> "$dast_targets" || true
    done

    sort -u "$dast_targets" -o "$dast_targets"

    # Deduplicate by URL structure with urless if available
    if [[ "${NUCLEI_DAST_DEDUP:-true}" == "true" ]] && command -v urless >/dev/null 2>&1; then
        urless < "$dast_targets" | sort -u > "${dast_targets}.dedup" 2>/dev/null && \
            mv "${dast_targets}.dedup" "$dast_targets" || true
    fi

    echo "$dast_targets"
}

# ---------------------------------------------------------------------------
run_nuclei_dast() {
    local fn="run_nuclei_dast"
    [[ "${NUCLEI_DAST:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    _ensure_nuclei || return 0

    local dast_targets; dast_targets=$(_collect_dast_targets)
    if [[ ! -s "$dast_targets" ]]; then
        log_warn "nuclei_dast: no DAST targets found"
        return 0
    fi

    local url_count; url_count=$(count_lines "$dast_targets")
    if [[ "${DEEP:-false}" != "true" ]] && [[ $url_count -gt "${DEEP_LIMIT2:-1500}" ]]; then
        log_warn "nuclei_dast: too many targets ($url_count) — use DEEP=true"
        return 0
    fi

    start_func "$fn" "Nuclei DAST (${url_count} targets)"
    _maybe_update_nuclei

    local dast_tpl="${NUCLEI_DAST_TEMPLATE_PATH:-${NUCLEI_TEMPLATES_PATH}/dast}"
    local out_json="${WORKSPACE}/results/nuclei_output/dast_json.txt"
    local out_txt="${RAW}/nuclei_dast.txt"
    ensure_dirs "${WORKSPACE}/results/nuclei_output"

    run_tool nuclei \
        -l "$dast_targets" \
        -dast -t "$dast_tpl" \
        -nh -silent -retries 2 \
        -rl "${NUCLEI_RATELIMIT:-150}" \
        ${NUCLEI_EXTRA_ARGS} ${NUCLEI_DAST_EXTRA_ARGS} \
        -j -o "$out_json" \
        2>>"${WORKSPACE}/logs/nuclei_dast.log" || true

    if [[ -s "$out_json" ]]; then
        # Tag with scan scope
        jq -c '. + {"scan_scope":"dast"}' "$out_json" 2>/dev/null \
            > "${WORKSPACE}/results/nuclei_output/dast_json_tagged.txt" || true
        jq -r '"["+.info.severity+"] ["+.["template-id"]+"] "+(."matched-at"//.host)' \
            "$out_json" 2>/dev/null > "$out_txt" || true
        jq -c '.' "$out_json" 2>/dev/null | while IFS= read -r rec; do
            local sev; sev=$(echo "$rec" | jq -r '.info.severity // "info"' 2>/dev/null)
            local tid; tid=$(echo "$rec" | jq -r '.["template-id"] // "unknown"' 2>/dev/null)
            local mat; mat=$(echo "$rec" | jq -r '."matched-at" // .host // empty' 2>/dev/null)
            emit_finding "$mat" "nuclei-dast" "$sev" "$tid" "$mat" "$tid"
        done
        for s in info low medium high critical; do
            jq -c "select(.info.severity == \"$s\")" "$out_json" > "${WORKSPACE}/results/nuclei_output/dast_${s}.json" 2>/dev/null || true
            [[ ! -s "${WORKSPACE}/results/nuclei_output/dast_${s}.json" ]] && rm -f "${WORKSPACE}/results/nuclei_output/dast_${s}.json"
        done
    fi

    end_func "$(count_lines "$out_txt") DAST findings → ${out_txt}" "$fn"
}

# ---------------------------------------------------------------------------
# Run nuclei with specific tags against a target file
# Usage: _nuclei_tag_scan LABEL TAG_STRING INPUT_FILE OUTPUT_FILE
_nuclei_tag_scan() {
    local label="$1" tags="$2" input="$3" out="$4"
    [[ ! -s "$input" ]] && return 0
    local count; count=$(count_lines "$input")
    log_info "  [nuclei-tags] $label: scanning $count targets (tags: $tags)"
    run_tool nuclei \
        -l "$input" \
        -tags "$tags" \
        -as -nh -silent -retries 2 \
        -rl "${NUCLEI_RATELIMIT:-150}" \
        ${NUCLEI_EXTRA_ARGS} \
        -o "$out" \
        2>>"${WORKSPACE}/logs/nuclei_tags.log" || true
    [[ -s "$out" ]] && log_info "  → $label: $(count_lines "$out") findings"
}
