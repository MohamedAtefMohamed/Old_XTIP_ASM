#!/usr/bin/env bash
# modules/vuln_web.sh — Web-based vulnerability checks
# Ports: cors_check, open_redirect, host_header_injection, crlf_checks,
#        webcache, xss, ssrf_checks, lfi, ssti, sqli, command_injection, 4xxbypass, smuggling

RAW="${WORKSPACE}/results/raw"
GF="${WORKSPACE}/gf"
TMP="${WORKSPACE}/.tmp"

_web_targets() { echo "${WORKSPACE}/targets/web_targets.txt"; }
_url_all()     { echo "${WORKSPACE}/urls/url_extract_nodupes.txt"; }

# ---------------------------------------------------------------------------
run_cors_check() {
    local fn="run_cors_check"
    [[ "${CORS_CHECK:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    require_tool httpx || return 0
    [[ ! -s "$(_web_targets)" ]] && { log_warn "cors: no web targets"; return 0; }
    start_func "$fn" "CORS Misconfiguration Check"
    local out="${RAW}/cors.txt"; : > "$out"

    # Wildcard
    httpx -l "$(_web_targets)" -H "Origin: https://evil.com" -H "${HEADER}" \
        -match-regex 'Access-Control-Allow-Origin: \*' \
        -threads "${HTTPX_THREADS:-50}" -rl "${HTTPX_RATELIMIT:-150}" -silent -nc 2>/dev/null \
        | awk '{print "[MEDIUM] Wildcard CORS: "$0}' >> "$out" || true

    # Reflection
    httpx -l "$(_web_targets)" -H "Origin: https://evil.com" -H "${HEADER}" \
        -match-regex 'Access-Control-Allow-Origin: https://evil\.com' \
        -threads "${HTTPX_THREADS:-50}" -rl "${HTTPX_RATELIMIT:-150}" -silent -nc 2>/dev/null \
        | awk '{print "[HIGH] CORS Reflection: "$0}' >> "$out" || true

    # Credentials
    httpx -l "$(_web_targets)" -H "Origin: https://evil.com" -H "${HEADER}" \
        -match-regex 'Access-Control-Allow-Credentials: true' \
        -threads "${HTTPX_THREADS:-50}" -rl "${HTTPX_RATELIMIT:-150}" -silent -nc 2>/dev/null \
        | awk '{print "[CRITICAL] CORS+Credentials: "$0}' >> "$out" || true

    # Null origin
    httpx -l "$(_web_targets)" -H "Origin: null" -H "${HEADER}" \
        -match-regex 'Access-Control-Allow-Origin: null' \
        -threads "${HTTPX_THREADS:-50}" -rl "${HTTPX_RATELIMIT:-150}" -silent -nc 2>/dev/null \
        | awk '{print "[HIGH] CORS Null Origin: "$0}' >> "$out" || true

    while IFS= read -r line; do
        local sev; sev=$(echo "$line" | grep -oP '(?<=\[)\w+(?=\])' | head -1)
        local url; url=$(echo "$line" | awk '{print $NF}')
        emit_finding "$url" "httpx-cors" "${sev:-medium}" "CORS Misconfiguration" "$url" "$line"
    done < "$out"

    end_func "$(count_lines "$out") CORS issues → ${out}" "$fn"
}

# ---------------------------------------------------------------------------
run_open_redirect() {
    local fn="run_open_redirect"
    [[ "${OPEN_REDIRECT:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    require_tool httpx || return 0
    local candidates="${GF}/redirect.txt"
    [[ ! -s "$candidates" ]] && { log_warn "open_redirect: no gf/redirect.txt"; return 0; }
    start_func "$fn" "Open Redirect Testing"
    local out="${RAW}/open_redirect.txt"; : > "$out"
    local -a payloads=("//evil.com" "https://evil.com" "/\\evil.com" "//evil%00.com")
    for p in "${payloads[@]}"; do
        cat "$candidates" | qsreplace "$p" 2>/dev/null \
            | httpx -silent -location -mc 301,302,303,307,308 -nc \
                -threads "${HTTPX_THREADS:-50}" -rl "${HTTPX_RATELIMIT:-150}" 2>/dev/null \
            | grep -i 'evil.com' \
            | awk '{print "[MEDIUM] Open Redirect: "$0}' >> "$out" || true
    done
    while IFS= read -r line; do
        emit_finding "$(echo "$line" | awk '{print $NF}')" "httpx-redirect" "medium" "Open Redirect" "$(echo "$line" | awk '{print $NF}')" "$line"
    done < "$out"
    end_func "$(count_lines "$out") findings → ${out}" "$fn"
}

# ---------------------------------------------------------------------------
run_host_header_injection() {
    local fn="run_host_header_injection"
    [[ "${HOST_HEADER_INJECTION:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    [[ ! -s "$(_web_targets)" ]] && { log_warn "hhi: no web targets"; return 0; }
    start_func "$fn" "Host Header Injection"
    local out="${RAW}/host_header.txt"; : > "$out"
    local -a hdrs=("X-Forwarded-Host: evil.com" "X-Host: evil.com" "Host: evil.com")
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        for h in "${hdrs[@]}"; do
            local resp; resp=$(curl -sk --max-time 10 -H "$h" "$url" 2>/dev/null || true)
            if echo "$resp" | grep -qi 'evil.com' 2>/dev/null; then
                echo "[HIGH] HHI via ${h%%:*}: $url" >> "$out"
                emit_finding "$url" "curl-hhi" "high" "Host Header Injection" "$url" "header: $h"
                break
            fi
        done
    done < <(head -n "${DEEP_LIMIT:-500}" "$(_web_targets)")
    end_func "$(count_lines "$out") findings → ${out}" "$fn"
}

# ---------------------------------------------------------------------------
run_crlf_check() {
    local fn="run_crlf_check"
    [[ "${CRLF_CHECKS:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    require_tool crlfuzz || return 0
    [[ ! -s "$(_web_targets)" ]] && { log_warn "crlf: no web targets"; return 0; }
    start_func "$fn" "CRLF Injection"
    local out="${RAW}/crlf.txt"
    run_tool crlfuzz -l "$(_web_targets)" -o "$out" 2>>"${WORKSPACE}/logs/crlf.log" || true
    while IFS= read -r line; do
        emit_finding "$line" "crlfuzz" "medium" "CRLF Injection" "$line"
    done < "$out"
    end_func "$(count_lines "$out") findings → ${out}" "$fn"
}

# ---------------------------------------------------------------------------
run_webcache_check() {
    local fn="run_webcache_check"
    [[ "${WEBCACHE:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    require_tool Web-Cache-Vulnerability-Scanner || return 0
    [[ ! -s "$(_web_targets)" ]] && { log_warn "webcache: no web targets"; return 0; }
    start_func "$fn" "Web Cache Poisoning"
    local out="${RAW}/webcache.txt"
    Web-Cache-Vulnerability-Scanner -u "file:$(_web_targets)" -v 0 2>/dev/null \
        | grep -iE 'vulnerable|HIT|poisoned' >> "$out" || true
    while IFS= read -r line; do
        emit_finding "$(echo "$line" | awk '{print $1}')" "wcvs" "high" "Web Cache Poisoning" "$(echo "$line" | awk '{print $1}')" "$line"
    done < "$out"
    end_func "$(count_lines "$out") findings → ${out}" "$fn"
}

# ---------------------------------------------------------------------------
run_xss() {
    local fn="run_xss"
    [[ "${XSS:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    require_tool dalfox || return 0
    local xss_input="${GF}/xss.txt"
    [[ ! -s "$xss_input" ]] && { log_warn "xss: no gf/xss.txt — run URL discovery first"; return 0; }
    start_func "$fn" "XSS (dalfox)"

    local reflected="${TMP}/xss_reflected.txt"
    if command -v qsreplace >/dev/null 2>&1 && command -v Gxss >/dev/null 2>&1; then
        qsreplace FUZZ < "$xss_input" | sed '/FUZZ/!d' \
            | Gxss -c 100 -p Xss | qsreplace FUZZ | sed '/FUZZ/!d' \
            > "$reflected" 2>/dev/null || cp "$xss_input" "$reflected"
    else
        qsreplace FUZZ < "$xss_input" | sed '/FUZZ/!d' > "$reflected" 2>/dev/null || cp "$xss_input" "$reflected"
    fi

    [[ ! -s "$reflected" ]] && { log_warn "xss: no reflected candidates"; return 0; }
    local out="${RAW}/xss.txt"
    local opts="-w ${DALFOX_THREADS:-30}"
    [[ -n "${XSS_SERVER:-}" ]] && opts="-b ${XSS_SERVER} ${opts}"

    run_tool dalfox pipe --silence --no-color --no-spinner \
        --only-poc r --ignore-return 302,404,403 --skip-bav \
        $opts < "$reflected" >> "$out" 2>>"${WORKSPACE}/logs/dalfox.log" || true

    while IFS= read -r line; do
        emit_finding "$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1)" "dalfox" "high" "XSS" "$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1)" "$line"
    done < "$out"
    end_func "$(count_lines "$out") XSS findings → ${out}" "$fn"
}

# ---------------------------------------------------------------------------
run_ssrf_check() {
    local fn="run_ssrf_check"
    [[ "${SSRF_CHECKS:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    require_tool ffuf || return 0
    local ssrf_input="${GF}/ssrf.txt"
    [[ ! -s "$ssrf_input" ]] && { log_warn "ssrf: no gf/ssrf.txt"; return 0; }
    start_func "$fn" "SSRF Checks"

    local collab="${COLLAB_SERVER:-}"
    local interact_pid=""
    if [[ -z "$collab" ]] && command -v interactsh-client >/dev/null 2>&1; then
        interactsh-client &> "${TMP}/ssrf_callback.txt" &
        interact_pid=$!
        sleep 2
        collab="FFUFHASH.$(tail -n1 "${TMP}/ssrf_callback.txt" | cut -c16-)"
    fi

    local tmp_ssrf="${TMP}/tmp_ssrf.txt"; : > "$tmp_ssrf"
    qsreplace "$collab"         < "$ssrf_input" >> "$tmp_ssrf" 2>/dev/null || true
    qsreplace "http://$collab"  < "$ssrf_input" >> "$tmp_ssrf" 2>/dev/null || true
    sort -u "$tmp_ssrf" -o "$tmp_ssrf"

    local out="${RAW}/ssrf_requested.txt"
    run_tool ffuf -v -H "${HEADER}" -t "${FFUF_THREADS:-40}" \
        -w "$tmp_ssrf" -u "FUZZ" -o "${TMP}/ssrf_ffuf.json" \
        2>/dev/null || true
    [[ -s "${TMP}/ssrf_ffuf.json" ]] \
        && jq -r '.results[]?.url // empty' "${TMP}/ssrf_ffuf.json" 2>/dev/null >> "$out" || true

    sleep "${SSRF_CALLBACK_WAIT:-15}"
    [[ -n "$interact_pid" ]] && kill "$interact_pid" 2>/dev/null || true

    if [[ -s "${TMP}/ssrf_callback.txt" ]]; then
        tail -n +11 "${TMP}/ssrf_callback.txt" > "${RAW}/ssrf_callback.txt"
        while IFS= read -r line; do
            emit_finding "unknown" "interactsh" "high" "SSRF OOB Callback" "unknown" "$line"
        done < "${RAW}/ssrf_callback.txt"
    fi

    end_func "$(count_lines "$out") SSRF candidates" "$fn"
}

# ---------------------------------------------------------------------------
run_lfi() {
    local fn="run_lfi"
    [[ "${LFI:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    require_tool ffuf || return 0
    local lfi_input="${GF}/lfi.txt"
    [[ ! -s "$lfi_input" ]] && { log_warn "lfi: no gf/lfi.txt"; return 0; }
    [[ ! -f "${LFI_WORDLIST:-}" ]] && { log_warn "lfi: LFI_WORDLIST not found at '${LFI_WORDLIST}'"; return 0; }
    start_func "$fn" "LFI Fuzzing"

    local tmp_lfi="${TMP}/tmp_lfi.txt"
    qsreplace "FUZZ" < "$lfi_input" | sed '/FUZZ/!d' > "$tmp_lfi" 2>/dev/null

    local url_count; url_count=$(count_lines "$tmp_lfi")
    if [[ "${DEEP:-false}" != "true" ]] && [[ $url_count -gt "${DEEP_LIMIT:-500}" ]]; then
        end_func "Too many URLs ($url_count) — use DEEP=true" "$fn"; return 0
    fi

    local out="${RAW}/lfi.txt"
    while IFS= read -r target; do
        [[ -z "$target" ]] && continue
        ffuf -v -r -t "${FFUF_THREADS:-40}" -H "${HEADER}" \
            -w "${LFI_WORDLIST}" -u "$target" -mr "root:|\\[boot loader\\]" \
            -o "${TMP}/lfi_tmp.json" 2>/dev/null || true
        [[ -s "${TMP}/lfi_tmp.json" ]] \
            && jq -r '.results[]?.url // empty' "${TMP}/lfi_tmp.json" 2>/dev/null \
            | tee -a "$out" | while IFS= read -r u; do
                emit_finding "$u" "ffuf-lfi" "high" "Local File Inclusion" "$u"
            done || true
    done < "$tmp_lfi"

    end_func "$(count_lines "$out") LFI findings" "$fn"
}

# ---------------------------------------------------------------------------
run_ssti() {
    local fn="run_ssti"
    [[ "${SSTI:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    local ssti_input="${GF}/ssti.txt"
    [[ ! -s "$ssti_input" ]] && { log_warn "ssti: no gf/ssti.txt"; return 0; }
    start_func "$fn" "SSTI Detection"

    local tmp_ssti="${TMP}/tmp_ssti.txt"
    qsreplace "FUZZ" < "$ssti_input" | sed '/FUZZ/!d' > "$tmp_ssti" 2>/dev/null
    local out="${RAW}/ssti.txt"

    if command -v TInjA >/dev/null 2>&1; then
        local report_dir="${TMP}/TInjA"; mkdir -p "$report_dir"
        local -a cmd=(TInjA url --reportpath "${report_dir}/" --ratelimit "${TInjA_RATELIMIT:-0}" \
                      --timeout "${TInjA_TIMEOUT:-15}" --verbosity 0)
        [[ -n "${HEADER:-}" ]]        && cmd+=(-H "${HEADER}")
        [[ -n "${COOKIE_HEADER:-}" ]] && cmd+=(-H "Cookie: ${COOKIE_HEADER}")
        while IFS= read -r u; do [[ -n "$u" ]] && cmd+=(--url "$u"); done < "$tmp_ssti"
        run_tool "${cmd[@]}" 2>/dev/null || true
        local rpt; rpt=$(ls -1t "${report_dir}"/*.jsonl 2>/dev/null | head -1 || true)
        if [[ -s "$rpt" ]]; then
            jq -r 'select((.isWebpageVulnerable==true) or any(.parameters[]?;.isParameterVulnerable==true))
                   | (.url//"")+" [certainty:"+(.certainty//"?")+"]"' "$rpt" 2>/dev/null \
                | tee -a "$out" | while IFS= read -r line; do
                    emit_finding "$(echo "$line"|awk '{print $1}')" "TInjA" "high" "SSTI" "$(echo "$line"|awk '{print $1}')" "$line"
                done || true
        fi
    elif command -v sstimap >/dev/null 2>&1; then
        run_tool sstimap --load-urls "$tmp_ssti" --no-color --level 1 2>/dev/null \
            | grep -i 'confirmed\|identified' | grep -oP 'https?://[^\s]+' \
            | tee -a "$out" | while IFS= read -r u; do
                emit_finding "$u" "sstimap" "high" "SSTI" "$u"
            done || true
    else
        log_warn "ssti: neither TInjA nor sstimap found — skipping"
    fi
    end_func "$(count_lines "$out") SSTI findings" "$fn"
}

# ---------------------------------------------------------------------------
run_sqli() {
    local fn="run_sqli"
    [[ "${SQLI:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    local sqli_input="${GF}/sqli.txt"
    [[ ! -s "$sqli_input" ]] && { log_warn "sqli: no gf/sqli.txt"; return 0; }
    start_func "$fn" "SQLi Testing"

    local tmp_sqli="${TMP}/tmp_sqli.txt"
    qsreplace "FUZZ" < "$sqli_input" | sed '/FUZZ/!d' > "$tmp_sqli" 2>/dev/null

    if [[ "${SQLMAP:-true}" == "true" ]] && command -v sqlmap >/dev/null 2>&1; then
        local level=1 risk=1
        [[ "${DEEP:-false}" == "true" ]] && level=3 && risk=2
        ensure_dirs "${RAW}/sqlmap"
        run_tool sqlmap -m "$tmp_sqli" \
            --level "$level" --risk "$risk" \
            -b -o --smart --batch --disable-coloring --random-agent \
            --threads "${SQLMAP_THREADS:-4}" \
            --output-dir="${RAW}/sqlmap" 2>>"${WORKSPACE}/logs/sqlmap.log" || true
        grep -rh "found" "${RAW}/sqlmap" 2>/dev/null | while IFS= read -r line; do
            emit_finding "unknown" "sqlmap" "high" "SQL Injection" "unknown" "$line"
        done
    fi
    end_func "SQLi scan complete — results in ${RAW}/sqlmap" "$fn"
}

# ---------------------------------------------------------------------------
run_command_injection() {
    local fn="run_command_injection"
    [[ "${COMM_INJ:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    require_tool commix || return 0
    local rce_input="${GF}/rce.txt"
    [[ ! -s "$rce_input" ]] && { log_warn "cmdinj: no gf/rce.txt"; return 0; }
    start_func "$fn" "Command Injection (commix)"
    local tmp_rce="${TMP}/tmp_rce.txt"
    qsreplace "FUZZ" < "$rce_input" | sed '/FUZZ/!d' > "$tmp_rce" 2>/dev/null
    ensure_dirs "${RAW}/command_injection"
    run_tool commix --batch -m "$tmp_rce" \
        --output-dir "${RAW}/command_injection" 2>>"${WORKSPACE}/logs/commix.log" || true
    end_func "Command injection scan complete" "$fn"
}

# ---------------------------------------------------------------------------
run_4xx_bypass() {
    local fn="run_4xx_bypass"
    [[ "${BYPASSER4XX:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    require_tool nomore403 || return 0
    start_func "$fn" "4XX Bypass"
    local candidates="${TMP}/403test.txt"; : > "$candidates"

    # Collect 403/401 targets from web probing
    jq -r '
        .[] |
        select(.isHttpAlive==true) |
        select(.httpMetadata!=null) |
        (.httpMetadata | fromjson? // {}) |
        select(.statusCode==403 or .statusCode==401) |
        .url // empty
    ' "${WORKSPACE}/targets/../../../asm_asset.json" 2>/dev/null >> "$candidates" || true

    [[ ! -s "$candidates" ]] && { end_func "No 4xx targets found" "$fn"; return 0; }
    local out="${RAW}/4xxbypass.txt"
    nomore403 < "$candidates" > "$out" 2>>"${WORKSPACE}/logs/nomore403.log" || true
    while IFS= read -r line; do
        emit_finding "$(echo "$line"|awk '{print $1}')" "nomore403" "medium" "4xx Bypass" "$(echo "$line"|awk '{print $1}')" "$line"
    done < "$out"
    end_func "$(count_lines "$out") bypass findings" "$fn"
}

# ---------------------------------------------------------------------------
run_smuggling() {
    local fn="run_smuggling"
    [[ "${SMUGGLING:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    require_tool smugglex || return 0
    [[ ! -s "$(_web_targets)" ]] && { log_warn "smuggling: no web targets"; return 0; }
    start_func "$fn" "HTTP Request Smuggling"
    local out="${RAW}/smuggling.txt"
    cat "$(_web_targets)" | smugglex -f plain -o "${TMP}/smuggling_raw.txt" \
        2>>"${WORKSPACE}/logs/smuggling.log" || true
    [[ -s "${TMP}/smuggling_raw.txt" ]] \
        && jq -c . < "${TMP}/smuggling_raw.txt" 2>/dev/null >> "$out" || true
    while IFS= read -r line; do
        local url; url=$(echo "$line" | jq -r '.url // empty' 2>/dev/null || true)
        emit_finding "${url:-unknown}" "smugglex" "high" "HTTP Request Smuggling" "${url:-unknown}" "$line"
    done < "$out"
    end_func "$(count_lines "$out") smuggling findings" "$fn"
}
