#!/usr/bin/env bash
# =============================================================================
#  modules/url_discovery.sh  —  Phase 0: URL crawling + passive collection
#
#  Input:  $WORKSPACE/targets/web_targets.txt   (from target_prep.sh)
#  Output:
#    $WORKSPACE/urls/katana_urls.txt
#    $WORKSPACE/urls/wayback_urls.txt
#    $WORKSPACE/urls/url_extract_nodupes.txt    (merged, deduped)
#    $WORKSPACE/gf/{xss,ssrf,lfi,ssti,rce,sqli,redirect}.txt
#
#  Mirrors the URL collection pipeline from XTIP_ASM_v2.0 (web.sh:urlchecks,
#  url_gf) — uses katana for active crawl + waybackurls for passive collection
#  then gf for pattern classification.
# =============================================================================

# ---------------------------------------------------------------------------
# KATANA — active web crawler
# ---------------------------------------------------------------------------
run_katana_crawl() {
    local fn="run_katana_crawl"

    if [[ "${CRAWL_KATANA:-true}" != "true" ]]; then
        skip_func "$fn" "CRAWL_KATANA disabled"; return 0
    fi
    if already_done "$fn"; then skip_func "$fn" "already processed"; return 0; fi

    local web_targets="${WORKSPACE}/targets/web_targets.txt"
    if [[ ! -s "$web_targets" ]]; then
        log_warn "  No web_targets.txt — skipping katana crawl"
        return 0
    fi
    if ! require_tool katana; then return 0; fi

    start_func "$fn" "Katana Active Crawl"
    local urls_dir="${WORKSPACE}/urls"
    ensure_dirs "$urls_dir" || return 1

    local katana_out="${urls_dir}/katana_urls.txt"
    local target_count; target_count=$(count_lines "$web_targets")
    log_info "  Crawling ${target_count} targets with katana (depth=${KATANA_DEPTH:-3})"

    local katana_args=(
        -list    "$web_targets"
        -d       "${KATANA_DEPTH:-3}"
        -c       "${KATANA_THREADS:-25}"
        -rl      "${KATANA_RATE_LIMIT:-150}"
        -timeout "${KATANA_TIMEOUT:-300}"
        -silent
        -nc
        -o       "$katana_out"
    )

    # Add headless mode if enabled
    if [[ "${KATANA_HEADLESS:-false}" == "true" ]]; then
        katana_args+=(-headless -strategy breadth-first)
    fi

    # Inject cookie if set
    if [[ -n "${COOKIE_HEADER:-}" ]]; then
        katana_args+=(-H "Cookie: ${COOKIE_HEADER}")
    fi

    run_tool katana "${katana_args[@]}" 2>>"${WORKSPACE}/logs/katana.log" || true

    local found; found=$(count_lines "$katana_out")
    log_info "  → katana_urls.txt: ${found} URLs crawled"
    end_func "Katana crawl complete (${found} URLs)" "$fn"
}

# ---------------------------------------------------------------------------
# WAYBACKURLS — passive historical URL collection
# ---------------------------------------------------------------------------
run_waybackurls() {
    local fn="run_waybackurls"

    if [[ "${CRAWL_WAYBACKURLS:-true}" != "true" ]]; then
        skip_func "$fn" "CRAWL_WAYBACKURLS disabled"; return 0
    fi
    if already_done "$fn"; then skip_func "$fn" "already processed"; return 0; fi

    if ! require_tool waybackurls; then return 0; fi

    local alive_subs="${WORKSPACE}/targets/alive_subdomains.txt"
    if [[ ! -s "$alive_subs" ]]; then
        log_warn "  No alive_subdomains.txt — skipping waybackurls"
        return 0
    fi

    start_func "$fn" "Waybackurls Passive URL Collection"
    local urls_dir="${WORKSPACE}/urls"
    ensure_dirs "$urls_dir" || return 1

    local wayback_out="${urls_dir}/wayback_urls.txt"
    local sub_count; sub_count=$(count_lines "$alive_subs")
    log_info "  Querying waybackurls for ${sub_count} subdomains..."

    : > "$wayback_out"
    while IFS= read -r subdomain; do
        [[ -z "$subdomain" ]] && continue
        if [[ "${WAYBACKURLS_LIMIT:-10000}" -gt 0 ]]; then
            waybackurls "$subdomain" 2>/dev/null \
                | head -n "${WAYBACKURLS_LIMIT:-10000}" \
                | grep -E '^https?://' \
                >> "$wayback_out" || true
        else
            waybackurls "$subdomain" 2>/dev/null \
                | grep -E '^https?://' \
                >> "$wayback_out" || true
        fi
    done < "$alive_subs"

    sort -u "$wayback_out" -o "$wayback_out"
    local found; found=$(count_lines "$wayback_out")
    log_info "  → wayback_urls.txt: ${found} historical URLs"
    end_func "Waybackurls complete (${found} URLs)" "$fn"
}

# ---------------------------------------------------------------------------
# URL MERGE + DEDUPLICATION
# ---------------------------------------------------------------------------
merge_urls() {
    local fn="merge_urls"

    if already_done "$fn"; then skip_func "$fn" "already processed"; return 0; fi
    start_func "$fn" "URL Merge & Deduplication"

    local urls_dir="${WORKSPACE}/urls"
    local merged="${urls_dir}/url_extract_nodupes.txt"

    : > "$merged"

    # Merge from all URL sources
    local src
    for src in \
        "${urls_dir}/katana_urls.txt" \
        "${urls_dir}/wayback_urls.txt"; do
        [[ -s "$src" ]] && cat "$src" >> "$merged"
    done

    # Also include root URLs from web_targets as baseline
    [[ -s "${WORKSPACE}/targets/web_targets.txt" ]] \
        && cat "${WORKSPACE}/targets/web_targets.txt" >> "$merged"

    # Deduplicate
    sort -u "$merged" -o "$merged"

    # Filter: keep only valid HTTP URLs
    grep -E '^https?://' "$merged" | sort -u > "${merged}.tmp" 2>/dev/null
    mv "${merged}.tmp" "$merged"

    local total; total=$(count_lines "$merged")
    log_info "  → url_extract_nodupes.txt: ${total} unique URLs"
    end_func "URL merge complete (${total} unique URLs)" "$fn"
}

# ---------------------------------------------------------------------------
# GF PATTERN CLASSIFICATION
# ---------------------------------------------------------------------------
# Mirrors v2.0 modules/web.sh url_gf() function
run_gf_patterns() {
    local fn="run_gf_patterns"

    if [[ "${GF_CLASSIFY:-true}" != "true" ]]; then
        skip_func "$fn" "GF_CLASSIFY disabled"; return 0
    fi
    if already_done "$fn"; then skip_func "$fn" "already processed"; return 0; fi

    if ! require_tool gf; then
        log_warn "  gf not found — DAST pattern classification skipped"
        log_warn "  Install: go install github.com/tomnomnom/gf@latest"
        log_warn "  Templates: https://github.com/1ndianl33t/Gf-Patterns"
        return 0
    fi

    local url_file="${WORKSPACE}/urls/url_extract_nodupes.txt"
    if [[ ! -s "$url_file" ]]; then
        log_warn "  No URLs to classify — run URL discovery first"
        return 0
    fi

    start_func "$fn" "GF Pattern Classification"
    local gf_dir="${WORKSPACE}/gf"
    ensure_dirs "$gf_dir" || return 1

    local url_count; url_count=$(count_lines "$url_file")
    log_info "  Classifying ${url_count} URLs with gf patterns..."

    # -------------------------------------------------------------------------
    # Pattern → output file mapping
    # -------------------------------------------------------------------------
    local -A GF_PATTERNS=(
        [xss]="xss.txt"
        [sqli]="sqli.txt"
        [ssrf]="ssrf.txt"
        [lfi]="lfi.txt"
        [ssti]="ssti.txt"
        [rce]="rce.txt"
        [redirect]="redirect.txt"
        [idor]="idor.txt"
        [debug_logic]="debug.txt"
    )

    local pattern outfile
    for pattern in "${!GF_PATTERNS[@]}"; do
        outfile="${gf_dir}/${GF_PATTERNS[$pattern]}"
        if gf "$pattern" < "$url_file" > "$outfile" 2>/dev/null; then
            local cnt; cnt=$(count_lines "$outfile")
            if [[ $cnt -gt 0 ]]; then
                log_info "  → gf/${GF_PATTERNS[$pattern]}: ${cnt} URLs"
            else
                rm -f "$outfile"   # remove empty files to avoid false-skips
            fi
        else
            log_warn "  gf pattern '$pattern' not found — skipping (install gf patterns)"
            rm -f "$outfile"
        fi
    done

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    local total_classified=0
    for f in "${gf_dir}"/*.txt; do
        [[ -f "$f" ]] && total_classified=$(( total_classified + $(count_lines "$f") ))
    done
    log_info "  Total classified entries across all patterns: ${total_classified}"

    end_func "GF classification complete" "$fn"
}

# ---------------------------------------------------------------------------
# PHASE 0 ORCHESTRATOR
# ---------------------------------------------------------------------------
run_url_discovery() {
    local fn="run_url_discovery"

    if [[ "${URL_DISCOVERY:-true}" != "true" ]]; then
        skip_func "$fn" "URL_DISCOVERY disabled"
        return 0
    fi

    log_info ""
    log_info "══ Phase 0: URL Discovery ════════════════════════════"

    # These run serially — each feeds the next
    run_serial "katana_crawl"    run_katana_crawl
    run_serial "waybackurls"     run_waybackurls
    run_serial "merge_urls"      merge_urls
    run_serial "gf_patterns"     run_gf_patterns
}
