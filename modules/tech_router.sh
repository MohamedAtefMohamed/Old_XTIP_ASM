#!/usr/bin/env bash
# =============================================================================
#  modules/tech_router.sh  —  Technology-aware scan routing
#
#  Reads:  $WORKSPACE/targets/tech_map.json (from target_prep.sh)
#  Writes: $WORKSPACE/.tmp/tech_routing/<tech>_targets.txt
#
#  Mirrors the routing logic in XTIP_ASM_v2.0/modules/web.sh (cms_scanner)
#  and the tech_specific_scanners() dispatch in vulns.sh.
# =============================================================================

route_by_technology() {
    local fn="route_by_technology"

    if [[ "${TECH_ROUTING:-true}" != "true" ]]; then
        skip_func "$fn" "TECH_ROUTING disabled"; return 0
    fi
    if already_done "$fn"; then skip_func "$fn" "already processed"; return 0; fi
    start_func "$fn" "Technology-Based Scan Routing"

    local tech_map="${WORKSPACE}/targets/tech_map.json"
    local routing_dir="${WORKSPACE}/.tmp/tech_routing"
    ensure_dirs "$routing_dir" || return 1

    if [[ ! -s "$tech_map" ]]; then
        log_warn "  No tech_map.json found — all tech-specific scanners will be skipped"
        end_func "No technology data available" "$fn"
        return 0
    fi

    # -------------------------------------------------------------------------
    # Technology routing table
    # Each entry: "<tech_keyword_regex>|<output_file_prefix>"
    # Keywords are case-insensitive matches against the technologies[] array
    # -------------------------------------------------------------------------
    local -a ROUTING_TABLE=(
        "wordpress|wp-engine|woocommerce|elementor|wp plugin|wp theme|nitropack"
        "wordpress"

        "joomla"
        "joomla"

        "drupal"
        "drupal"

        "magento"
        "magento"

        "moodle"
        "moodle"

        "spring|spring-boot|springboot"
        "springboot"

        "jenkins"
        "jenkins"

        "jira|confluence|bitbucket"
        "jira"

        "jboss|wildfly"
        "jboss"

        "apache tomcat|tomcat"
        "tomcat"

        "weblogic"
        "weblogic"

        "gitlab"
        "gitlab"

        "grafana"
        "grafana"

        "kibana|elasticsearch"
        "kibana"

        "laravel|symfony"
        "laravel"

        "phpmyadmin"
        "phpmyadmin"

        "cpanel|whm"
        "cpanel"

        "next.js|nextjs"
        "nextjs"

        "node.js|nodejs|express"
        "nodejs"

        "django"
        "django"

        "php"
        "php"
    )

    # -------------------------------------------------------------------------
    # Route each asset's URL to the appropriate target files
    # -------------------------------------------------------------------------
    local total_routed=0

    # Process routing table in pairs (regex, prefix)
    local i
    for (( i=0; i<${#ROUTING_TABLE[@]}; i+=2 )); do
        local pattern="${ROUTING_TABLE[$i]}"
        local prefix="${ROUTING_TABLE[$((i+1))]}"
        local outfile="${routing_dir}/${prefix}_targets.txt"

        # jq filter: check if any technology matches the pattern (case-insensitive)
        local matched
        matched=$(jq -r --arg pat "$pattern" '
            select(
                (.technologies // []) |
                map(ascii_downcase) |
                any(test($pat; "i"))
            ) |
            .url // empty
        ' "$tech_map" 2>/dev/null | grep -E '^https?://' | sort -u)

        if [[ -n "$matched" ]]; then
            echo "$matched" > "$outfile"
            local count; count=$(echo "$matched" | grep -c .)
            log_info "  → ${prefix}: ${count} target(s)"
            total_routed=$(( total_routed + count ))
        fi
    done

    # -------------------------------------------------------------------------
    # Also create a "general_web" list: HTTP-alive with no specific tech match
    # -------------------------------------------------------------------------
    local all_routed_urls="${routing_dir}/.all_routed.tmp"
    cat "${routing_dir}"/*_targets.txt 2>/dev/null | sort -u > "$all_routed_urls"
    local web_targets="${WORKSPACE}/targets/web_targets.txt"
    if [[ -s "$web_targets" ]]; then
        comm -23 <(sort -u "$web_targets") <(sort -u "$all_routed_urls") \
            > "${routing_dir}/general_web_targets.txt" 2>/dev/null
        local gen_count; gen_count=$(count_lines "${routing_dir}/general_web_targets.txt")
        [[ $gen_count -gt 0 ]] && log_info "  → general_web (no specific tech): ${gen_count} target(s)"
    fi
    rm -f "$all_routed_urls"

    # -------------------------------------------------------------------------
    # Emit a routing summary
    # -------------------------------------------------------------------------
    {
        echo "=== Technology Routing Summary ==="
        for f in "${routing_dir}"/*_targets.txt; do
            [[ -f "$f" ]] || continue
            local tech; tech=$(basename "$f" _targets.txt)
            printf "  %-20s %d\n" "$tech" "$(count_lines "$f")"
        done
        echo "  Total routed URLs: $total_routed"
    } | tee "${routing_dir}/routing_summary.txt" >&2

    end_func "Tech routing complete — results in ${routing_dir}" "$fn"
}
