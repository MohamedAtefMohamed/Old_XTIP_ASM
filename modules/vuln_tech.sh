#!/usr/bin/env bash
# modules/vuln_tech.sh — Technology-specific scanners
# Ports: tech_specific_scanners() from XTIP_ASM_v2.0/modules/vulns.sh
# Calls _nuclei_tag_scan from vuln_nuclei.sh for nuclei-based checks

RAW="${WORKSPACE}/results/raw"
TECH_SCANS="${WORKSPACE}/results/tech_scans"
ROUTING="${WORKSPACE}/.tmp/tech_routing"
TMP="${WORKSPACE}/.tmp"

_tech_input() { echo "${ROUTING}/${1}_targets.txt"; }
_tech_out()   { echo "${TECH_SCANS}/nuclei_${1}.txt"; }

# ---------------------------------------------------------------------------
run_tech_specific_scanners() {
    local fn="run_tech_specific_scanners"
    [[ "${ADAPTIVE_TECH_SCANNING:-true}" != "true" ]] && { skip_func "$fn" "disabled"; return 0; }
    already_done "$fn" && { skip_func "$fn" "processed"; return 0; }
    start_func "$fn" "Adaptive Technology-Specific Scanners"
    ensure_dirs "$TECH_SCANS" || return 1

    # -----------------------------------------------------------------------
    # WordPress
    # -----------------------------------------------------------------------
    if [[ -s "$(_tech_input wordpress)" ]]; then
        _nuclei_tag_scan "WordPress" "wordpress,wp-plugin,wp-theme" \
            "$(_tech_input wordpress)" "$(_tech_out wordpress)"
        if command -v wpscan >/dev/null 2>&1; then
            while IFS= read -r wp_url; do
                [[ -z "$wp_url" ]] && continue
                local host; host=$(echo "$wp_url" | awk -F/ '{print $3}' | tr ':' '_')
                local wout="${TECH_SCANS}/wpscan_${host}.txt"
                local wpscan_args=(--url "$wp_url" --random-user-agent
                    --disable-tls-checks -e vp,vt,tt,cb,dbe,u,m -f cli-no-color)
                [[ -n "${WPSCAN_API_TOKEN:-}" ]] && wpscan_args+=(--api-token "$WPSCAN_API_TOKEN")
                run_tool wpscan "${wpscan_args[@]}" > "$wout" 2>>"${WORKSPACE}/logs/wpscan.log" || true
                grep -iE 'VULNERABILITY|vulnerability|CVE|CRITICAL|HIGH|MEDIUM' "$wout" 2>/dev/null \
                    | while IFS= read -r line; do
                        emit_finding "$wp_url" "wpscan" "high" "WordPress Vulnerability" "$wp_url" "$line"
                    done
            done < "$(_tech_input wordpress)"
        fi
    fi

    # -----------------------------------------------------------------------
    # Joomla
    # -----------------------------------------------------------------------
    if [[ -s "$(_tech_input joomla)" ]]; then
        _nuclei_tag_scan "Joomla" "joomla" "$(_tech_input joomla)" "$(_tech_out joomla)"
        local joomscan_pl="${TOOLS_DIR}/joomscan/joomscan.pl"
        if [[ -f "$joomscan_pl" ]]; then
            while IFS= read -r url; do
                [[ -z "$url" ]] && continue
                local host; host=$(echo "$url" | awk -F/ '{print $3}' | tr ':' '_')
                run_tool perl "$joomscan_pl" -u "$url" --random-agent \
                    > "${TECH_SCANS}/joomscan_${host}.txt" 2>/dev/null || true
            done < "$(_tech_input joomla)"
        fi
    fi

    # -----------------------------------------------------------------------
    # Drupal
    # -----------------------------------------------------------------------
    if [[ -s "$(_tech_input drupal)" ]]; then
        _nuclei_tag_scan "Drupal" "drupal" "$(_tech_input drupal)" "$(_tech_out drupal)"
        local droopescan="${TOOLS_DIR}/droopescan/droopescan"
        if [[ -f "$droopescan" ]]; then
            while IFS= read -r url; do
                [[ -z "$url" ]] && continue
                local host; host=$(echo "$url" | awk -F/ '{print $3}' | tr ':' '_')
                python3 "$droopescan" scan drupal -u "$url" \
                    > "${TECH_SCANS}/droopescan_${host}.txt" 2>/dev/null || true
            done < "$(_tech_input drupal)"
        fi
    fi

    # -----------------------------------------------------------------------
    # Spring Boot
    # -----------------------------------------------------------------------
    if [[ -s "$(_tech_input springboot)" ]]; then
        _nuclei_tag_scan "SpringBoot" "springboot" "$(_tech_input springboot)" "$(_tech_out springboot)"
        local sb_scan="${TOOLS_DIR}/SpringBoot-Scan/SpringBoot-Scan.py"
        if [[ -f "$sb_scan" ]]; then
            while IFS= read -r url; do
                [[ -z "$url" ]] && continue
                local host; host=$(echo "$url" | awk -F/ '{print $3}' | tr ':' '_')
                python3 "$sb_scan" -u "$url" \
                    > "${TECH_SCANS}/springbootscan_${host}.txt" 2>/dev/null || true
            done < "$(_tech_input springboot)"
        fi
    fi

    # -----------------------------------------------------------------------
    # Jenkins
    # -----------------------------------------------------------------------
    if [[ -s "$(_tech_input jenkins)" ]]; then
        _nuclei_tag_scan "Jenkins" "jenkins" "$(_tech_input jenkins)" "$(_tech_out jenkins)"
    fi

    # -----------------------------------------------------------------------
    # Jira / Confluence / Atlassian
    # -----------------------------------------------------------------------
    if [[ -s "$(_tech_input jira)" ]]; then
        _nuclei_tag_scan "Atlassian" "atlassian,jira,confluence" \
            "$(_tech_input jira)" "$(_tech_out atlassian)"
        local jiralens="${TOOLS_DIR}/Jira-Lens/jira-lens.py"
        if [[ -f "$jiralens" ]]; then
            while IFS= read -r url; do
                [[ -z "$url" ]] && continue
                local host; host=$(echo "$url" | awk -F/ '{print $3}' | tr ':' '_')
                python3 "$jiralens" -u "$url" \
                    > "${TECH_SCANS}/jiralens_${host}.txt" 2>/dev/null || true
            done < "$(_tech_input jira)"
        fi
    fi

    # -----------------------------------------------------------------------
    # JBoss / WildFly
    # -----------------------------------------------------------------------
    if [[ -s "$(_tech_input jboss)" ]]; then
        _nuclei_tag_scan "JBoss" "jboss,wildfly" "$(_tech_input jboss)" "$(_tech_out jboss)"
        local jexboss="${TOOLS_DIR}/jexboss/jexboss.py"
        if [[ -f "$jexboss" ]]; then
            while IFS= read -r url; do
                [[ -z "$url" ]] && continue
                local host; host=$(echo "$url" | awk -F/ '{print $3}' | tr ':' '_')
                python3 "$jexboss" -u "$url" \
                    > "${TECH_SCANS}/jexboss_${host}.txt" 2>/dev/null || true
            done < "$(_tech_input jboss)"
        fi
    fi

    # -----------------------------------------------------------------------
    # Apache Tomcat
    # -----------------------------------------------------------------------
    if [[ -s "$(_tech_input tomcat)" ]]; then
        _nuclei_tag_scan "Tomcat" "tomcat" "$(_tech_input tomcat)" "$(_tech_out tomcat)"
    fi

    # -----------------------------------------------------------------------
    # WebLogic
    # -----------------------------------------------------------------------
    if [[ -s "$(_tech_input weblogic)" ]]; then
        _nuclei_tag_scan "WebLogic" "weblogic" "$(_tech_input weblogic)" "$(_tech_out weblogic)"
        local wls="${TOOLS_DIR}/WeblogicScan/WeblogicScan.py"
        if [[ -f "$wls" ]]; then
            while IFS= read -r url; do
                [[ -z "$url" ]] && continue
                local host; host=$(echo "$url" | awk -F/ '{print $3}' | tr ':' '_')
                python3 "$wls" -u "$url" \
                    > "${TECH_SCANS}/weblogicscan_${host}.txt" 2>/dev/null || true
            done < "$(_tech_input weblogic)"
        fi
    fi

    # -----------------------------------------------------------------------
    # AEM (Adobe Experience Manager)
    # -----------------------------------------------------------------------
    if [[ -s "$(_tech_input aem)" ]]; then
        _nuclei_tag_scan "AEM" "aem" "$(_tech_input aem)" "$(_tech_out aem)"
        local aem_h="${TOOLS_DIR}/aem-hacker/aem_hacker.py"
        if [[ -f "$aem_h" ]]; then
            while IFS= read -r url; do
                [[ -z "$url" ]] && continue
                local host; host=$(echo "$url" | awk -F/ '{print $3}' | tr ':' '_')
                python3 "$aem_h" -u "$url" --host "$host" \
                    > "${TECH_SCANS}/aemhacker_${host}.txt" 2>/dev/null || true
            done < "$(_tech_input aem)"
        fi
    fi

    # -----------------------------------------------------------------------
    # Magento, Moodle, GitLab, Grafana, Kibana, Laravel, phpMyAdmin, cPanel
    # -----------------------------------------------------------------------
    local -A CATCH_ALL=(
        [magento]="magento"
        [moodle]="moodle"
        [gitlab]="gitlab"
        [grafana]="grafana"
        [kibana]="kibana,elasticsearch"
        [laravel]="laravel,symfony"
        [phpmyadmin]="phpmyadmin"
        [cpanel]="cpanel"
        [nextjs]="next.js"
        [nodejs]="nodejs,node.js"
        [django]="django"
        [php]="php"
    )
    local tech
    for tech in "${!CATCH_ALL[@]}"; do
        if [[ -s "$(_tech_input "$tech")" ]]; then
            _nuclei_tag_scan "$tech" "${CATCH_ALL[$tech]}" \
                "$(_tech_input "$tech")" "$(_tech_out "$tech")"
        fi
    done

    # -----------------------------------------------------------------------
    # Emit findings from all tech-scan txt files
    # -----------------------------------------------------------------------
    local total=0
    for f in "${TECH_SCANS}"/*.txt; do
        [[ -f "$f" ]] || continue
        local cnt; cnt=$(count_lines "$f")
        (( total += cnt ))
        local toolname; toolname=$(basename "$f" .txt)
        while IFS= read -r line; do
            local sev="medium"
            echo "$line" | grep -qi 'critical\|CRITICAL' && sev="critical"
            echo "$line" | grep -qi 'high\|HIGH\|CVE'    && sev="high"
            emit_finding "tech_scan" "$toolname" "$sev" "Tech-Specific Finding" "tech_scan" "$line"
        done < "$f"
    done

    end_func "Found ${total} tech-specific findings → ${TECH_SCANS}" "$fn"
}
