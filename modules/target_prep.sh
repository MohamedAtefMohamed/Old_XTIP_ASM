#!/usr/bin/env bash
# =============================================================================
#  modules/target_prep.sh  —  Parse asm_asset.json → scan-ready target files
#
#  Input:  $ASSET_JSON  (asm_asset.json)
#  Output: $WORKSPACE/targets/
#    web_targets.txt       — HTTP-alive base URLs (one per line)
#    all_subdomains.txt    — every subdomain (alive or not)
#    alive_subdomains.txt  — DNS-alive subdomains
#    ips.txt               — unique resolved IPs
#    https_hosts.txt       — hosts with HTTPS (port 443)
#    ssh_hosts.txt         — hosts with SSH (port 22)
#    port_map.json         — per-subdomain port info (JSONL)
#    tech_map.json         — per-subdomain technology list (JSONL)
#    tls_info.txt          — TLS summary per host
#    expiring_certs.txt    — certs expiring within 30 days
#    cloud_assets.txt      — discovered cloud assets
#    non_http_ports.txt    — open ports that are NOT 80/443
# =============================================================================

prepare_targets() {
    local fn="prepare_targets"

    if already_done "$fn"; then skip_func "$fn" "already processed"; return 0; fi
    start_func "$fn" "Target Preparation (JSON → scan targets)"

    if [[ ! -f "$ASSET_JSON" ]]; then
        log_fail "Asset file not found: $ASSET_JSON"
        return 1
    fi

    if ! command -v jq >/dev/null 2>&1; then
        log_fail "jq is required for target parsing but was not found in PATH"
        return 1
    fi

    local tdir="${WORKSPACE}/targets"
    ensure_dirs "$tdir" || return 1

    log_info "  Parsing $ASSET_JSON ..."

    # -------------------------------------------------------------------------
    # 0. Sanitize JSON (Remove trailing commas)
    # -------------------------------------------------------------------------
    local safe_json="${WORKSPACE}/.tmp/asm_asset_clean.json"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c '
import sys, re
with open(sys.argv[1], "r", encoding="utf-8") as f: c = f.read()
with open(sys.argv[2], "w", encoding="utf-8") as f: f.write(re.sub(r",\s*([\]}])", r"\1", c))
' "$ASSET_JSON" "$safe_json" 2>/dev/null || cp "$ASSET_JSON" "$safe_json"
    elif command -v perl >/dev/null 2>&1; then
        perl -0777 -pe "s/,\s*([}\]])/\$1/g" "$ASSET_JSON" > "$safe_json" 2>/dev/null || cp "$ASSET_JSON" "$safe_json"
    else
        cp "$ASSET_JSON" "$safe_json"
    fi
    local SRC_JSON="$safe_json"

    # -------------------------------------------------------------------------
    # 1. All subdomains
    # -------------------------------------------------------------------------
    { jq -r '.[].subdomain // empty' "$SRC_JSON" 2>/dev/null || true; } \
        | sort -u > "${tdir}/all_subdomains.txt"
    log_info "  → all_subdomains.txt: $(count_lines "${tdir}/all_subdomains.txt") entries"

    # -------------------------------------------------------------------------
    # 2. DNS-alive subdomains  (isAlive == true)
    # -------------------------------------------------------------------------
    { jq -r '.[] | select(.isAlive == true) | .subdomain // empty' "$SRC_JSON" 2>/dev/null || true; } \
        | sort -u > "${tdir}/alive_subdomains.txt"
    log_info "  → alive_subdomains.txt: $(count_lines "${tdir}/alive_subdomains.txt") entries"

    # -------------------------------------------------------------------------
    # 3. HTTP-alive base URLs  (isHttpAlive == true, httpMetadata.url present)
    # -------------------------------------------------------------------------
    {
        jq -r '
            .[] |
            select(.isHttpAlive == true) |
            select(.httpMetadata != null) |
            (.httpMetadata | fromjson? // {}) |
            .url // empty
        ' "$SRC_JSON" 2>/dev/null || true
    } | grep -E '^https?://' \
      | sed 's#/*$##' \
      | sort -u > "${tdir}/web_targets.txt" || true
    log_info "  → web_targets.txt: $(count_lines "${tdir}/web_targets.txt") URLs"

    # -------------------------------------------------------------------------
    # 4. Resolved IPs  (flatten resolvedIps JSON arrays)
    # -------------------------------------------------------------------------
    {
        jq -r '
            .[] |
            select(.resolvedIps != null and .resolvedIps != "[]") |
            (.resolvedIps | fromjson? // []) |
            .[]
        ' "$SRC_JSON" 2>/dev/null || true
    } | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
      | grep -vE '^(127\.|10\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' \
      | sort -u > "${tdir}/ips.txt" || true
    log_info "  → ips.txt: $(count_lines "${tdir}/ips.txt") unique IPs"

    # -------------------------------------------------------------------------
    # 5. HTTPS hosts  (port 443 open)
    # -------------------------------------------------------------------------
    {
        jq -r '
            .[] |
            select(.portMetadata != null) |
            . as $asset |
            (.portMetadata | fromjson? // {}) |
            to_entries[] |
            select(.key == "443" and .value.state == "open") |
            $asset.subdomain
        ' "$SRC_JSON" 2>/dev/null || true
    } | sort -u > "${tdir}/https_hosts.txt" || true
    log_info "  → https_hosts.txt: $(count_lines "${tdir}/https_hosts.txt") hosts"

    # -------------------------------------------------------------------------
    # 6. SSH hosts  (port 22 open)
    # -------------------------------------------------------------------------
    {
        jq -r '
            .[] |
            select(.portMetadata != null) |
            . as $asset |
            (.portMetadata | fromjson? // {}) |
            to_entries[] |
            select(.key == "22" and .value.state == "open") |
            $asset.subdomain
        ' "$SRC_JSON" 2>/dev/null || true
    } | sort -u > "${tdir}/ssh_hosts.txt" || true
    log_info "  → ssh_hosts.txt: $(count_lines "${tdir}/ssh_hosts.txt") hosts"

    # -------------------------------------------------------------------------
    # 7. Port map JSONL  (one line per asset, with open ports)
    # -------------------------------------------------------------------------
    jq -c '
        .[] |
        select(.portMetadata != null) |
        {
            subdomain: .subdomain,
            ip: (.resolvedIps | try fromjson | .[0] // null),
            ports: (.portMetadata | try fromjson | to_entries |
                    map(select(.value.state == "open") |
                        {port: .key, service: .value.service, protocol: .value.protocol}))
        }
    ' "$SRC_JSON" 2>/dev/null > "${tdir}/port_map.json" || true
    log_info "  → port_map.json: $(count_lines "${tdir}/port_map.json") entries"

    # -------------------------------------------------------------------------
    # 8. Non-web open ports (not 80/443)
    # -------------------------------------------------------------------------
    {
        jq -r '
            .[] |
            select(.portMetadata != null) |
            . as $asset |
            (.portMetadata | fromjson? // {}) |
            to_entries[] |
            select(.value.state == "open") |
            select(.key != "80" and .key != "443") |
            "\($asset.subdomain):\(.key) [\(.value.service)]"
        ' "$SRC_JSON" 2>/dev/null || true
    } | sort -u > "${tdir}/non_http_ports.txt" || true
    log_info "  → non_http_ports.txt: $(count_lines "${tdir}/non_http_ports.txt") entries"

    # -------------------------------------------------------------------------
    # 9. Technology map JSONL  (one line per asset with tech list)
    # -------------------------------------------------------------------------
    jq -c '
        .[] |
        select(.httpMetadata != null) |
        . as $asset |
        (.httpMetadata | fromjson? // {}) as $hm |
        select(($hm.technologies // []) | length > 0) |
        {
            subdomain: $asset.subdomain,
            url: $hm.url,
            technologies: ($hm.technologies // []),
            webServer: ($hm.webServer // null),
            statusCode: ($hm.statusCode // null)
        }
    ' "$SRC_JSON" 2>/dev/null > "${tdir}/tech_map.json" || true
    log_info "  → tech_map.json: $(count_lines "${tdir}/tech_map.json") entries"

    # -------------------------------------------------------------------------
    # 10. TLS summary
    # -------------------------------------------------------------------------
    jq -r '
        .[] |
        select(.tlsMetadata != null) |
        . as $asset |
        (.tlsMetadata | fromjson? // {}) as $tls |
        "\($asset.subdomain) | issuer=\($tls.issuer // "?") version=\($tls.version // "?") expiry=\($tls.notAfter // "?") days_left=\($tls.daysUntilExpiry // "?") expired=\($tls.isExpired // false)"
    ' "$SRC_JSON" 2>/dev/null > "${tdir}/tls_info.txt" || true
    log_info "  → tls_info.txt: $(count_lines "${tdir}/tls_info.txt") TLS entries"

    # -------------------------------------------------------------------------
    # 11. Expiring certificates (within 30 days or already expired)
    # -------------------------------------------------------------------------
    jq -r '
        .[] |
        select(.tlsMetadata != null) |
        . as $asset |
        (.tlsMetadata | fromjson? // {}) as $tls |
        select(
            ($tls.isExpired == true) or
            (($tls.daysUntilExpiry // 9999) <= 30)
        ) |
        "\($asset.subdomain) | days_left=\($tls.daysUntilExpiry // "EXPIRED") expired=\($tls.isExpired)"
    ' "$SRC_JSON" 2>/dev/null > "${tdir}/expiring_certs.txt" || true
    log_info "  → expiring_certs.txt: $(count_lines "${tdir}/expiring_certs.txt") entries"

    # -------------------------------------------------------------------------
    # 12. Cloud assets
    # -------------------------------------------------------------------------
    {
        jq -r '
            .[] |
            select(.cloudAssets != null) |
            (.cloudAssets | fromjson? // []) |
            .[] |
            "\(.provider) | \(.service) | \(.access) | \(.url)"
        ' "$SRC_JSON" 2>/dev/null || true
    } | sort -u > "${tdir}/cloud_assets.txt" || true
    log_info "  → cloud_assets.txt: $(count_lines "${tdir}/cloud_assets.txt") cloud assets"

    # -------------------------------------------------------------------------
    # 13. Summary statistics
    # -------------------------------------------------------------------------
    {
        echo "=== Target Preparation Summary ==="
        echo "Total assets:          $(jq 'length' "$SRC_JSON" 2>/dev/null || echo '?')"
        echo "Alive subdomains:      $(count_lines "${tdir}/alive_subdomains.txt")"
        echo "HTTP-alive targets:    $(count_lines "${tdir}/web_targets.txt")"
        echo "Unique IPs:            $(count_lines "${tdir}/ips.txt")"
        echo "HTTPS hosts:           $(count_lines "${tdir}/https_hosts.txt")"
        echo "SSH-exposed hosts:     $(count_lines "${tdir}/ssh_hosts.txt")"
        echo "Assets with tech:      $(count_lines "${tdir}/tech_map.json")"
        echo "Cloud assets:          $(count_lines "${tdir}/cloud_assets.txt")"
        echo "Expiring/expired certs:$(count_lines "${tdir}/expiring_certs.txt")"
    } > "${tdir}/prep_summary.txt"
    cat "${tdir}/prep_summary.txt" >&2

    end_func "Targets prepared in ${tdir}" "$fn"
}
