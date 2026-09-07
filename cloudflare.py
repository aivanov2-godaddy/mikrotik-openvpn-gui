from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from deployment import cloudflare_country_allowlist_rule, normalize_cloudflare_hostname


API_BASE = "https://api.cloudflare.com/client/v4"
WAF_PHASE = "http_request_firewall_custom"
WAF_REF = "vpn_dashboard_bulgaria_only"
CONFIG_PHASE = "http_config_settings"
CONFIG_REF = "vpn_dashboard_strict_tls"


class CloudflareError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class WAFOperation:
    method: str
    path: str
    body: dict[str, Any]


class CloudflareAPI:
    def __init__(self, token: str, zone_id: str) -> None:
        if not token:
            raise CloudflareError("CLOUDFLARE_API_TOKEN is required")
        if not zone_id:
            raise CloudflareError("CLOUDFLARE_ZONE_ID is required")
        self.token = token
        self.zone_id = zone_id

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(
            API_BASE + path,
            data=payload,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "mikrotik-openvpn-gui/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                decoded = json.loads(response.read().decode())
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:1000]
            raise CloudflareError(f"Cloudflare HTTP {error.code}: {detail}") from None
        except (OSError, json.JSONDecodeError) as error:
            raise CloudflareError(f"Cloudflare request failed: {error}") from None
        if not decoded.get("success"):
            raise CloudflareError(f"Cloudflare API rejected request: {decoded.get('errors', [])}")
        return decoded.get("result")


def desired_rule(
    hostname: str, countries: tuple[str, ...], *, include_position: bool = True
) -> dict[str, Any]:
    return cloudflare_country_allowlist_rule(
        hostname, countries, include_position=include_position
    )


def desired_tls_rule(hostname: str, *, include_position: bool = True) -> dict[str, Any]:
    normalized_host = normalize_cloudflare_hostname(hostname)
    rule: dict[str, Any] = {
        "action": "set_config",
        "action_parameters": {"ssl": "strict"},
        "expression": f'(http.host eq "{normalized_host}")',
        "description": "VPN Dashboard: strict origin TLS",
        "enabled": True,
        "ref": CONFIG_REF,
    }
    if include_position:
        rule["position"] = {"index": 1}
    return rule


def plan_waf_operation(
    entrypoint: dict[str, Any] | None,
    *,
    zone_id: str,
    hostname: str,
    countries: tuple[str, ...],
) -> WAFOperation | None:
    if not countries:
        return None
    phase_path = f"/zones/{zone_id}/rulesets/phases/{WAF_PHASE}/entrypoint"
    if entrypoint is None:
        return WAFOperation(
            "PUT", phase_path,
            {"rules": [desired_rule(hostname, countries, include_position=False)]},
        )

    ruleset_id = str(entrypoint["id"])
    current = next((rule for rule in entrypoint.get("rules", []) if rule.get("ref") == WAF_REF), None)
    wanted = desired_rule(hostname, countries, include_position=False)
    if current is None:
        return WAFOperation(
            "POST",
            f"/zones/{zone_id}/rulesets/{ruleset_id}/rules",
            desired_rule(hostname, countries, include_position=True),
        )
    equivalent = all(current.get(key) == value for key, value in wanted.items())
    if equivalent:
        return None
    return WAFOperation(
        "PATCH",
        f"/zones/{zone_id}/rulesets/{ruleset_id}/rules/{current['id']}",
        desired_rule(hostname, countries, include_position=True),
    )


def plan_tls_operation(
    entrypoint: dict[str, Any] | None, *, zone_id: str, hostname: str
) -> WAFOperation | None:
    phase_path = f"/zones/{zone_id}/rulesets/phases/{CONFIG_PHASE}/entrypoint"
    if entrypoint is None:
        return WAFOperation(
            "PUT", phase_path, {"rules": [desired_tls_rule(hostname, include_position=False)]}
        )

    ruleset_id = str(entrypoint["id"])
    current = next((rule for rule in entrypoint.get("rules", []) if rule.get("ref") == CONFIG_REF), None)
    wanted = desired_tls_rule(hostname, include_position=False)
    if current is None:
        return WAFOperation(
            "POST",
            f"/zones/{zone_id}/rulesets/{ruleset_id}/rules",
            desired_tls_rule(hostname, include_position=True),
        )
    equivalent = all(current.get(key) == value for key, value in wanted.items())
    if equivalent:
        return None
    return WAFOperation(
        "PATCH",
        f"/zones/{zone_id}/rulesets/{ruleset_id}/rules/{current['id']}",
        desired_tls_rule(hostname, include_position=True),
    )


def get_entrypoint(api: CloudflareAPI, phase: str = WAF_PHASE) -> dict[str, Any] | None:
    path = f"/zones/{api.zone_id}/rulesets/phases/{phase}/entrypoint"
    try:
        return api.request("GET", path)
    except CloudflareError as error:
        if "HTTP 404" in str(error):
            return None
        raise


def dns_record(api: CloudflareAPI, hostname: str) -> dict[str, Any]:
    query = urllib.parse.urlencode({"type": "A", "name": hostname})
    records = api.request("GET", f"/zones/{api.zone_id}/dns_records?{query}")
    if len(records) != 1:
        raise CloudflareError(f"Expected one A record for {hostname}, found {len(records)}")
    return records[0]


def status(
    api: CloudflareAPI, hostname: str, *, include_dns: bool = False
) -> dict[str, Any]:
    entrypoint = get_entrypoint(api)
    config_entrypoint = get_entrypoint(api, CONFIG_PHASE)
    ssl = api.request("GET", f"/zones/{api.zone_id}/settings/ssl")
    rule = None if entrypoint is None else next(
        (item for item in entrypoint.get("rules", []) if item.get("ref") == WAF_REF), None
    )
    result = {
        "zone_ssl_mode": ssl.get("value"),
        "vpn_ssl_rule": None if config_entrypoint is None else next(
            (
                {
                    "action": item.get("action"),
                    "expression": item.get("expression"),
                    "settings": item.get("action_parameters"),
                    "enabled": item.get("enabled"),
                }
                for item in config_entrypoint.get("rules", [])
                if item.get("ref") == CONFIG_REF
            ),
            None,
        ),
        "country_allowlist_rule": None if rule is None else {
            "action": rule.get("action"), "expression": rule.get("expression"), "enabled": rule.get("enabled")
        },
    }
    if include_dns:
        record = dns_record(api, hostname)
        result["dns"] = {
            "name": record.get("name"),
            "content": record.get("content"),
            "proxied": record.get("proxied"),
        }
    return result


def apply_edge(
    api: CloudflareAPI,
    hostname: str,
    *,
    countries: tuple[str, ...] = (),
    proxy_dns: bool = False,
) -> dict[str, Any]:
    operation = plan_waf_operation(
        get_entrypoint(api), zone_id=api.zone_id,
        hostname=hostname, countries=countries,
    )
    if operation:
        api.request(operation.method, operation.path, operation.body)

    tls_operation = plan_tls_operation(
        get_entrypoint(api, CONFIG_PHASE), zone_id=api.zone_id, hostname=hostname
    )
    if tls_operation:
        api.request(tls_operation.method, tls_operation.path, tls_operation.body)
    if proxy_dns:
        record = dns_record(api, hostname)
        api.request(
            "PATCH",
            f"/zones/{api.zone_id}/dns_records/{record['id']}",
            {
                "type": "A",
                "name": hostname,
                "content": record["content"],
                "proxied": True,
                "ttl": 1,
            },
        )
    return status(api, hostname, include_dns=proxy_dns)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect or apply the VPN Dashboard Cloudflare edge policy")
    parser.add_argument(
        "--hostname", default=os.environ.get("CLOUDFLARE_PUBLIC_HOST", ""),
        help="public dashboard DNS hostname (or set CLOUDFLARE_PUBLIC_HOST)",
    )
    parser.add_argument(
        "--allow-country", action="append", default=[], metavar="ISO_CODE",
        help="optional repeatable two-letter country code for a host-scoped WAF allowlist",
    )
    parser.add_argument("--check", action="store_true", help="read current Cloudflare state")
    parser.add_argument("--proxy-dns", action="store_true", help="also set the selected A record to proxied")
    parser.add_argument("--apply-edge", action="store_true", help="apply explicit optional WAF, strict TLS, and DNS settings")
    args = parser.parse_args()
    try:
        hostname = normalize_cloudflare_hostname(args.hostname)
    except ValueError as error:
        parser.error(f"--hostname or CLOUDFLARE_PUBLIC_HOST: {error}")
    countries = tuple(args.allow_country)
    if not args.check and not args.apply_edge:
        print(
            json.dumps(
                {
                    "desired_waf_rule": (
                        desired_rule(hostname, countries) if countries else None
                    ),
                    "desired_tls_rule": desired_tls_rule(hostname),
                    "zone_ssl_mode": "unchanged",
                    "dns_proxy_requested": args.proxy_dns,
                },
                indent=2,
            )
        )
        return
    api = CloudflareAPI(
        os.environ.get("CLOUDFLARE_API_TOKEN", ""),
        os.environ.get("CLOUDFLARE_ZONE_ID", ""),
    )
    result = (
        apply_edge(api, hostname, countries=countries, proxy_dns=args.proxy_dns)
        if args.apply_edge else status(api, hostname, include_dns=args.proxy_dns)
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
