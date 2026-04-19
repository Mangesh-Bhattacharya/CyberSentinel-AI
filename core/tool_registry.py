"""
CyberSentinel AI - Tool Registry
Central registry for all agent tools: network scanners, SIEM integrations,
firewall control, EDR APIs, and threat intelligence feeds.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import aiohttp
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ToolResult(BaseModel):
      tool_name: str
      success: bool
      data: Any = None
      error: Optional[str] = None
      execution_time_ms: float = 0.0
      timestamp: datetime = Field(default_factory=datetime.utcnow)


async def tool_dns_lookup(hostname: str) -> ToolResult:
      """Resolve hostname to IP addresses."""
      start = time.time()
      try:
                loop = asyncio.get_event_loop()
                addrs = await loop.getaddrinfo(hostname, None)
                ips = list(set(a[4][0] for a in addrs))
                return ToolResult(
                    tool_name="dns_lookup", success=True,
                    data={"hostname": hostname, "resolved_ips": ips},
                    execution_time_ms=(time.time() - start) * 1000,
                )
except Exception as e:
        return ToolResult(tool_name="dns_lookup", success=False, error=str(e))


async def tool_port_scan(target: str, ports: List[int] = None, timeout: float = 1.0) -> ToolResult:
      """TCP connect scan for specified ports."""
      start = time.time()
      if ports is None:
                ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 27017]
            open_ports: List[int] = []

    async def check_port(port: int):
              try:
                            _, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
                            writer.close()
                            await writer.wait_closed()
                            open_ports.append(port)
except Exception:
            pass

    await asyncio.gather(*[check_port(p) for p in ports])
    high_risk = {23, 445, 3389, 5900}
    risk = "HIGH" if any(p in high_risk for p in open_ports) else "LOW"

    return ToolResult(
              tool_name="port_scan", success=True,
              data={"target": target, "open_ports": sorted(open_ports), "risk": risk},
              execution_time_ms=(time.time() - start) * 1000,
    )


async def tool_virustotal_lookup(resource: str, api_key: str, resource_type: str = "ip") -> ToolResult:
      """Query VirusTotal for reputation."""
    start = time.time()
    endpoints = {
              "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{resource}",
              "domain": f"https://www.virustotal.com/api/v3/domains/{resource}",
              "hash": f"https://www.virustotal.com/api/v3/files/{resource}",
    }
    url = endpoints.get(resource_type, endpoints["ip"])
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
              async with aiohttp.ClientSession() as session:
                            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                              if resp.status == 200:
                                                                    data = await resp.json()
                                                                    attrs = data.get("data", {}).get("attributes", {})
                                                                    stats = attrs.get("last_analysis_stats", {})
                                                                    return ToolResult(
                                                                        tool_name="virustotal_lookup", success=True,
                                                                        data={
                                                                            "resource": resource, "type": resource_type,
                                                                            "malicious": stats.get("malicious", 0),
                                                                            "suspicious": stats.get("suspicious", 0),
                                                                            "harmless": stats.get("harmless", 0),
                                                                        },
                                                                        execution_time_ms=(time.time() - start) * 1000,
                                                                    )
                                                                return ToolResult(tool_name="virustotal_lookup", success=False, error=f"HTTP {resp.status}")
    except Exception as e:
        return ToolResult(tool_name="virustotal_lookup", success=False, error=str(e))


async def tool_cve_lookup(cve_id: str) -> ToolResult:
      """Lookup CVE details from NVD API v2."""
    start = time.time()
    try:
              url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
              async with aiohttp.ClientSession() as session:
                            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                                              if resp.status == 200:
                                                                    data = await resp.json()
                                                                    vulns = data.get("vulnerabilities", [])
                                                                    if not vulns:
                                                                                              return ToolResult(tool_name="cve_lookup", success=False, error=f"{cve_id} not found")
                                                                                          cve = vulns[0].get("cve", {})
                                                                    metrics = cve.get("metrics", {})
                                                                    cvss_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}]
                                                                    cvss = cvss_list[0].get("cvssData", {})
                                                                    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
                                                                    return ToolResult(
                                                                        tool_name="cve_lookup", success=True,
                                                                        data={
                                                                            "cve_id": cve_id, "description": desc,
                                                                            "cvss_score": cvss.get("baseScore"),
                                                                            "severity": cvss.get("baseSeverity"),
                                                                            "vector": cvss.get("vectorString"),
                                                                            "published": cve.get("published"),
                                                                        },
                                                                        execution_time_ms=(time.time() - start) * 1000,
                                                                    )
    except Exception as e:
        return ToolResult(tool_name="cve_lookup", success=False, error=str(e))


async def tool_check_cisa_kev(cve_id: str) -> ToolResult:
      """Check if CVE is in CISA KEV catalog."""
    start = time.time()
    try:
              url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
              async with aiohttp.ClientSession() as session:
                            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                                              if resp.status == 200:
                                                                    data = await resp.json(content_type=None)
                                                                    match = next((v for v in data.get("vulnerabilities", []) if v.get("cveID") == cve_id), None)
                                                                    return ToolResult(
                                                                        tool_name="check_cisa_kev", success=True,
                                                                        data={"in_kev": bool(match), "cve_id": cve_id, **(match or {})},
                                                                        execution_time_ms=(time.time() - start) * 1000,
                                                                    )
    except Exception as e:
        return ToolResult(tool_name="check_cisa_kev", success=False, error=str(e))


async def tool_shodan_lookup(ip: str, api_key: str) -> ToolResult:
      """Query Shodan for host info."""
    start = time.time()
    try:
              async with aiohttp.ClientSession() as session:
                            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
                            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                              if resp.status == 200:
                                                                    data = await resp.json()
                                                                    return ToolResult(
                                                                        tool_name="shodan_lookup", success=True,
                                                                        data={
                                                                            "ip": ip, "country": data.get("country_name"),
                                                                            "org": data.get("org"), "open_ports": data.get("ports", []),
                                                                            "vulns": list(data.get("vulns", {}).keys()),
                                                                        },
                                                                        execution_time_ms=(time.time() - start) * 1000,
                                                                    )
    except Exception as e:
        return ToolResult(tool_name="shodan_lookup", success=False, error=str(e))


async def tool_search_logs(
      query: str, time_range_hours: int = 24, index: str = "*",
      siem_url: str = "http://localhost:9200", max_results: int = 100,
) -> ToolResult:
      """Search Elasticsearch SIEM for security events."""
    start = time.time()
    try:
              es_query = {
                            "query": {"bool": {"must": [
                                              {"query_string": {"query": query, "default_field": "*"}},
                                              {"range": {"@timestamp": {"gte": f"now-{time_range_hours}h", "lte": "now"}}},
                            ]}},
                            "sort": [{"@timestamp": {"order": "desc"}}], "size": max_results,
              }
              async with aiohttp.ClientSession() as session:
                            async with session.post(
                                              f"{siem_url}/{index}/_search", json=es_query, timeout=aiohttp.ClientTimeout(total=30)
                            ) as resp:
                                              if resp.status == 200:
                                                                    data = await resp.json()
                                                                    hits = data.get("hits", {})
                                                                    return ToolResult(
                                                                        tool_name="search_logs", success=True,
                                                                        data={
                                                                            "total": hits.get("total", {}).get("value", 0),
                                                                            "results": [h.get("_source", {}) for h in hits.get("hits", [])],
                                                                        },
                                                                        execution_time_ms=(time.time() - start) * 1000,
                                                                    )
    except Exception as e:
        return ToolResult(tool_name="search_logs", success=False, error=str(e))


async def tool_analyze_log_line(log_line: str) -> ToolResult:
      """Extract IOCs and suspicious patterns from a log line."""
    start = time.time()
    patterns = {
              "ip_address": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
              "url": re.compile(r'https?://[^\s<>"{}]+'),
              "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
              "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
              "cve": re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE),
    }
    suspicious_keywords = [
              "powershell", "cmd.exe", "mimikatz", "cobalt strike", "pass the hash",
              "privilege escalation", "sql injection", "wget", "certutil",
    ]
    extracted = {name: list(set(p.findall(log_line)))[:5] for name, p in patterns.items() if p.findall(log_line)}
    matched_kw = [kw for kw in suspicious_keywords if kw.lower() in log_line.lower()]
    severity = "critical" if len(matched_kw) >= 3 else "high" if matched_kw else "medium" if extracted.get("md5") else "info"

    return ToolResult(
              tool_name="analyze_log_line", success=True,
              data={"extracted_iocs": extracted, "suspicious_keywords": matched_kw, "severity": severity},
              execution_time_ms=(time.time() - start) * 1000,
    )


async def tool_isolate_endpoint(
      endpoint_id: str, edr_api_url: str = "http://localhost:8888",
      api_key: str = "", reason: str = "Security incident",
) -> ToolResult:
      """Isolate an endpoint via EDR API."""
    start = time.time()
    try:
              headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
              async with aiohttp.ClientSession() as session:
                            async with session.post(
                                              f"{edr_api_url}/api/endpoints/{endpoint_id}/isolate",
                                              json={"reason": reason}, headers=headers, timeout=aiohttp.ClientTimeout(total=30)
                            ) as resp:
                                              data = await resp.json()
                                              return ToolResult(
                                                  tool_name="isolate_endpoint", success=resp.status in (200, 202),
                                                  data={"endpoint_id": endpoint_id, "status": data.get("status")},
                                                  execution_time_ms=(time.time() - start) * 1000,
                                              )
    except Exception as e:
        return ToolResult(tool_name="isolate_endpoint", success=False, error=str(e))


async def tool_block_ip(
      ip_address: str, direction: str = "both", firewall_api_url: str = "http://localhost:8889",
      api_key: str = "", reason: str = "Automated block", duration_minutes: int = 60,
) -> ToolResult:
      """Block an IP via firewall API."""
    start = time.time()
    try:
              ipaddress.ip_address(ip_address)
except ValueError:
        return ToolResult(tool_name="block_ip", success=False, error=f"Invalid IP: {ip_address}")
    try:
              headers = {"Authorization": f"Bearer {api_key}"}
              async with aiohttp.ClientSession() as session:
                            async with session.post(
                                              f"{firewall_api_url}/api/rules",
                                              json={"ip": ip_address, "direction": direction, "reason": reason, "duration_minutes": duration_minutes},
                                              headers=headers, timeout=aiohttp.ClientTimeout(total=15)
                            ) as resp:
                                              data = await resp.json()
                                              return ToolResult(
                                                  tool_name="block_ip", success=resp.status in (200, 201),
                                                  data={"ip_blocked": ip_address, "rule_id": data.get("rule_id")},
                                                  execution_time_ms=(time.time() - start) * 1000,
                                              )
    except Exception as e:
        return ToolResult(tool_name="block_ip", success=False, error=str(e))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS: Dict[str, Dict] = {
      "dns_lookup": {
                "handler": tool_dns_lookup,
                "definition": {
                              "name": "dns_lookup",
                              "description": "Resolve hostname to IP addresses and check characteristics",
                              "parameters": {"type": "object", "properties": {"hostname": {"type": "string"}}, "required": ["hostname"]},
                },
      },
      "port_scan": {
                "handler": tool_port_scan,
                "definition": {
                              "name": "port_scan",
                              "description": "TCP port scan to identify open services",
                              "parameters": {
                                                "type": "object",
                                                "properties": {
                                                                      "target": {"type": "string"},
                                                                      "ports": {"type": "array", "items": {"type": "integer"}},
                                                },
                                                "required": ["target"],
                              },
                },
      },
      "virustotal_lookup": {
                "handler": tool_virustotal_lookup,
                "definition": {
                              "name": "virustotal_lookup",
                              "description": "Check IP/domain/hash reputation on VirusTotal",
                              "parameters": {
                                                "type": "object",
                                                "properties": {
                                                                      "resource": {"type": "string"},
                                                                      "api_key": {"type": "string"},
                                                                      "resource_type": {"type": "string", "enum": ["ip", "domain", "hash"]},
                                                },
                                                "required": ["resource", "api_key"],
                              },
                },
      },
      "cve_lookup": {
                "handler": tool_cve_lookup,
                "definition": {
                              "name": "cve_lookup",
                              "description": "Look up CVE details including CVSS scores from NVD",
                              "parameters": {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]},
                },
      },
      "check_cisa_kev": {
                "handler": tool_check_cisa_kev,
                "definition": {
                              "name": "check_cisa_kev",
                              "description": "Check if CVE is in CISA Known Exploited Vulnerabilities catalog",
                              "parameters": {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]},
                },
      },
      "shodan_lookup": {
                "handler": tool_shodan_lookup,
                "definition": {
                              "name": "shodan_lookup",
                              "description": "Query Shodan for host info and exposed vulnerabilities",
                              "parameters": {
                                                "type": "object",
                                                "properties": {"ip": {"type": "string"}, "api_key": {"type": "string"}},
                                                "required": ["ip", "api_key"],
                              },
                },
      },
      "search_logs": {
                "handler": tool_search_logs,
                "definition": {
                              "name": "search_logs",
                              "description": "Search SIEM Elasticsearch for security events",
                              "parameters": {
                                                "type": "object",
                                                "properties": {
                                                                      "query": {"type": "string"},
                                                                      "time_range_hours": {"type": "integer"},
                                                                      "max_results": {"type": "integer"},
                                                },
                                                "required": ["query"],
                              },
                },
      },
      "analyze_log_line": {
                "handler": tool_analyze_log_line,
                "definition": {
                              "name": "analyze_log_line",
                              "description": "Extract IOCs and detect suspicious patterns in a log line",
                              "parameters": {"type": "object", "properties": {"log_line": {"type": "string"}}, "required": ["log_line"]},
                },
      },
      "isolate_endpoint": {
                "handler": tool_isolate_endpoint,
                "definition": {
                              "name": "isolate_endpoint",
                              "description": "Network-isolate an endpoint via EDR API for containment",
                              "parameters": {
                                                "type": "object",
                                                "properties": {"endpoint_id": {"type": "string"}, "reason": {"type": "string"}},
                                                "required": ["endpoint_id"],
                              },
                },
      },
      "block_ip": {
                "handler": tool_block_ip,
                "definition": {
                              "name": "block_ip",
                              "description": "Block an IP address via firewall API",
                              "parameters": {
                                                "type": "object",
                                                "properties": {
                                                                      "ip_address": {"type": "string"},
                                                                      "direction": {"type": "string", "enum": ["inbound", "outbound", "both"]},
                                                                      "reason": {"type": "string"},
                                                                      "duration_minutes": {"type": "integer"},
                                                },
                                                "required": ["ip_address"],
                              },
                },
      },
}


def get_all_tool_definitions() -> List[Dict]:
      """Return all tool definitions for LLM function calling."""
    return [v["definition"] for v in TOOL_DEFINITIONS.values()]


def get_tool_handler(tool_name: str) -> Optional[Callable]:
      """Get tool handler by name."""
    tool = TOOL_DEFINITIONS.get(tool_name)
    return tool["handler"] if tool else None


async def execute_tool(tool_name: str, **kwargs) -> ToolResult:
      """Execute a registered tool by name."""
    handler = get_tool_handler(tool_name)
    if not handler:
              return ToolResult(tool_name=tool_name, success=False, error=f"Tool not found: {tool_name}")
          return await handler(**kwargs)
