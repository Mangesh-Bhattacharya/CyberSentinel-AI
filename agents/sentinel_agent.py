"""
CyberSentinel AI - Sentinel Agent (Alert Triage & Detection)
=============================================================
Classifies alerts, maps to MITRE ATT&CK, and calculates risk scores.

Author: Mangesh Bhattacharya
Company: SentinelSync Inc.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate

logger = logging.getLogger(__name__)


# MITRE ATT&CK TTP Reference Map (v15)
MITRE_TTP_MAP = {
      "lateral_movement": {
                "tactic": "TA0008",
                "techniques": ["T1021", "T1550", "T1563"],
                "description": "Lateral Movement"
      },
      "credential_access": {
                "tactic": "TA0006",
                "techniques": ["T1003", "T1110", "T1555"],
                "description": "Credential Access"
      },
      "exfiltration": {
                "tactic": "TA0010",
                "techniques": ["T1041", "T1048", "T1052"],
                "description": "Exfiltration"
      },
      "command_and_control": {
                "tactic": "TA0011",
                "techniques": ["T1071", "T1095", "T1571"],
                "description": "Command and Control"
      },
      "persistence": {
                "tactic": "TA0003",
                "techniques": ["T1053", "T1078", "T1136"],
                "description": "Persistence"
      },
      "privilege_escalation": {
                "tactic": "TA0004",
                "techniques": ["T1068", "T1134", "T1548"],
                "description": "Privilege Escalation"
      },
      "defense_evasion": {
                "tactic": "TA0005",
                "techniques": ["T1027", "T1055", "T1562"],
                "description": "Defense Evasion"
      },
      "ransomware": {
                "tactic": "TA0040",
                "techniques": ["T1486", "T1490", "T1489"],
                "description": "Impact - Ransomware"
      },
      "phishing": {
                "tactic": "TA0001",
                "techniques": ["T1566", "T1192", "T1193"],
                "description": "Initial Access - Phishing"
      },
}

TRIAGE_PROMPT = """You are a senior SOC analyst AI specializing in alert triage and threat classification.

Analyze the following security alert and provide a structured assessment:

Alert Data:
{alert_data}

Provide your analysis in the following JSON format:
{{
    "risk_score": <float 0.0-10.0>,
        "severity": "<critical|high|medium|low|info>",
            "classification": "<threat_type>",
                "mitre_tactics": ["<tactic_id>"],
                    "mitre_techniques": ["<technique_id>"],
                        "iocs": ["<ip|domain|hash|url>"],
                            "summary": "<2-3 sentence analysis>",
                                "recommended_action": "<immediate action>",
                                    "false_positive_probability": <float 0.0-1.0>,
                                        "confidence": <float 0.0-1.0>
                                        }}

                                        Risk Scoring Guide:
                                        - 9.0-10.0: Critical (active data exfiltration, ransomware, APT confirmed)
                                        - 7.0-8.9: High (confirmed malware, credential theft, lateral movement)
                                        - 5.0-6.9: Medium (suspicious behavior, anomalous traffic, policy violation)
                                        - 3.0-4.9: Low (reconnaissance, scanning, minor policy breach)
                                        - 0.0-2.9: Info (normal variation, likely false positive)

                                        Be precise, evidence-based, and security-focused."""


class SentinelAgent:
      """
          Alert Triage & Detection Agent.

                  Analyzes raw security alerts from SIEM/EDR/network sensors,
                      classifies threats, maps to MITRE ATT&CK, and produces
                          actionable risk assessments.
                              """

    def __init__(self, config: Dict[str, Any], llm: Any):
              self.config = config
              self.llm = llm
              self.alert_threshold = config.get("agents", {}).get("sentinel", {}).get("alert_threshold", 7.0)
              self.prompt = ChatPromptTemplate.from_template(TRIAGE_PROMPT)
              self.parser = JsonOutputParser()

    def analyze(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
              """
                      Analyze a security alert and produce a risk assessment.

                                      Args:
                                                  alert_data: Raw alert data (SIEM log, EDR event, network alert)

                                                                      Returns:
                                                                                  Structured threat assessment with MITRE mapping
                                                                                          """
              try:
                            # Pre-process the alert
                            normalized = self._normalize_alert(alert_data)

                  # LLM-based triage
                            chain = self.prompt | self.llm | self.parser
            result = chain.invoke({"alert_data": json.dumps(normalized, indent=2)})

            # Enrich with MITRE mapping
            result = self._enrich_with_mitre(result, normalized)

            # Extract IOCs from raw log
            if "raw_log" in normalized:
                              iocs = self._extract_iocs(normalized["raw_log"])
                              result["iocs"] = list(set(result.get("iocs", []) + iocs))

            # Apply risk score adjustments
            result["risk_score"] = self._adjust_risk_score(result, normalized)

            logger.info(
                              f"[SENTINEL] Alert analyzed: severity={result.get('severity')}, "
                              f"risk={result.get('risk_score', 0):.1f}, "
                              f"tactics={result.get('mitre_tactics', [])}"
            )

            return result

except Exception as e:
            logger.error(f"[SENTINEL] Analysis failed: {e}")
            return self._fallback_assessment(alert_data)

    def _normalize_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
              """Normalize alert data from various SIEM formats."""
        normalized = {
                      "timestamp": alert_data.get("timestamp", datetime.utcnow().isoformat()),
                      "source_ip": alert_data.get("source_ip", alert_data.get("src_ip", "unknown")),
                      "destination_ip": alert_data.get("destination_ip", alert_data.get("dst_ip", "unknown")),
                      "event_type": alert_data.get("event_type", alert_data.get("type", "unknown")),
                      "severity": alert_data.get("severity", "unknown"),
                      "raw_log": alert_data.get("raw_log", alert_data.get("message", "")),
                      "source_host": alert_data.get("source_host", alert_data.get("hostname", "unknown")),
                      "user": alert_data.get("user", alert_data.get("username", "unknown")),
                      "process": alert_data.get("process", alert_data.get("process_name", "unknown")),
        }
        return normalized

    def _enrich_with_mitre(self, result: Dict[str, Any], alert: Dict[str, Any]) -> Dict[str, Any]:
              """Map alert to MITRE ATT&CK framework."""
        event_type = alert.get("event_type", "").lower()
        raw_log = alert.get("raw_log", "").lower()

        # Find matching TTP
        matched_tactics = []
        matched_techniques = []

        for keyword, ttp in MITRE_TTP_MAP.items():
                      if keyword in event_type or keyword in raw_log:
                                        matched_tactics.append(ttp["tactic"])
                                        matched_techniques.extend(ttp["techniques"])

                  # Merge LLM results with rule-based mapping
                  existing_tactics = result.get("mitre_tactics", [])
        existing_techniques = result.get("mitre_techniques", [])

        result["mitre_tactics"] = list(set(existing_tactics + matched_tactics))
        result["mitre_techniques"] = list(set(existing_techniques + matched_techniques))

        return result

    def _extract_iocs(self, text: str) -> List[str]:
              """Extract Indicators of Compromise from text using regex."""
        iocs = []

        # IPv4 addresses
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        iocs.extend(re.findall(ip_pattern, text))

        # Domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, text)
        iocs.extend([d for d in domains if '.' in d and not d.endswith('.py')])

        # MD5/SHA1/SHA256 hashes
        hash_pattern = r'\b[0-9a-fA-F]{32,64}\b'
        iocs.extend(re.findall(hash_pattern, text))

        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        iocs.extend(re.findall(url_pattern, text))

        return list(set(iocs))[:20]  # Cap at 20 IOCs

    def _adjust_risk_score(self, result: Dict[str, Any], alert: Dict[str, Any]) -> float:
              """Apply contextual adjustments to the base risk score."""
        base_score = result.get("risk_score", 5.0)

        # Boost score for critical MITRE tactics
        critical_tactics = ["TA0010", "TA0040"]  # Exfiltration, Impact
        for tactic in result.get("mitre_tactics", []):
                      if tactic in critical_tactics:
                                        base_score = min(10.0, base_score + 1.5)

                  # Boost for known malicious keywords
                  raw_log = alert.get("raw_log", "").lower()
        malicious_keywords = ["ransomware", "mimikatz", "cobalt strike", "powershell -enc", "certutil"]
        for keyword in malicious_keywords:
                      if keyword in raw_log:
                                        base_score = min(10.0, base_score + 1.0)

                  # Reduce score if high false positive probability
                  fp_prob = result.get("false_positive_probability", 0.0)
        if fp_prob > 0.7:
                      base_score = max(0.0, base_score - 2.0)

        return round(min(10.0, max(0.0, base_score)), 2)

    def _fallback_assessment(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
              """Return a conservative assessment if LLM fails."""
        return {
                      "risk_score": 5.0,
                      "severity": "medium",
                      "classification": "unknown",
                      "mitre_tactics": [],
                      "mitre_techniques": [],
                      "iocs": [],
                      "summary": "Alert analysis failed. Manual review required.",
                      "recommended_action": "Escalate to Tier-2 analyst for manual investigation.",
                      "false_positive_probability": 0.5,
                      "confidence": 0.0,
                      "error": "LLM analysis unavailable",
        }
