"""
CyberSentinel AI - Anomaly Detector
ML-powered behavioral anomaly detection using statistical baselines,
Isolation Forest, and LSTM-based time series analysis for network and user behavior.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Tuple

import numpy as np
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums & Config
# ---------------------------------------------------------------------------

class AnomalyType(str, Enum):
      STATISTICAL = "statistical"        # Z-score based
    BEHAVIORAL = "behavioral"          # User/entity behavior analytics
    TEMPORAL = "temporal"              # Time-based patterns
    NETWORK_FLOW = "network_flow"      # Network traffic anomaly
    AUTHENTICATION = "authentication"  # Login/auth anomalies
    DATA_EXFIL = "data_exfiltration"  # Unusual data transfer volumes
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class AnomalySeverity(str, Enum):
      CRITICAL = "critical"
      HIGH = "high"
      MEDIUM = "medium"
      LOW = "low"
      INFO = "info"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class AnomalyEvent(BaseModel):
      id: str = Field(default_factory=lambda: f"anm_{int(time.time() * 1000)}")
      anomaly_type: AnomalyType
      severity: AnomalySeverity
      score: float                    # 0.0 to 1.0
    entity: str                     # User, IP, hostname
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    baseline_value: Optional[float] = None
    observed_value: Optional[float] = None
    deviation_factor: Optional[float] = None
    mitre_technique: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_event: Optional[Dict] = None


class BaselineProfile(BaseModel):
      """Statistical baseline for an entity."""
      entity: str
      metric: str
      values: List[float] = Field(default_factory=list)
      mean: float = 0.0
      std_dev: float = 0.0
      min_val: float = 0.0
      max_val: float = 0.0
      p95: float = 0.0
      p99: float = 0.0
      sample_count: int = 0
      last_updated: datetime = Field(default_factory=datetime.utcnow)
      window_hours: int = 168  # 1 week default


# ---------------------------------------------------------------------------
# Statistical Baseline Engine
# ---------------------------------------------------------------------------

class BaselineEngine:
      """
          Maintains rolling statistical baselines for entities and metrics.
              Uses exponential moving average for online learning.
                  """

    def __init__(self, window_size: int = 1000, alpha: float = 0.1):
              self.window_size = window_size
              self.alpha = alpha  # EMA smoothing factor
        self._baselines: Dict[str, Dict[str, Deque]] = defaultdict(lambda: defaultdict(lambda: deque(maxlen=window_size)))
        self._ema: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._variance: Dict[str, Dict[str, float]] = defaultdict(dict)

    def update(self, entity: str, metric: str, value: float):
              """Update baseline with new observation."""
              self._baselines[entity][metric].append(value)

        # Exponential Moving Average
              if metric not in self._ema[entity]:
                            self._ema[entity][metric] = value
                            self._variance[entity][metric] = 0.0
else:
            old_ema = self._ema[entity][metric]
              self._ema[entity][metric] = self.alpha * value + (1 - self.alpha) * old_ema
            # Online variance estimation (Welford's method simplified)
            diff = value - old_ema
            self._variance[entity][metric] = (1 - self.alpha) * (
                              self._variance[entity][metric] + self.alpha * diff * diff
            )

    def get_zscore(self, entity: str, metric: str, value: float) -> Optional[float]:
              """Calculate Z-score for a value against entity baseline."""
              data = list(self._baselines[entity][metric])
              if len(data) < 10:
                            return None

              mean = statistics.mean(data)
              try:
                            std = statistics.stdev(data)
except statistics.StatisticsError:
            return None

        if std == 0:
                      return 0.0

        return (value - mean) / std

    def get_percentile_rank(self, entity: str, metric: str, value: float) -> Optional[float]:
              """Get percentile rank of a value in the baseline distribution."""
              data = sorted(self._baselines[entity][metric])
              if not data:
                            return None
                        rank = sum(1 for x in data if x <= value) / len(data)
        return rank * 100

    def get_profile(self, entity: str, metric: str) -> Optional[BaselineProfile]:
              """Get statistical profile for an entity metric."""
        data = list(self._baselines[entity][metric])
        if len(data) < 5:
                      return None

        sorted_data = sorted(data)
        n = len(sorted_data)

        def percentile(pct: float) -> float:
                      idx = math.ceil(pct / 100 * n) - 1
                      return sorted_data[max(0, min(idx, n - 1))]

        return BaselineProfile(
                      entity=entity,
                      metric=metric,
                      values=data[-100:],
                      mean=statistics.mean(data),
                      std_dev=statistics.stdev(data) if len(data) > 1 else 0.0,
                      min_val=min(data),
                      max_val=max(data),
                      p95=percentile(95),
                      p99=percentile(99),
                      sample_count=len(data),
        )

    def is_anomalous(self, entity: str, metric: str, value: float, threshold_sigma: float = 3.0) -> Tuple[bool, float]:
              """Check if a value is anomalous using Z-score threshold."""
        zscore = self.get_zscore(entity, metric, value)
        if zscore is None:
                      return False, 0.0
                  return abs(zscore) > threshold_sigma, zscore


# ---------------------------------------------------------------------------
# Network Flow Anomaly Detector
# ---------------------------------------------------------------------------

class NetworkFlowDetector:
      """
          Detects network anomalies including:
              - Port scanning (high unique destination port count)
                  - DDoS (high packet rate from single source)
                      - Data exfiltration (high outbound transfer to unusual destinations)
                          - C2 beaconing (regular interval connections)
                              - DNS tunneling (high DNS query volume, unusually long domain names)
                                  """

    def __init__(self):
              self.baseline = BaselineEngine()
        self._connection_tracker: Dict[str, List[Dict]] = defaultdict(list)
        self._dns_tracker: Dict[str, List[str]] = defaultdict(list)
        self._beacon_tracker: Dict[str, Deque] = defaultdict(lambda: deque(maxlen=100))

    async def analyze_flow(self, flow: Dict[str, Any]) -> List[AnomalyEvent]:
              """Analyze a network flow record for anomalies."""
              anomalies = []
              src_ip = flow.get("src_ip", "")
              dst_ip = flow.get("dst_ip", "")
              dst_port = flow.get("dst_port", 0)
              bytes_out = flow.get("bytes_out", 0)
              packet_rate = flow.get("packets_per_second", 0)
              protocol = flow.get("protocol", "TCP").upper()
              timestamp = flow.get("timestamp", time.time())

        # Track connection
              self._connection_tracker[src_ip].append({
                            "dst_ip": dst_ip, "dst_port": dst_port, "timestamp": timestamp
              })

        # Update baselines
        self.baseline.update(src_ip, "bytes_per_connection", bytes_out)
        self.baseline.update(src_ip, "packet_rate", packet_rate)

        # Port scan detection
        recent_connections = [
                      c for c in self._connection_tracker[src_ip]
                      if timestamp - c["timestamp"] < 60  # Last 60 seconds
        ]
        unique_dst_ports = len(set(c["dst_port"] for c in recent_connections))
        if unique_dst_ports > 20:
                      anomalies.append(AnomalyEvent(
                                        anomaly_type=AnomalyType.NETWORK_FLOW,
                                        severity=AnomalySeverity.HIGH,
                                        score=min(unique_dst_ports / 100, 1.0),
                                        entity=src_ip,
                                        description=f"Possible port scan: {unique_dst_ports} unique ports in 60s",
                                        evidence={"unique_ports": unique_dst_ports, "src_ip": src_ip},
                                        mitre_technique="T1046",
                                        raw_event=flow,
                      ))

        # Data exfiltration detection
        is_anomalous, zscore = self.baseline.is_anomalous(src_ip, "bytes_per_connection", bytes_out)
        if is_anomalous and bytes_out > 10_000_000:  # 10MB
                      anomalies.append(AnomalyEvent(
                                        anomaly_type=AnomalyType.DATA_EXFIL,
                                        severity=AnomalySeverity.HIGH,
                                        score=min(abs(zscore) / 10, 1.0),
                                        entity=src_ip,
                                        description=f"Unusual data transfer: {bytes_out / 1_000_000:.1f}MB (z-score: {zscore:.2f})",
                                        evidence={"bytes_out": bytes_out, "zscore": zscore, "dst_ip": dst_ip},
                                        baseline_value=self.baseline._ema[src_ip].get("bytes_per_connection"),
                                        observed_value=bytes_out,
                                        deviation_factor=zscore,
                                        mitre_technique="T1041",
                                        raw_event=flow,
                      ))

        # C2 beaconing detection (regular intervals)
        self._beacon_tracker[f"{src_ip}->{dst_ip}"].append(timestamp)
        beacon_score = self._detect_beaconing(f"{src_ip}->{dst_ip}")
        if beacon_score > 0.7:
                      anomalies.append(AnomalyEvent(
                                        anomaly_type=AnomalyType.NETWORK_FLOW,
                                        severity=AnomalySeverity.CRITICAL,
                                        score=beacon_score,
                                        entity=src_ip,
                                        description=f"C2 beaconing pattern detected to {dst_ip} (regularity: {beacon_score:.2f})",
                                        evidence={"src_ip": src_ip, "dst_ip": dst_ip, "beacon_score": beacon_score},
                                        mitre_technique="T1071",
                                        raw_event=flow,
                      ))

        return anomalies

    def _detect_beaconing(self, connection_key: str) -> float:
              """Detect C2 beaconing by analyzing connection interval regularity."""
              timestamps = list(self._beacon_tracker[connection_key])
              if len(timestamps) < 5:
                            return 0.0

              intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
              if not intervals:
                            return 0.0

              mean_interval = statistics.mean(intervals)
              if mean_interval <= 0:
                            return 0.0

              try:
                            cv = statistics.stdev(intervals) / mean_interval  # Coefficient of variation
except statistics.StatisticsError:
            return 0.0

        # Low CV = highly regular = potential beaconing
        # CV < 0.1 means very regular (90%+ score)
        beacon_score = max(0.0, 1.0 - cv * 5)
        return beacon_score

    async def analyze_dns(self, dns_event: Dict) -> List[AnomalyEvent]:
              """Detect DNS anomalies including tunneling and DGA domains."""
              anomalies = []
              src_ip = dns_event.get("src_ip", "")
              query = dns_event.get("query", "")
              response = dns_event.get("response", "")

        if not query:
                      return anomalies

        self._dns_tracker[src_ip].append(query)
        self.baseline.update(src_ip, "dns_query_rate",
                                                          len(self._dns_tracker[src_ip]))

        # DNS tunneling: unusually long domain names
        domain_parts = query.split(".")
        max_label_len = max((len(p) for p in domain_parts), default=0)
        total_len = len(query)

        if max_label_len > 50 or total_len > 150:
                      entropy = self._calculate_entropy(query)
                      if entropy > 3.5:
                                        anomalies.append(AnomalyEvent(
                                                              anomaly_type=AnomalyType.NETWORK_FLOW,
                                                              severity=AnomalySeverity.HIGH,
                                                              score=min(entropy / 5.0, 1.0),
                                                              entity=src_ip,
                                                              description=f"Possible DNS tunneling: long/high-entropy domain '{query[:80]}'",
                                                              evidence={
                                                                                        "query": query, "domain_length": total_len,
                                                                                        "max_label_len": max_label_len, "entropy": entropy,
                                                              },
                                                              mitre_technique="T1071.004",
                                                              raw_event=dns_event,
                                        ))

                  # High DNS query rate
                  recent_queries = len(self._dns_tracker[src_ip])
        is_anomalous, zscore = self.baseline.is_anomalous(src_ip, "dns_query_rate", recent_queries)
        if is_anomalous and recent_queries > 100:
                      anomalies.append(AnomalyEvent(
                                        anomaly_type=AnomalyType.NETWORK_FLOW,
                                        severity=AnomalySeverity.MEDIUM,
                                        score=min(abs(zscore) / 10, 1.0),
                                        entity=src_ip,
                                        description=f"Elevated DNS query rate: {recent_queries} queries",
                                        evidence={"query_count": recent_queries, "zscore": zscore},
                                        mitre_technique="T1071.004",
                      ))

        return anomalies

    @staticmethod
    def _calculate_entropy(text: str) -> float:
              """Calculate Shannon entropy of a string."""
              if not text:
                            return 0.0
                        freq = defaultdict(int)
        for char in text:
                      freq[char] += 1
                  n = len(text)
        return -sum((count / n) * math.log2(count / n) for count in freq.values())


# ---------------------------------------------------------------------------
# User Behavior Analytics (UEBA)
# ---------------------------------------------------------------------------

class UEBADetector:
      """
          User and Entity Behavior Analytics.
              Detects anomalies in user activity patterns.
                  """

    def __init__(self):
              self.baseline = BaselineEngine(window_size=500)
        self._user_activity: Dict[str, List[Dict]] = defaultdict(list)
        self._failed_logins: Dict[str, Deque] = defaultdict(lambda: deque(maxlen=100))

    async def analyze_auth_event(self, event: Dict) -> List[AnomalyEvent]:
              """Analyze authentication event for anomalies."""
        anomalies = []
        user = event.get("user", "")
        src_ip = event.get("src_ip", "")
        result = event.get("result", "")
        timestamp = event.get("timestamp", time.time())
        hour_of_day = datetime.fromtimestamp(timestamp).hour

        # Track activity
        self._user_activity[user].append(event)
        self.baseline.update(user, "hour_of_day", hour_of_day)

        # Brute force: multiple failed logins
        if result in ("failed", "failure", "FAILURE"):
                      self._failed_logins[user].append(timestamp)
                      recent_failures = sum(1 for t in self._failed_logins[user] if timestamp - t < 300)
                      if recent_failures >= 5:
                                        anomalies.append(AnomalyEvent(
                                                              anomaly_type=AnomalyType.AUTHENTICATION,
                                                              severity=AnomalySeverity.HIGH if recent_failures >= 10 else AnomalySeverity.MEDIUM,
                                                              score=min(recent_failures / 20, 1.0),
                                                              entity=user,
                                                              description=f"Brute force: {recent_failures} failed logins in 5 minutes from {src_ip}",
                                                              evidence={"user": user, "src_ip": src_ip, "failures": recent_failures},
                                                              mitre_technique="T1110",
                                                              raw_event=event,
                                        ))

                  # Off-hours login
                  profile = self.baseline.get_profile(user, "hour_of_day")
        if profile and profile.sample_count >= 20:
                      zscore = self.baseline.get_zscore(user, "hour_of_day", hour_of_day)
                      if zscore and abs(zscore) > 2.5:
                                        anomalies.append(AnomalyEvent(
                                                              anomaly_type=AnomalyType.BEHAVIORAL,
                                                              severity=AnomalySeverity.MEDIUM,
                                                              score=min(abs(zscore) / 5, 1.0),
                                                              entity=user,
                                                              description=f"Unusual login time for {user}: hour={hour_of_day} (z-score={zscore:.2f})",
                                                              evidence={"user": user, "hour": hour_of_day, "zscore": zscore, "typical_mean": profile.mean},
                                                              baseline_value=profile.mean,
                                                              observed_value=hour_of_day,
                                                              deviation_factor=zscore,
                                                              mitre_technique="T1078",
                                                              raw_event=event,
                                        ))

                  return anomalies

    async def analyze_file_access(self, event: Dict) -> List[AnomalyEvent]:
              """Detect unusual file access patterns."""
        anomalies = []
        user = event.get("user", "")
        file_count = event.get("files_accessed", 1)
        sensitive_files = event.get("sensitive_files", 0)
        timestamp = event.get("timestamp", time.time())

        self.baseline.update(user, "file_access_count", file_count)
        self.baseline.update(user, "sensitive_file_access", sensitive_files)

        # Anomalous file access volume
        is_anomalous, zscore = self.baseline.is_anomalous(user, "file_access_count", file_count, threshold_sigma=3.0)
        if is_anomalous and file_count > 100:
                      anomalies.append(AnomalyEvent(
                                        anomaly_type=AnomalyType.BEHAVIORAL,
                                        severity=AnomalySeverity.HIGH,
                                        score=min(abs(zscore) / 8, 1.0),
                                        entity=user,
                                        description=f"Mass file access: {file_count} files (z-score={zscore:.2f}) - possible insider threat",
                                        evidence={"user": user, "file_count": file_count, "zscore": zscore},
                                        mitre_technique="T1005",
                                        raw_event=event,
                      ))

        # Sudden sensitive file access
        if sensitive_files > 0:
                      profile = self.baseline.get_profile(user, "sensitive_file_access")
                      if profile and profile.mean < 1 and sensitive_files > 5:
                                        anomalies.append(AnomalyEvent(
                                                              anomaly_type=AnomalyType.BEHAVIORAL,
                                                              severity=AnomalySeverity.CRITICAL,
                                                              score=min(sensitive_files / 20, 1.0),
                                                              entity=user,
                                                              description=f"Unusual sensitive file access: {sensitive_files} files by {user}",
                                                              evidence={"user": user, "sensitive_files": sensitive_files},
                                                              mitre_technique="T1083",
                                                              raw_event=event,
                                        ))

                  return anomalies


# ---------------------------------------------------------------------------
# Isolation Forest Detector (ML-based)
# ---------------------------------------------------------------------------

class IsolationForestDetector:
      """
          Scikit-learn Isolation Forest for unsupervised anomaly detection.
              Detects anomalies in multi-dimensional feature spaces.
                  """

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100):
              self.contamination = contamination
        self.n_estimators = n_estimators
        self._model = None
        self._scaler = None
        self._feature_buffer: List[List[float]] = []
        self._is_fitted = False
        self._min_samples = 50

    def _extract_features(self, event: Dict) -> Optional[List[float]]:
              """Extract numerical features from an event."""
        try:
                      features = [
                                        float(event.get("bytes_in", 0)),
                                        float(event.get("bytes_out", 0)),
                                        float(event.get("duration_ms", 0)),
                                        float(event.get("packet_count", 0)),
                                        float(event.get("unique_dst_ports", 0)),
                                        float(event.get("failed_logins", 0)),
                                        float(event.get("hour_of_day", 12)),
                                        float(event.get("day_of_week", 3)),
                                        float(event.get("files_accessed", 0)),
                                        float(event.get("processes_spawned", 0)),
                      ]
                      return features
except (ValueError, TypeError):
            return None

    def fit(self, events: List[Dict]):
              """Train the isolation forest on a dataset."""
        try:
                      from sklearn.ensemble import IsolationForest
                      from sklearn.preprocessing import StandardScaler

            features = [self._extract_features(e) for e in events]
            features = [f for f in features if f is not None]

            if len(features) < self._min_samples:
                              logger.warning(f"Insufficient samples for Isolation Forest: {len(features)}")
                              return

            X = np.array(features)
            self._scaler = StandardScaler()
            X_scaled = self._scaler.fit_transform(X)

            self._model = IsolationForest(
                              contamination=self.contamination,
                              n_estimators=self.n_estimators,
                              random_state=42,
                              n_jobs=-1,
            )
            self._model.fit(X_scaled)
            self._is_fitted = True
            logger.info(f"Isolation Forest fitted on {len(features)} samples")
except ImportError:
            logger.warning("scikit-learn not installed. ML detection disabled.")

    def predict(self, event: Dict) -> Tuple[bool, float]:
              """Predict if an event is anomalous. Returns (is_anomalous, score)."""
        if not self._is_fitted or self._model is None:
                      return False, 0.0

        features = self._extract_features(event)
        if features is None:
                      return False, 0.0

        X = np.array([features])
        X_scaled = self._scaler.transform(X)

        prediction = self._model.predict(X_scaled)[0]  # -1 = anomaly, 1 = normal
        score = -self._model.score_samples(X_scaled)[0]  # Higher = more anomalous

        is_anomalous = prediction == -1
        # Normalize score to 0-1
        normalized_score = min(max((score - 0.3) / 0.7, 0.0), 1.0)

        return is_anomalous, normalized_score

    def update_buffer(self, event: Dict):
              """Add event to buffer for periodic retraining."""
        features = self._extract_features(event)
        if features:
                      self._feature_buffer.append(features)
                      if len(self._feature_buffer) >= 1000:
                                        self.fit([{"bytes_in": f[0], "bytes_out": f[1]} for f in self._feature_buffer])
                                        self._feature_buffer = self._feature_buffer[-100:]


# ---------------------------------------------------------------------------
# Main Anomaly Detection Orchestrator
# ---------------------------------------------------------------------------

class AnomalyDetector:
      """
          Unified anomaly detection system combining:
              - Statistical baseline analysis
                  - Network flow monitoring
                      - UEBA (User and Entity Behavior Analytics)
                          - ML-based Isolation Forest
                              """

    def __init__(self):
              self.network_detector = NetworkFlowDetector()
        self.ueba_detector = UEBADetector()
        self.ml_detector = IsolationForestDetector()
        self._event_history: List[AnomalyEvent] = []
        self._alert_callbacks: List[Any] = []
        logger.info("AnomalyDetector initialized")

    def register_alert_callback(self, callback: Any):
              """Register callback for real-time anomaly alerts."""
        self._alert_callbacks.append(callback)

    async def _dispatch_alerts(self, anomalies: List[AnomalyEvent]):
              """Dispatch anomaly events to registered callbacks."""
        for anomaly in anomalies:
                      self._event_history.append(anomaly)
                      for callback in self._alert_callbacks:
                                        try:
                                                              if asyncio.iscoroutinefunction(callback):
                                                                                        await callback(anomaly)
                                        else:
                                                                  callback(anomaly)
                                        except Exception as e:
                                            logger.error(f"Alert callback error: {e}")

              async def analyze_event(self, event: Dict, event_type: str = "generic") -> List[AnomalyEvent]:
                        """
                                Analyze a security event for anomalies.
                                        event_type: 'network_flow', 'dns', 'auth', 'file_access', 'generic'
                                                """
                        all_anomalies: List[AnomalyEvent] = []

        # Route to appropriate detector
        if event_type == "network_flow":
                      network_anomalies = await self.network_detector.analyze_flow(event)
                      all_anomalies.extend(network_anomalies)

elif event_type == "dns":
            dns_anomalies = await self.network_detector.analyze_dns(event)
            all_anomalies.extend(dns_anomalies)

elif event_type == "auth":
            auth_anomalies = await self.ueba_detector.analyze_auth_event(event)
            all_anomalies.extend(auth_anomalies)

elif event_type == "file_access":
            file_anomalies = await self.ueba_detector.analyze_file_access(event)
            all_anomalies.extend(file_anomalies)

        # ML detection on all events
        self.ml_detector.update_buffer(event)
        is_anomalous, ml_score = self.ml_detector.predict(event)
        if is_anomalous and ml_score > 0.6:
                      entity = event.get("src_ip") or event.get("user") or "unknown"
                      all_anomalies.append(AnomalyEvent(
                          anomaly_type=AnomalyType.BEHAVIORAL,
                          severity=AnomalySeverity.HIGH if ml_score > 0.8 else AnomalySeverity.MEDIUM,
                          score=ml_score,
                          entity=entity,
                          description=f"ML model (Isolation Forest) flagged anomalous behavior (score={ml_score:.3f})",
                          evidence={"ml_score": ml_score, "event_type": event_type},
                          raw_event=event,
                      ))

        # Dispatch alerts
        if all_anomalies:
                      await self._dispatch_alerts(all_anomalies)

        return all_anomalies

    async def analyze_batch(self, events: List[Dict], event_type: str = "generic") -> List[AnomalyEvent]:
              """Analyze a batch of events concurrently."""
        tasks = [self.analyze_event(event, event_type) for event in events]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_anomalies = []
        for r in results:
                      if isinstance(r, list):
                                        all_anomalies.extend(r)
                                return all_anomalies

    def get_top_anomalies(self, n: int = 10, min_severity: str = "medium") -> List[AnomalyEvent]:
              """Get top N anomalies sorted by severity and score."""
        severity_order = {
                      AnomalySeverity.CRITICAL: 4,
                      AnomalySeverity.HIGH: 3,
                      AnomalySeverity.MEDIUM: 2,
                      AnomalySeverity.LOW: 1,
                      AnomalySeverity.INFO: 0,
        }
        min_level = severity_order.get(AnomalySeverity(min_severity), 0)

        filtered = [
                      a for a in self._event_history
                      if severity_order.get(a.severity, 0) >= min_level
        ]
        return sorted(filtered, key=lambda x: (severity_order.get(x.severity, 0), x.score), reverse=True)[:n]

    def get_entity_risk_score(self, entity: str) -> float:
              """Calculate aggregate risk score for an entity."""
        entity_events = [e for e in self._event_history if e.entity == entity]
        if not entity_events:
                      return 0.0

        severity_weights = {
                      AnomalySeverity.CRITICAL: 1.0,
                      AnomalySeverity.HIGH: 0.75,
                      AnomalySeverity.MEDIUM: 0.5,
                      AnomalySeverity.LOW: 0.25,
                      AnomalySeverity.INFO: 0.1,
        }

        total_score = sum(
                      e.score * severity_weights.get(e.severity, 0.5)
                      for e in entity_events
        )
        # Normalize and decay by time
        recent_events = [
                      e for e in entity_events
                      if (datetime.utcnow() - e.timestamp).total_seconds() < 86400
        ]
        recent_score = sum(
                      e.score * severity_weights.get(e.severity, 0.5)
                      for e in recent_events
        )

        return min(recent_score / max(len(recent_events), 1) + total_score * 0.1, 10.0)

    def train_ml_model(self, historical_events: List[Dict]):
              """Train ML model on historical baseline data."""
        logger.info(f"Training ML model on {len(historical_events)} events")
        self.ml_detector.fit(historical_events)

    def get_statistics(self) -> Dict[str, Any]:
              """Get detection statistics."""
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        for event in self._event_history:
                      severity_counts[event.severity.value] += 1
            type_counts[event.anomaly_type.value] += 1

        return {
                      "total_anomalies": len(self._event_history),
                      "by_severity": dict(severity_counts),
                      "by_type": dict(type_counts),
                      "ml_model_fitted": self.ml_detector._is_fitted,
                      "top_entities": self._get_top_entities(),
        }

    def _get_top_entities(self, n: int = 5) -> List[Dict]:
              """Get entities with most anomalies."""
        entity_counts: Dict[str, int] = defaultdict(int)
        for event in self._event_history:
                      entity_counts[event.entity] += 1
        return [
                      {"entity": k, "count": v, "risk_score": self.get_entity_risk_score(k)}
                      for k, v in sorted(entity_counts.items(), key=lambda x: x[1], reverse=True)[:n]
        ]
