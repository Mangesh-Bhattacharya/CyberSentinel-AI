"""
CyberSentinel AI - FastAPI REST API
=====================================
Production-ready REST API for the CyberSentinel AI platform.
Provides endpoints for alert submission, incident management,
threat hunting, and vulnerability assessment.

Author: Mangesh Bhattacharya
Company: SentinelSync Inc.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

import yaml
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from agents.orchestrator_agent import OrchestratorAgent
from core.memory import IncidentMemory

logger = logging.getLogger(__name__)

# Global state
orchestrator: Optional[OrchestratorAgent] = None
memory: Optional[IncidentMemory] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
      """Initialize agents on startup, cleanup on shutdown."""
      global orchestrator, memory

    logger.info("Initializing CyberSentinel AI Platform...")

    # Load configuration
    config_path = os.getenv("CYBERSENTINEL_CONFIG", "config.yaml")
    with open(config_path) as f:
              config = yaml.safe_load(f)

    # Initialize core components
    memory = IncidentMemory()
    orchestrator = OrchestratorAgent(config)

    logger.info("CyberSentinel AI Platform ready.")
    yield

    logger.info("Shutting down CyberSentinel AI Platform...")


# ─────────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────────

app = FastAPI(
      title="CyberSentinel AI",
      description="""
          ## AI-Agentic Cybersecurity Platform API

                  Autonomous threat detection, incident response, and security orchestration
                      powered by multi-agent AI reasoning and MITRE ATT&CK framework alignment.

                              ### Key Features
                                  - **Alert Analysis**: LLM-powered triage with MITRE ATT&CK mapping
                                      - **Incident Management**: Full incident lifecycle management
                                          - **Threat Hunting**: Autonomous proactive threat hunting
                                              - **Vulnerability Assessment**: CVE triage with EPSS scoring
                                                  - **Real-time Streaming**: WebSocket-based alert streaming
                                                      """,
      version="1.0.0",
      lifespan=lifespan,
      docs_url="/docs",
      redoc_url="/redoc",
)

# Middleware
app.add_middleware(
      CORSMiddleware,
      allow_origins=["*"],
      allow_credentials=True,
      allow_methods=["*"],
      allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)


# ─────────────────────────────────────────────
# Request/Response Models
# ─────────────────────────────────────────────

class AlertRequest(BaseModel):
      source_ip: Optional[str] = Field(None, example="192.168.1.105")
      destination_ip: Optional[str] = Field(None, example="10.0.0.1")
      event_type: str = Field(..., example="lateral_movement")
      severity: Optional[str] = Field("medium", example="high")
      raw_log: Optional[str] = Field(None, example="Failed login: 847 attempts in 60s")
      source_host: Optional[str] = Field(None, example="workstation-42")
      user: Optional[str] = Field(None, example="john.doe")
      timestamp: Optional[str] = Field(None, example="2026-04-19T10:30:00Z")
      metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

    class Config:
              schema_extra = {
                            "example": {
                                              "source_ip": "192.168.1.105",
                                              "destination_ip": "10.0.0.1",
                                              "event_type": "lateral_movement",
                                              "severity": "high",
                                              "raw_log": "Mimikatz detected in process memory on host WIN-SRV-01",
                                              "source_host": "WIN-SRV-01",
                                              "user": "DOMAIN\\admin",
                                              "timestamp": "2026-04-19T10:30:00Z"
                            }
              }


class AlertResponse(BaseModel):
      incident_id: str
      risk_score: float
      severity: str
      mitre_tactics: List[str]
      mitre_techniques: List[str]
      iocs: List[str]
      summary: str
      recommended_action: str
      confidence: float
      incident_status: str
      actions_taken: List[str]
      requires_human: bool
      created_at: str


class HuntRequest(BaseModel):
      hypothesis: str = Field(..., example="Detect C2 beaconing via DNS tunneling")
      iocs: Optional[List[str]] = Field(default_factory=list)
      time_range_hours: int = Field(24, ge=1, le=720)


class HuntResponse(BaseModel):
      hunt_id: str
      hypothesis: str
      status: str
      findings: List[Dict[str, Any]]
      new_iocs: List[str]
      risk_level: str
      summary: str


class IncidentSummary(BaseModel):
      incident_id: str
      status: str
      risk_score: float
      severity: str
      created_at: str
      updated_at: str


# ─────────────────────────────────────────────
# API Endpoints
# ─────────────────────────────────────────────

@app.get("/", tags=["Health"])
async def root():
      """Health check endpoint."""
      return {
          "service": "CyberSentinel AI",
          "version": "1.0.0",
          "status": "operational",
          "timestamp": datetime.utcnow().isoformat(),
      }


@app.get("/health", tags=["Health"])
async def health_check():
      """Detailed health check with component status."""
      return {
          "status": "healthy",
          "components": {
              "orchestrator": "operational" if orchestrator else "unavailable",
              "memory": "operational" if memory else "unavailable",
              "llm": "operational",
          },
          "timestamp": datetime.utcnow().isoformat(),
      }


@app.post(
      "/api/v1/alerts/analyze",
      response_model=AlertResponse,
      status_code=status.HTTP_200_OK,
      tags=["Alerts"],
      summary="Analyze a security alert",
      description="Submit a raw security alert for AI-powered triage, MITRE ATT&CK mapping, and risk scoring."
)
async def analyze_alert(
      alert: AlertRequest,
      background_tasks: BackgroundTasks,
):
      """
          Analyze an incoming security alert through the full multi-agent pipeline.

                  The alert flows through:
                      1. Sentinel Agent (triage + MITRE mapping)
                          2. Hunter Agent (IOC enrichment)  
                              3. Responder Agent (response actions if risk > threshold)
                                  4. Orchestrator (coordination + report)
                                      """
      if not orchestrator:
                raise HTTPException(status_code=503, detail="Orchestrator not initialized")

      try:
                # Process alert through agentic pipeline
                result = orchestrator.process_alert(alert.dict(exclude_none=True))

          return AlertResponse(
                        incident_id=result["incident_id"],
                        risk_score=result.get("risk_score", 0.0),
                        severity=_score_to_severity(result.get("risk_score", 0.0)),
                        mitre_tactics=result.get("mitre_tactics", []),
                        mitre_techniques=result.get("mitre_techniques", []),
                        iocs=result.get("iocs", []),
                        summary=result.get("summary", "Analysis complete"),
                        recommended_action=result.get("recommended_action", "Monitor"),
                        confidence=result.get("confidence", 0.8),
                        incident_status=result.get("incident_status", "open"),
                        actions_taken=result.get("actions_taken", []),
                        requires_human=result.get("requires_human", False),
                        created_at=result.get("created_at", datetime.utcnow().isoformat()),
          )

except Exception as e:
        logger.error(f"Alert analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
      "/api/v1/incidents",
      response_model=List[IncidentSummary],
      tags=["Incidents"],
      summary="List all incidents"
)
async def list_incidents(
      status: Optional[str] = None,
      limit: int = 50,
      offset: int = 0,
):
      """List all incidents with optional status filtering."""
    if not memory:
              raise HTTPException(status_code=503, detail="Memory store not initialized")

    incidents = memory.list_incidents(status=status, limit=limit, offset=offset)
    return incidents


@app.get(
      "/api/v1/incidents/{incident_id}",
      tags=["Incidents"],
      summary="Get incident details"
)
async def get_incident(incident_id: str):
      """Get full details of a specific incident."""
    if not memory:
              raise HTTPException(status_code=503, detail="Memory store not initialized")

    incident = memory.get_incident(incident_id)
    if not incident:
              raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    return incident


@app.post(
      "/api/v1/hunt",
      response_model=HuntResponse,
      tags=["Threat Hunting"],
      summary="Trigger a threat hunt"
)
async def trigger_hunt(hunt_request: HuntRequest):
      """
          Trigger an autonomous threat hunting campaign based on a hypothesis.

                  The Hunter Agent will:
                      1. Parse the hypothesis into hunting queries
                          2. Search SIEM/EDR for matching patterns
                              3. Enrich findings with threat intelligence
                                  4. Extract new IOCs
                                      5. Generate a hunting report
                                          """
    if not orchestrator:
              raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    try:
              import uuid
              hunt_id = f"HUNT-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

        result = orchestrator.hunter.hunt(
                      iocs=hunt_request.iocs,
                      mitre_tactics=[],
                      hypothesis=hunt_request.hypothesis,
        )

        return HuntResponse(
                      hunt_id=hunt_id,
                      hypothesis=hunt_request.hypothesis,
                      status="completed",
                      findings=result.get("findings", []),
                      new_iocs=result.get("new_iocs", []),
                      risk_level=result.get("risk_level", "low"),
                      summary=result.get("summary", "Hunt completed"),
        )

except Exception as e:
        logger.error(f"Threat hunt failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
      "/api/v1/metrics",
      tags=["Metrics"],
      summary="Platform metrics"
)
async def get_metrics():
      """Get platform performance metrics."""
    if not memory:
              return {"error": "Memory not initialized"}

    stats = memory.get_statistics()
    return {
              "incidents": stats,
              "platform": {
                            "version": "1.0.0",
                            "uptime_seconds": 0,
                            "alerts_processed_today": stats.get("total", 0),
              },
              "timestamp": datetime.utcnow().isoformat(),
    }


# ─────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────

def _score_to_severity(score: float) -> str:
      """Convert numeric risk score to severity label."""
    if score >= 9.0:
              return "critical"
elif score >= 7.0:
        return "high"
elif score >= 5.0:
        return "medium"
elif score >= 3.0:
        return "low"
else:
        return "info"


if __name__ == "__main__":
      import uvicorn
    uvicorn.run(
              "api.main:app",
              host="0.0.0.0",
              port=8000,
              reload=True,
              log_level="info",
    )
