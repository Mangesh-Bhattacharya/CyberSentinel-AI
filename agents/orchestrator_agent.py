"""
CyberSentinel AI - Orchestrator Agent
=====================================
Central coordination agent that routes tasks between specialized agents
using LangGraph ReAct reasoning and maintains shared incident state.

Author: Mangesh Bhattacharya
Company: SentinelSync Inc.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode

from agents.sentinel_agent import SentinelAgent
from agents.hunter_agent import HunterAgent
from agents.responder_agent import ResponderAgent
from agents.vulnerability_agent import VulnerabilityAgent
from core.memory import IncidentMemory
from core.tools import get_orchestrator_tools

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# State Schema
# ─────────────────────────────────────────────

class AgentState(TypedDict):
      """Shared state across all agents in the graph."""
      incident_id: str
      messages: List[Any]
      current_agent: str
      alert_data: Dict[str, Any]
      risk_score: float
      mitre_tactics: List[str]
      iocs: List[str]
      actions_taken: List[str]
      requires_human: bool
      incident_status: str  # open | investigating | contained | resolved
    created_at: str
    updated_at: str


# ─────────────────────────────────────────────
# Orchestrator Agent
# ─────────────────────────────────────────────

class OrchestratorAgent:
      """
          Central AI agent that coordinates all specialized agents.
              Uses LangGraph to implement a ReAct-style multi-agent workflow
                  with conditional routing based on threat context.
                      """

    SYSTEM_PROMPT = """You are the CyberSentinel AI Orchestrator — a senior cybersecurity 
        AI agent responsible for coordinating a team of specialized security agents.

            Your responsibilities:
                1. Analyze incoming security alerts and determine priority
                    2. Route tasks to the appropriate specialized agent:
                           - SentinelAgent: Alert triage, MITRE ATT&CK mapping, risk scoring
                                  - HunterAgent: Proactive threat hunting, IOC enrichment
                                         - ResponderAgent: Incident response, containment actions
                                                - VulnerabilityAgent: CVE triage, patch prioritization
                                                    3. Maintain incident state and ensure continuity across agent handoffs
                                                        4. Escalate to human analysts when confidence < 70% or risk score > 9.5
                                                            5. Generate executive briefings upon incident resolution

                                                                Always reason step-by-step (ReAct pattern):
                                                                    Thought -> Action -> Observation -> Thought -> ... -> Final Answer

                                                                        Be decisive, precise, and security-first in all decisions.
                                                                            """

    def __init__(self, config: Dict[str, Any]):
              self.config = config
              self.memory = IncidentMemory()
              self.llm = self._init_llm()
              self.tools = get_orchestrator_tools()

        # Initialize specialized agents
              self.sentinel = SentinelAgent(config, self.llm)
              self.hunter = HunterAgent(config, self.llm)
              self.responder = ResponderAgent(config, self.llm)
              self.vulnerability = VulnerabilityAgent(config, self.llm)

        # Build the agent graph
              self.graph = self._build_graph()

    def _init_llm(self):
              """Initialize LLM based on configuration."""
              provider = self.config.get("llm", {}).get("provider", "openai")
              model = self.config.get("llm", {}).get("model", "gpt-4o")
              temperature = self.config.get("llm", {}).get("temperature", 0.1)

        if provider == "anthropic":
                      return ChatAnthropic(model=model, temperature=temperature)
else:
              return ChatOpenAI(model=model, temperature=temperature)

    def _build_graph(self) -> StateGraph:
              """Build the LangGraph multi-agent workflow."""
              graph = StateGraph(AgentState)

        # Add nodes for each agent
              graph.add_node("orchestrator", self._orchestrator_node)
        graph.add_node("sentinel", self._sentinel_node)
        graph.add_node("hunter", self._hunter_node)
        graph.add_node("responder", self._responder_node)
        graph.add_node("vulnerability", self._vulnerability_node)
        graph.add_node("human_escalation", self._human_escalation_node)
        graph.add_node("report_generator", self._report_generator_node)
        graph.add_node("tools", ToolNode(self.tools))

        # Define workflow edges
        graph.set_entry_point("orchestrator")

        # Conditional routing from orchestrator
        graph.add_conditional_edges(
                      "orchestrator",
                      self._route_from_orchestrator,
                      {
                                        "sentinel": "sentinel",
                                        "hunter": "hunter",
                                        "responder": "responder",
                                        "vulnerability": "vulnerability",
                                        "human": "human_escalation",
                                        "report": "report_generator",
                                        "tools": "tools",
                                        "end": END,
                      }
        )

        # After each specialized agent, return to orchestrator
        for agent in ["sentinel", "hunter", "responder", "vulnerability"]:
                      graph.add_edge(agent, "orchestrator")

        graph.add_edge("tools", "orchestrator")
        graph.add_edge("human_escalation", END)
        graph.add_edge("report_generator", END)

        return graph.compile()

    def _route_from_orchestrator(self, state: AgentState) -> str:
              """Determine next agent based on current state."""
              # Human escalation if required
              if state.get("requires_human"):
                            return "human"

        # Check if incident is resolved
        if state.get("incident_status") == "resolved":
                      return "report"

        # Parse last message to determine routing
        messages = state.get("messages", [])
        if not messages:
                      return "sentinel"

        last_message = messages[-1]
        content = getattr(last_message, "content", "").lower()

        # Route based on orchestrator decision
        if "sentinel" in content or "triage" in content:
                      return "sentinel"
elif "hunt" in content or "threat hunting" in content:
              return "hunter"
elif "respond" in content or "contain" in content or "block" in content:
              return "responder"
elif "vulnerability" in content or "cve" in content or "patch" in content:
              return "vulnerability"
elif "tool" in content:
              return "tools"
elif state.get("risk_score", 0) > 9.5:
              return "human"
else:
              return "end"

    def _orchestrator_node(self, state: AgentState) -> AgentState:
              """Main orchestrator reasoning node."""
              messages = state.get("messages", [])

        # Build context message
              context = {
                            "incident_id": state.get("incident_id"),
                            "risk_score": state.get("risk_score", 0),
                            "mitre_tactics": state.get("mitre_tactics", []),
                            "actions_taken": state.get("actions_taken", []),
                            "incident_status": state.get("incident_status", "open"),
              }

        system_msg = SystemMessage(content=self.SYSTEM_PROMPT)
        user_msg = HumanMessage(content=f"""
                Current Incident Context:
                        {json.dumps(context, indent=2)}

                                        Alert Data:
                                                {json.dumps(state.get('alert_data', {}), indent=2)}

                                                                Determine the next action and which agent should handle it.
                                                                        """)

        response = self.llm.invoke([system_msg] + messages + [user_msg])

        return {
                      **state,
                      "messages": messages + [user_msg, response],
                      "current_agent": "orchestrator",
                      "updated_at": datetime.utcnow().isoformat(),
        }

    def _sentinel_node(self, state: AgentState) -> AgentState:
              """Route to Sentinel Agent for triage."""
              result = self.sentinel.analyze(state["alert_data"])
              return {
                  **state,
                  "risk_score": result.get("risk_score", state.get("risk_score", 0)),
                  "mitre_tactics": result.get("mitre_tactics", []),
                  "iocs": result.get("iocs", []),
                  "messages": state["messages"] + [
                      AIMessage(content=f"[SentinelAgent] {result.get('summary', 'Triage complete')}")
                  ],
                  "current_agent": "sentinel",
              }

    def _hunter_node(self, state: AgentState) -> AgentState:
              """Route to Hunter Agent for threat hunting."""
              result = self.hunter.hunt(
                  iocs=state.get("iocs", []),
                  mitre_tactics=state.get("mitre_tactics", [])
              )
              return {
                  **state,
                  "iocs": state.get("iocs", []) + result.get("new_iocs", []),
                  "messages": state["messages"] + [
                      AIMessage(content=f"[HunterAgent] {result.get('summary', 'Hunting complete')}")
                  ],
                  "current_agent": "hunter",
              }

    def _responder_node(self, state: AgentState) -> AgentState:
              """Route to Responder Agent for incident response."""
              result = self.responder.respond(
                  incident_id=state["incident_id"],
                  alert_data=state["alert_data"],
                  risk_score=state.get("risk_score", 0),
                  auto_contain=self.config.get("agents", {}).get("responder", {}).get("auto_contain", False)
              )
              return {
                  **state,
                  "actions_taken": state.get("actions_taken", []) + result.get("actions", []),
                  "incident_status": result.get("status", state.get("incident_status", "open")),
                  "messages": state["messages"] + [
                      AIMessage(content=f"[ResponderAgent] {result.get('summary', 'Response complete')}")
                  ],
                  "current_agent": "responder",
              }

    def _vulnerability_node(self, state: AgentState) -> AgentState:
              """Route to Vulnerability Agent for CVE triage."""
              result = self.vulnerability.assess(state["alert_data"])
              return {
                  **state,
                  "messages": state["messages"] + [
                      AIMessage(content=f"[VulnerabilityAgent] {result.get('summary', 'Assessment complete')}")
                  ],
                  "current_agent": "vulnerability",
              }

    def _human_escalation_node(self, state: AgentState) -> AgentState:
              """Escalate to human analyst."""
              logger.warning(
                  f"[ESCALATION] Incident {state['incident_id']} requires human review. "
                  f"Risk Score: {state.get('risk_score', 0):.1f}"
              )
              return {
                  **state,
                  "incident_status": "escalated",
                  "requires_human": True,
                  "messages": state["messages"] + [
                      AIMessage(content=f"[ESCALATED] Incident {state['incident_id']} has been escalated to Tier-2 analyst. Risk Score: {state.get('risk_score', 0):.1f}/10")
                  ],
              }

    def _report_generator_node(self, state: AgentState) -> AgentState:
              """Generate final incident report."""
              report = {
                  "incident_id": state["incident_id"],
                  "status": state["incident_status"],
                  "risk_score": state.get("risk_score", 0),
                  "mitre_tactics": state.get("mitre_tactics", []),
                  "iocs": state.get("iocs", []),
                  "actions_taken": state.get("actions_taken", []),
                  "timeline": {
                      "created": state.get("created_at"),
                      "resolved": datetime.utcnow().isoformat(),
                  }
              }
              logger.info(f"[REPORT] Incident {state['incident_id']} resolved: {json.dumps(report, indent=2)}")
              return {
                  **state,
                  "messages": state["messages"] + [
                      AIMessage(content=f"[REPORT GENERATED] {json.dumps(report, indent=2)}")
                  ],
              }

    def process_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
              """
                      Main entry point: process an incoming security alert.

                                      Args:
                                                  alert_data: Raw alert data from SIEM/EDR/network sensor

                                                                      Returns:
                                                                                  Final incident state with all agent outputs
                                                                                          """
              import uuid
              incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

        logger.info(f"[ORCHESTRATOR] Processing new alert -> {incident_id}")

        initial_state: AgentState = {
                      "incident_id": incident_id,
                      "messages": [],
                      "current_agent": "orchestrator",
                      "alert_data": alert_data,
                      "risk_score": 0.0,
                      "mitre_tactics": [],
                      "iocs": [],
                      "actions_taken": [],
                      "requires_human": False,
                      "incident_status": "open",
                      "created_at": datetime.utcnow().isoformat(),
                      "updated_at": datetime.utcnow().isoformat(),
        }

        # Run the agentic graph
        final_state = self.graph.invoke(
                      initial_state,
                      config={"recursion_limit": 25}
        )

        # Store in memory
        self.memory.store_incident(incident_id, final_state)

        return final_state
