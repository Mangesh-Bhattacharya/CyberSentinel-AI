"""
CyberSentinel AI - LLM Engine
Core LLM integration layer supporting multiple providers (OpenAI, Anthropic, Ollama)
with function calling, streaming, and agentic reasoning capabilities.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Union

import anthropic
import openai
from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations & Config
# ---------------------------------------------------------------------------

class LLMProvider(str, Enum):
      OPENAI = "openai"
      ANTHROPIC = "anthropic"
      OLLAMA = "ollama"
      AZURE_OPENAI = "azure_openai"


class ReasoningMode(str, Enum):
      STANDARD = "standard"
      CHAIN_OF_THOUGHT = "chain_of_thought"
      REACT = "react"           # Reason + Act
    REFLEXION = "reflexion"   # Self-reflective reasoning


@dataclass
class LLMConfig:
      provider: LLMProvider = LLMProvider.OPENAI
      model: str = "gpt-4o"
      temperature: float = 0.1
      max_tokens: int = 4096
      timeout: int = 120
      max_retries: int = 3
      reasoning_mode: ReasoningMode = ReasoningMode.REACT
      enable_cache: bool = True
      system_fingerprint: Optional[str] = None

    # Provider-specific
      openai_api_key: Optional[str] = None
      anthropic_api_key: Optional[str] = None
      ollama_base_url: str = "http://localhost:11434"
      azure_endpoint: Optional[str] = None
      azure_api_version: str = "2024-02-01"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class Message(BaseModel):
      role: str  # system | user | assistant | tool
    content: str
    tool_call_id: Optional[str] = None
    tool_calls: Optional[List[Dict]] = None
    name: Optional[str] = None


class ToolDefinition(BaseModel):
      name: str
      description: str
      parameters: Dict[str, Any]
      strict: bool = True


class LLMResponse(BaseModel):
      content: str
      reasoning: Optional[str] = None
      tool_calls: List[Dict] = Field(default_factory=list)
      finish_reason: str = "stop"
      usage: Dict[str, int] = Field(default_factory=dict)
      latency_ms: float = 0.0
      model: str = ""
      provider: str = ""


class ThreatAnalysis(BaseModel):
      threat_level: str  # critical | high | medium | low | info
    confidence: float  # 0.0 - 1.0
    threat_type: str
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    summary: str
    false_positive_probability: float = 0.0


# ---------------------------------------------------------------------------
# Prompt Templates
# ---------------------------------------------------------------------------

SYSTEM_PROMPTS = {
      "threat_analyst": """You are CyberSentinel AI, an elite autonomous cybersecurity analyst with deep expertise in:
      - Threat hunting and advanced persistent threat (APT) analysis
      - MITRE ATT&CK framework (v15) mapping
      - Incident response and digital forensics
      - Network intrusion detection and malware analysis
      - Zero-day vulnerability assessment
      - Cloud security (AWS, Azure, GCP) and container security

      You operate with precision and speed. When analyzing security events:
      1. Always map findings to MITRE ATT&CK tactics and techniques
      2. Provide concrete, actionable remediation steps
      3. Assess confidence levels and false positive probability
      4. Prioritize by business impact and exploitability
      5. Consider the kill chain progression

      Respond in structured JSON when analysis is requested. Be concise, technical, and decisive.""",

      "incident_responder": """You are CyberSentinel AI's Incident Response specialist. You coordinate:
      - Real-time threat containment and eradication
      - Evidence preservation and forensic analysis
      - Stakeholder communication and escalation
      - Recovery planning and business continuity
      - Post-incident lessons learned

      Follow NIST SP 800-61 and PICERL methodology. Always consider:
      - Blast radius and lateral movement potential
      - Data exfiltration risk
      - Regulatory notification requirements (GDPR, HIPAA, PCI-DSS)
      - Evidence integrity for potential legal proceedings""",

      "vulnerability_assessor": """You are CyberSentinel AI's Vulnerability Intelligence specialist. You analyze:
      - CVE details, CVSS v3.1/v4.0 scores, and exploitability
      - Patch prioritization using SSVC (Stakeholder-Specific Vulnerability Categorization)
      - Attack surface reduction strategies
      - Compensating controls when patching is not immediately feasible
      - Supply chain and third-party risk

      Always reference NVD, CISA KEV catalog, and ExploitDB data in your assessments.""",

      "threat_hunter": """You are CyberSentinel AI's Proactive Threat Hunter. You specialize in:
      - Hypothesis-driven threat hunting using the PEAK framework
      - Behavioral analytics and anomaly detection
      - IOC/TTP correlation across SIEM, EDR, and NDR data
      - Living-off-the-land (LotL) attack detection
      - Insider threat detection patterns

      Build hunting hypotheses, define detection logic, and create YARA/Sigma rules.""",
}

REACT_TEMPLATE = """You are reasoning through a cybersecurity task step by step.

Current Task: {task}

Available Tools: {tools}

Security Context:
{context}

Use the following format strictly:
Thought: [Your reasoning about what to do next]
Action: [Tool name to call]
Action Input: [JSON input for the tool]
Observation: [Result from tool - will be filled in]
... (repeat Thought/Action/Action Input/Observation as needed)
Thought: I have gathered enough information to provide a final analysis.
Final Answer: [Complete structured analysis]

Begin:"""


# ---------------------------------------------------------------------------
# LLM Engine
# ---------------------------------------------------------------------------

class LLMEngine:
      """
          Multi-provider LLM engine with agentic capabilities including:
              - Tool/function calling
                  - ReAct reasoning loops
                      - Streaming responses
                          - Response caching
                              - Automatic retry with exponential backoff
                                  """

    def __init__(self, config: LLMConfig):
              self.config = config
              self._response_cache: Dict[str, LLMResponse] = {}
              self._tool_registry: Dict[str, Callable] = {}
              self._clients: Dict[str, Any] = {}
              self._init_clients()
              logger.info(f"LLMEngine initialized: provider={config.provider}, model={config.model}")

    def _init_clients(self):
              """Initialize LLM provider clients."""
              if self.config.provider == LLMProvider.OPENAI:
                            self._clients["openai"] = openai.AsyncOpenAI(
                                              api_key=self.config.openai_api_key,
                                              timeout=self.config.timeout,
                            )
elif self.config.provider == LLMProvider.ANTHROPIC:
            self._clients["anthropic"] = anthropic.AsyncAnthropic(
                              api_key=self.config.anthropic_api_key,
                              timeout=self.config.timeout,
            )
elif self.config.provider == LLMProvider.AZURE_OPENAI:
            self._clients["azure"] = openai.AsyncAzureOpenAI(
                              azure_endpoint=self.config.azure_endpoint,
                              api_version=self.config.azure_api_version,
                              timeout=self.config.timeout,
            )

    def register_tool(self, tool_def: ToolDefinition, handler: Callable):
              """Register a callable tool for function calling."""
              self._tool_registry[tool_def.name] = {"definition": tool_def, "handler": handler}
              logger.debug(f"Registered tool: {tool_def.name}")

    def _get_cache_key(self, messages: List[Message], tools: List[ToolDefinition]) -> str:
              import hashlib
              content = json.dumps([m.dict() for m in messages] + [t.dict() for t in tools], sort_keys=True)
              return hashlib.sha256(content.encode()).hexdigest()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def complete(
              self,
              messages: List[Message],
              tools: Optional[List[ToolDefinition]] = None,
              system_prompt: Optional[str] = None,
              stream: bool = False,
    ) -> LLMResponse:
              """Send messages to LLM and return response."""
              tools = tools or []

        # Check cache
              if self.config.enable_cache and not stream:
                            cache_key = self._get_cache_key(messages, tools)
                            if cache_key in self._response_cache:
                                              logger.debug("Cache hit for LLM request")
                                              return self._response_cache[cache_key]

                        start_time = time.time()

        try:
                      if self.config.provider in (LLMProvider.OPENAI, LLMProvider.AZURE_OPENAI):
                                        response = await self._complete_openai(messages, tools, system_prompt, stream)
elif self.config.provider == LLMProvider.ANTHROPIC:
                response = await self._complete_anthropic(messages, tools, system_prompt, stream)
elif self.config.provider == LLMProvider.OLLAMA:
                response = await self._complete_ollama(messages, tools, system_prompt)
else:
                raise ValueError(f"Unsupported provider: {self.config.provider}")

            response.latency_ms = (time.time() - start_time) * 1000

            if self.config.enable_cache and not stream:
                              self._response_cache[cache_key] = response

            return response

except Exception as e:
            logger.error(f"LLM completion failed: {e}")
            raise

    async def _complete_openai(
              self,
              messages: List[Message],
              tools: List[ToolDefinition],
              system_prompt: Optional[str],
              stream: bool,
    ) -> LLMResponse:
              """OpenAI/Azure completion."""
              client_key = "azure" if self.config.provider == LLMProvider.AZURE_OPENAI else "openai"
              client = self._clients[client_key]

        formatted_messages = []
        if system_prompt:
                      formatted_messages.append({"role": "system", "content": system_prompt})

        for msg in messages:
                      m = {"role": msg.role, "content": msg.content}
                      if msg.tool_call_id:
                                        m["tool_call_id"] = msg.tool_call_id
                                    if msg.tool_calls:
                                                      m["tool_calls"] = msg.tool_calls
                                                  if msg.name:
                                                                    m["name"] = msg.name
                                                                formatted_messages.append(m)

        kwargs = {
                      "model": self.config.model,
                      "messages": formatted_messages,
                      "temperature": self.config.temperature,
                      "max_tokens": self.config.max_tokens,
        }

        if tools:
                      kwargs["tools"] = [
                          {
                                                "type": "function",
                                                "function": {
                                                                          "name": t.name,
                                                                          "description": t.description,
                                                                          "parameters": t.parameters,
                                                                          "strict": t.strict,
                                                },
                          }
                          for t in tools
        ]
            kwargs["tool_choice"] = "auto"

        completion = await client.chat.completions.create(**kwargs)
        choice = completion.choices[0]

        tool_calls = []
        if choice.message.tool_calls:
                      for tc in choice.message.tool_calls:
                                        tool_calls.append({
                                                              "id": tc.id,
                                                              "type": "function",
                                                              "function": {
                                                                                        "name": tc.function.name,
                                                                                        "arguments": tc.function.arguments,
                                                              },
                                        })

        return LLMResponse(
                      content=choice.message.content or "",
                      tool_calls=tool_calls,
                      finish_reason=choice.finish_reason or "stop",
                      usage={
                                        "prompt_tokens": completion.usage.prompt_tokens,
                                        "completion_tokens": completion.usage.completion_tokens,
                                        "total_tokens": completion.usage.total_tokens,
                      },
                      model=completion.model,
                      provider=self.config.provider.value,
        )

    async def _complete_anthropic(
              self,
              messages: List[Message],
              tools: List[ToolDefinition],
              system_prompt: Optional[str],
              stream: bool,
    ) -> LLMResponse:
              """Anthropic Claude completion."""
        client = self._clients["anthropic"]

        formatted_messages = [
                      {"role": msg.role if msg.role != "system" else "user", "content": msg.content}
                      for msg in messages
                      if msg.role != "system"
        ]

        kwargs = {
                      "model": self.config.model,
                      "messages": formatted_messages,
                      "max_tokens": self.config.max_tokens,
                      "temperature": self.config.temperature,
        }

        if system_prompt:
                      kwargs["system"] = system_prompt

        if tools:
                      kwargs["tools"] = [
                          {
                                                "name": t.name,
                                                "description": t.description,
                                                "input_schema": t.parameters,
                          }
                          for t in tools
        ]

        response = await client.messages.create(**kwargs)

        content = ""
        tool_calls = []
        for block in response.content:
                      if block.type == "text":
                                        content = block.text
elif block.type == "tool_use":
                tool_calls.append({
                                      "id": block.id,
                                      "type": "function",
                                      "function": {
                                                                "name": block.name,
                                                                "arguments": json.dumps(block.input),
                                      },
                })

        return LLMResponse(
                      content=content,
                      tool_calls=tool_calls,
                      finish_reason=response.stop_reason or "stop",
                      usage={
                                        "prompt_tokens": response.usage.input_tokens,
                                        "completion_tokens": response.usage.output_tokens,
                                        "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
                      },
                      model=response.model,
                      provider=LLMProvider.ANTHROPIC.value,
        )

    async def _complete_ollama(
              self,
              messages: List[Message],
              tools: List[ToolDefinition],
              system_prompt: Optional[str],
    ) -> LLMResponse:
              """Ollama local model completion."""
        import aiohttp

        payload = {
                      "model": self.config.model,
                      "messages": [{"role": m.role, "content": m.content} for m in messages],
                      "stream": False,
                      "options": {"temperature": self.config.temperature, "num_predict": self.config.max_tokens},
        }
        if system_prompt:
                      payload["system"] = system_prompt

        async with aiohttp.ClientSession() as session:
                      async with session.post(
                          f"{self.config.ollama_base_url}/api/chat",
                          json=payload,
                          timeout=aiohttp.ClientTimeout(total=self.config.timeout),
        ) as resp:
                          data = await resp.json()

        return LLMResponse(
                      content=data.get("message", {}).get("content", ""),
                      finish_reason="stop",
                      model=self.config.model,
                      provider=LLMProvider.OLLAMA.value,
        )

    # ---------------------------------------------------------------------------
    # Agentic ReAct Loop
    # ---------------------------------------------------------------------------

    async def run_react_loop(
              self,
              task: str,
              context: Dict[str, Any],
              agent_type: str = "threat_analyst",
              max_iterations: int = 10,
    ) -> Dict[str, Any]:
              """
                      Execute a ReAct (Reason + Act) loop for autonomous agentic reasoning.
                              The agent thinks, calls tools, observes results, and iterates.
                                      """
        system_prompt = SYSTEM_PROMPTS.get(agent_type, SYSTEM_PROMPTS["threat_analyst"])
        tool_defs = [v["definition"] for v in self._tool_registry.values()]
        tool_names = [t.name for t in tool_defs]

        messages: List[Message] = [
                      Message(
                                        role="user",
                                        content=REACT_TEMPLATE.format(
                                                              task=task,
                                                              tools=json.dumps(tool_names, indent=2),
                                                              context=json.dumps(context, indent=2),
                                        ),
                      )
        ]

        iterations = 0
        execution_trace = []

        while iterations < max_iterations:
                      iterations += 1
            logger.info(f"ReAct iteration {iterations}/{max_iterations}")

            response = await self.complete(messages, tool_defs, system_prompt)
            execution_trace.append({"iteration": iterations, "response": response.content})

            # Check for tool calls
            if response.tool_calls:
                              messages.append(Message(
                                                    role="assistant",
                                                    content=response.content,
                                                    tool_calls=response.tool_calls,
                              ))

                # Execute tool calls in parallel
                              tool_results = await self._execute_tool_calls(response.tool_calls)

                for tc, result in zip(response.tool_calls, tool_results):
                                      messages.append(Message(
                                                                role="tool",
                                                                content=json.dumps(result),
                                                                tool_call_id=tc["id"],
                                                                name=tc["function"]["name"],
                                      ))
                                  continue

            # Check if we have a final answer
            if "Final Answer:" in response.content or response.finish_reason == "stop":
                              return {
                                                    "final_answer": response.content,
                                                    "iterations": iterations,
                                                    "execution_trace": execution_trace,
                                                    "tool_usage": len([t for t in execution_trace if "tool_call" in str(t)]),
                              }

            messages.append(Message(role="assistant", content=response.content))

        return {
                      "final_answer": "Max iterations reached. Partial analysis available.",
                      "iterations": iterations,
                      "execution_trace": execution_trace,
                      "partial": True,
        }

    async def _execute_tool_calls(self, tool_calls: List[Dict]) -> List[Any]:
              """Execute tool calls in parallel and return results."""
        tasks = []
        for tc in tool_calls:
                      fn_name = tc["function"]["name"]
            try:
                              args = json.loads(tc["function"]["arguments"])
except json.JSONDecodeError:
                args = {}

            if fn_name in self._tool_registry:
                              handler = self._tool_registry[fn_name]["handler"]
                              if asyncio.iscoroutinefunction(handler):
                                                    tasks.append(handler(**args))
            else:
                    tasks.append(asyncio.get_event_loop().run_in_executor(None, lambda: handler(**args)))
else:
                tasks.append(asyncio.coroutine(lambda: {"error": f"Tool {fn_name} not found"})())

        return await asyncio.gather(*tasks, return_exceptions=True)

    # ---------------------------------------------------------------------------
    # High-level Security Analysis Methods
    # ---------------------------------------------------------------------------

    async def analyze_threat(self, alert_data: Dict[str, Any]) -> ThreatAnalysis:
              """Analyze a security alert and return structured threat analysis."""
        system_prompt = SYSTEM_PROMPTS["threat_analyst"]

        prompt = f"""Analyze the following security alert and provide a comprehensive threat assessment.

        Alert Data:
        {json.dumps(alert_data, indent=2)}

        Respond with a JSON object matching this exact schema:
        {{
          "threat_level": "critical|high|medium|low|info",
            "confidence": 0.0-1.0,
              "threat_type": "string",
                "mitre_tactics": ["TA0001", ...],
                  "mitre_techniques": ["T1059", ...],
                    "indicators": ["IOC1", ...],
                      "recommended_actions": ["action1", ...],
                        "summary": "string",
                          "false_positive_probability": 0.0-1.0
                          }}"""

        messages = [Message(role="user", content=prompt)]
        response = await self.complete(messages, system_prompt=system_prompt)

        # Parse JSON from response
        try:
                      # Extract JSON block
                      content = response.content
            if "```json" in content:
                              content = content.split("```json")[1].split("```")[0].strip()
elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()

            data = json.loads(content)
            return ThreatAnalysis(**data)
except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse threat analysis JSON: {e}")
            return ThreatAnalysis(
                              threat_level="medium",
                              confidence=0.5,
                              threat_type="unknown",
                              summary=response.content,
            )

    async def generate_hunt_hypothesis(self, environment_context: Dict) -> List[Dict]:
              """Generate proactive threat hunting hypotheses based on environment context."""
        system_prompt = SYSTEM_PROMPTS["threat_hunter"]

        prompt = f"""Based on the following environment context, generate 5 threat hunting hypotheses.

        Environment:
        {json.dumps(environment_context, indent=2)}

        For each hypothesis, provide:
        1. Hypothesis statement
        2. MITRE ATT&CK technique(s) being hunted
        3. Data sources required
        4. Detection logic (pseudo-code or Sigma rule)
        5. Priority (1-5, where 1 is highest)

        Format as JSON array."""

        messages = [Message(role="user", content=prompt)]
        response = await self.complete(messages, system_prompt=system_prompt)

        try:
                      content = response.content
            if "```json" in content:
                              content = content.split("```json")[1].split("```")[0].strip()
elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            return json.loads(content)
except Exception:
            return [{"hypothesis": response.content, "priority": 3}]

    async def generate_sigma_rule(self, threat_description: str, log_source: str) -> str:
              """Generate a Sigma detection rule for a given threat."""
        prompt = f"""Generate a production-ready Sigma detection rule for the following threat.

        Threat Description: {threat_description}
        Log Source: {log_source}

        Requirements:
        - Valid Sigma v2.0 syntax
        - Include all required fields (title, id, status, description, references, author, date, logsource, detection, falsepositives, level)
        - Use proper condition logic
        - Include relevant field mappings

        Output only the Sigma YAML rule, no explanations."""

        messages = [Message(role="user", content=prompt)]
        response = await self.complete(messages, system_prompt=SYSTEM_PROMPTS["threat_analyst"])
        return response.content

    async def explain_vulnerability(self, cve_id: str, cve_data: Dict) -> Dict:
              """Generate a comprehensive vulnerability explanation and remediation guide."""
        system_prompt = SYSTEM_PROMPTS["vulnerability_assessor"]

        prompt = f"""Analyze CVE {cve_id} and provide a comprehensive assessment.

        CVE Data:
        {json.dumps(cve_data, indent=2)}

        Provide:
        1. Executive summary (2-3 sentences)
        2. Technical deep-dive
        3. Attack scenarios (how an attacker would exploit this)
        4. SSVC priority score with justification
        5. Immediate mitigations (if patching is not possible)
        6. Patch guidance
        7. Detection opportunities (log sources, indicators)

        Format as structured JSON."""

        messages = [Message(role="user", content=prompt)]
        response = await self.complete(messages, system_prompt=system_prompt)

        try:
                      content = response.content
            if "```json" in content:
                              content = content.split("```json")[1].split("```")[0].strip()
                          return json.loads(content)
except Exception:
            return {"analysis": response.content, "cve_id": cve_id}

    async def stream_incident_response(
              self, incident_data: Dict
    ) -> AsyncIterator[str]:
              """Stream incident response guidance in real-time."""
        system_prompt = SYSTEM_PROMPTS["incident_responder"]
        prompt = f"""Provide step-by-step incident response guidance for:

        {json.dumps(incident_data, indent=2)}

        Structure your response as:
        1. IMMEDIATE ACTIONS (next 15 minutes)
        2. CONTAINMENT (15 min - 2 hours)
        3. INVESTIGATION (2-24 hours)
        4. ERADICATION & RECOVERY (24-72 hours)
        5. POST-INCIDENT (week 1-2)

        Be specific, actionable, and prioritize by impact."""

        if self.config.provider == LLMProvider.OPENAI:
                      client = self._clients["openai"]
            formatted_msgs = [
                              {"role": "system", "content": system_prompt},
                              {"role": "user", "content": prompt},
            ]
            async with client.chat.completions.stream(
                              model=self.config.model,
                              messages=formatted_msgs,
                              temperature=self.config.temperature,
                              max_tokens=self.config.max_tokens,
            ) as stream:
                              async for chunk in stream:
                                                    if chunk.choices[0].delta.content:
                                                                              yield chunk.choices[0].delta.content
else:
            response = await self.complete(
                              [Message(role="user", content=prompt)],
                              system_prompt=system_prompt,
            )
            yield response.content


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_llm_engine(
      provider: str = "openai",
      model: Optional[str] = None,
      **kwargs,
) -> LLMEngine:
      """Factory function to create an LLM engine from simple parameters."""
    provider_enum = LLMProvider(provider)
    default_models = {
              LLMProvider.OPENAI: "gpt-4o",
              LLMProvider.ANTHROPIC: "claude-opus-4-5",
              LLMProvider.OLLAMA: "llama3.3",
              LLMProvider.AZURE_OPENAI: "gpt-4o",
    }
    config = LLMConfig(
              provider=provider_enum,
              model=model or default_models[provider_enum],
              **kwargs,
    )
    return LLMEngine(config)
