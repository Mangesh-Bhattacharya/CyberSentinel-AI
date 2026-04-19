"""
CyberSentinel AI - Memory Store
Hybrid memory system combining short-term (Redis), long-term (vector DB),
and episodic (PostgreSQL) memory for persistent agent context and learning.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import redis.asyncio as aioredis
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Memory Types
# ---------------------------------------------------------------------------

class MemoryType(str, Enum):
      SHORT_TERM = "short_term"       # Redis - fast, ephemeral (TTL-based)
    LONG_TERM = "long_term"         # Vector DB - semantic search
    EPISODIC = "episodic"           # PostgreSQL - event-based with full context
    WORKING = "working"             # In-memory dict - current session


class MemoryPriority(str, Enum):
      CRITICAL = "critical"
      HIGH = "high"
      MEDIUM = "medium"
      LOW = "low"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class MemoryEntry(BaseModel):
      id: str = Field(default_factory=lambda: str(uuid.uuid4()))
      content: str
      metadata: Dict[str, Any] = Field(default_factory=dict)
      memory_type: MemoryType = MemoryType.SHORT_TERM
      priority: MemoryPriority = MemoryPriority.MEDIUM
      tags: List[str] = Field(default_factory=list)
      created_at: datetime = Field(default_factory=datetime.utcnow)
      accessed_at: datetime = Field(default_factory=datetime.utcnow)
      access_count: int = 0
      ttl_seconds: Optional[int] = None
      embedding: Optional[List[float]] = None
      source_agent: Optional[str] = None
      session_id: Optional[str] = None


class SecurityContext(BaseModel):
      """Accumulated security context across agent sessions."""
      session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
      active_incidents: List[Dict] = Field(default_factory=list)
      known_threats: List[Dict] = Field(default_factory=list)
      compromised_assets: List[str] = Field(default_factory=list)
      investigation_timeline: List[Dict] = Field(default_factory=list)
      iocs: Dict[str, List[str]] = Field(default_factory=dict)  # type -> list of IOCs
    mitre_techniques_observed: List[str] = Field(default_factory=list)
    environment_baseline: Dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class AgentMemorySnapshot(BaseModel):
      """Snapshot of agent's memory at a point in time for debugging/audit."""
      agent_id: str
      session_id: str
      timestamp: datetime = Field(default_factory=datetime.utcnow)
      working_memory: Dict[str, Any] = Field(default_factory=dict)
      recent_actions: List[Dict] = Field(default_factory=list)
      context_summary: str = ""
      total_tokens_used: int = 0


# ---------------------------------------------------------------------------
# Short-Term Memory (Redis)
# ---------------------------------------------------------------------------

class ShortTermMemory:
      """
          Redis-backed short-term memory with TTL support.
              Stores recent alerts, agent state, and session context.
                  """

    DEFAULT_TTL = 3600  # 1 hour

    def __init__(self, redis_url: str = "redis://localhost:6379"):
              self.redis_url = redis_url
              self._client: Optional[aioredis.Redis] = None

    async def _get_client(self) -> aioredis.Redis:
              if self._client is None:
                            self._client = await aioredis.from_url(
                                              self.redis_url,
                                              encoding="utf-8",
                                              decode_responses=True,
                                              max_connections=20,
                            )
                        return self._client

    async def store(
              self,
              key: str,
              value: Any,
              ttl: int = DEFAULT_TTL,
              namespace: str = "cybersentinel",
    ) -> bool:
              """Store a value with optional TTL."""
        client = await self._get_client()
        full_key = f"{namespace}:{key}"
        serialized = json.dumps(value) if not isinstance(value, str) else value
        await client.set(full_key, serialized, ex=ttl)
        logger.debug(f"Stored in short-term memory: {full_key}")
        return True

    async def retrieve(self, key: str, namespace: str = "cybersentinel") -> Optional[Any]:
              """Retrieve a value."""
        client = await self._get_client()
        full_key = f"{namespace}:{key}"
        data = await client.get(full_key)
        if data is None:
                      return None
                  try:
                                return json.loads(data)
except json.JSONDecodeError:
            return data

    async def delete(self, key: str, namespace: str = "cybersentinel") -> bool:
              """Delete a key."""
        client = await self._get_client()
        result = await client.delete(f"{namespace}:{key}")
        return result > 0

    async def store_alert(self, alert_id: str, alert_data: Dict, ttl: int = 86400) -> bool:
              """Store a security alert."""
        return await self.store(f"alert:{alert_id}", alert_data, ttl=ttl)

    async def get_alert(self, alert_id: str) -> Optional[Dict]:
              """Retrieve a security alert."""
        return await self.retrieve(f"alert:{alert_id}")

    async def store_agent_state(self, agent_id: str, state: Dict, ttl: int = 1800) -> bool:
              """Store agent working state."""
        return await self.store(f"agent_state:{agent_id}", state, ttl=ttl)

    async def get_agent_state(self, agent_id: str) -> Optional[Dict]:
              """Get agent working state."""
        return await self.retrieve(f"agent_state:{agent_id}")

    async def push_event(self, queue: str, event: Dict, max_size: int = 1000) -> bool:
              """Push an event to a Redis list (queue)."""
              client = await self._get_client()
              key = f"cybersentinel:queue:{queue}"
              await client.lpush(key, json.dumps(event))
              await client.ltrim(key, 0, max_size - 1)
              return True

    async def pop_events(self, queue: str, count: int = 10) -> List[Dict]:
              """Pop events from a Redis list."""
              client = await self._get_client()
              key = f"cybersentinel:queue:{queue}"
              pipe = client.pipeline()
              for _ in range(count):
                            pipe.rpop(key)
                        results = await pipe.execute()
        return [json.loads(r) for r in results if r is not None]

    async def increment_counter(self, counter_name: str, ttl: int = 3600) -> int:
              """Increment a rate counter."""
        client = await self._get_client()
        key = f"cybersentinel:counter:{counter_name}"
        count = await client.incr(key)
        if count == 1:
                      await client.expire(key, ttl)
                  return count

    async def set_lock(self, lock_name: str, ttl: int = 30) -> bool:
              """Acquire a distributed lock."""
        client = await self._get_client()
        key = f"cybersentinel:lock:{lock_name}"
        result = await client.set(key, "1", ex=ttl, nx=True)
        return result is True

    async def release_lock(self, lock_name: str) -> bool:
              """Release a distributed lock."""
        return await self.delete(f"lock:{lock_name}")

    async def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
              """Get recent alerts from the stream."""
        return await self.pop_events("alerts", count=limit)

    async def health_check(self) -> bool:
              """Check Redis connectivity."""
        try:
                      client = await self._get_client()
                      await client.ping()
                      return True
except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False


# ---------------------------------------------------------------------------
# Long-Term Memory (Vector Store)
# ---------------------------------------------------------------------------

class LongTermMemory:
      """
          Vector database-backed long-term memory for semantic search.
              Supports Chroma, Qdrant, and Pinecone backends.
                  Stores threat intelligence, past incidents, and learned patterns.
                      """

    def __init__(
              self,
              backend: str = "chroma",
              collection_name: str = "cybersentinel_memory",
              persist_directory: str = "./data/chroma",
              embedding_model: str = "all-MiniLM-L6-v2",
    ):
              self.backend = backend
              self.collection_name = collection_name
              self.persist_directory = persist_directory
              self.embedding_model_name = embedding_model
              self._collection = None
              self._embedding_fn = None

    def _init_chroma(self):
              """Initialize ChromaDB collection."""
              try:
                            import chromadb
                            from chromadb.utils import embedding_functions

                  client = chromadb.PersistentClient(path=self.persist_directory)
            ef = embedding_functions.SentenceTransformerEmbeddingFunction(
                              model_name=self.embedding_model_name
            )
            self._collection = client.get_or_create_collection(
                              name=self.collection_name,
                              embedding_function=ef,
                              metadata={"hnsw:space": "cosine"},
            )
            logger.info(f"ChromaDB initialized: {self.collection_name}")
except ImportError:
            logger.warning("ChromaDB not installed. Long-term memory disabled.")

    async def initialize(self):
              """Initialize the vector store."""
        if self.backend == "chroma":
                      await asyncio.get_event_loop().run_in_executor(None, self._init_chroma)

    async def store_memory(self, entry: MemoryEntry) -> str:
              """Store a memory entry with semantic embedding."""
        if self._collection is None:
                      await self.initialize()

        if self._collection is None:
                      return entry.id

        def _store():
                      self._collection.upsert(
                                        ids=[entry.id],
                                        documents=[entry.content],
                                        metadatas=[{
                                                              "priority": entry.priority.value,
                                                              "tags": json.dumps(entry.tags),
                                                              "source_agent": entry.source_agent or "",
                                                              "session_id": entry.session_id or "",
                                                              "created_at": entry.created_at.isoformat(),
                                                              **{k: str(v) for k, v in entry.metadata.items()},
                                        }],
                      )

        await asyncio.get_event_loop().run_in_executor(None, _store)
        logger.debug(f"Stored in long-term memory: {entry.id}")
        return entry.id

    async def semantic_search(
              self,
              query: str,
              n_results: int = 5,
              filter_tags: Optional[List[str]] = None,
              min_relevance: float = 0.5,
    ) -> List[Dict[str, Any]]:
              """Search memory semantically."""
        if self._collection is None:
                      await self.initialize()

        if self._collection is None:
                      return []

        where = None
        if filter_tags:
                      # ChromaDB where filter
                      where = {"tags": {"$in": filter_tags}}

        def _search():
                      results = self._collection.query(
                                        query_texts=[query],
                                        n_results=n_results,
                                        where=where,
                                        include=["documents", "metadatas", "distances"],
                      )
                      return results

        raw = await asyncio.get_event_loop().run_in_executor(None, _search)

        memories = []
        if raw["ids"] and raw["ids"][0]:
                      for i, (doc_id, doc, meta, dist) in enumerate(
                                        zip(raw["ids"][0], raw["documents"][0], raw["metadatas"][0], raw["distances"][0])
                      ):
                                        relevance = 1 - dist  # cosine distance → similarity
                if relevance >= min_relevance:
                                      memories.append({
                                                                "id": doc_id,
                                                                "content": doc,
                                                                "metadata": meta,
                                                                "relevance": relevance,
                                                                "rank": i + 1,
                                      })

        return sorted(memories, key=lambda x: x["relevance"], reverse=True)

    async def store_threat_intel(self, threat_data: Dict) -> str:
              """Store threat intelligence report."""
        content = f"""
        Threat Type: {threat_data.get('threat_type', 'unknown')}
        Severity: {threat_data.get('severity', 'unknown')}
        MITRE Techniques: {', '.join(threat_data.get('mitre_techniques', []))}
        IOCs: {json.dumps(threat_data.get('iocs', {}))}
        Summary: {threat_data.get('summary', '')}
        Recommended Actions: {', '.join(threat_data.get('recommended_actions', []))}
                """.strip()

        entry = MemoryEntry(
                      content=content,
                      metadata=threat_data,
                      memory_type=MemoryType.LONG_TERM,
                      priority=MemoryPriority.HIGH,
                      tags=["threat_intel"] + threat_data.get("mitre_techniques", []),
                      source_agent="sentinel_agent",
        )
        return await self.store_memory(entry)

    async def find_similar_incidents(self, incident_description: str, n: int = 3) -> List[Dict]:
              """Find past incidents similar to the current one."""
        return await self.semantic_search(
                      query=incident_description,
                      n_results=n,
                      filter_tags=["incident"],
        )

    async def store_sigma_rule(self, rule_content: str, rule_metadata: Dict) -> str:
              """Store a generated Sigma detection rule."""
        entry = MemoryEntry(
                      content=rule_content,
                      metadata=rule_metadata,
                      memory_type=MemoryType.LONG_TERM,
                      priority=MemoryPriority.HIGH,
                      tags=["sigma_rule", "detection"],
        )
        return await self.store_memory(entry)


# ---------------------------------------------------------------------------
# Episodic Memory (SQLite for local dev / PostgreSQL for prod)
# ---------------------------------------------------------------------------

class EpisodicMemory:
      """
          SQL-backed episodic memory for complete event reconstruction.
              Stores full incident timelines, agent decision traces, and audit logs.
                  """

    def __init__(self, db_url: str = "sqlite+aiosqlite:///./data/episodic_memory.db"):
              self.db_url = db_url
        self._engine = None

    async def initialize(self):
              """Create tables if they don't exist."""
        try:
                      from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
                      from sqlalchemy import text

            self._engine = create_async_engine(self.db_url, echo=False)

            create_events = """
                        CREATE TABLE IF NOT EXISTS security_events (
                                        id TEXT PRIMARY KEY,
                                                        session_id TEXT,
                                                                        event_type TEXT NOT NULL,
                                                                                        severity TEXT DEFAULT 'medium',
                                                                                                        source TEXT,
                                                                                                                        content TEXT NOT NULL,
                                                                                                                                        metadata JSON,
                                                                                                                                                        tags TEXT,
                                                                                                                                                                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                                                                                                                                                        processed INTEGER DEFAULT 0
                                                                                                                                                                                                    )
                                                                                                                                                                                                                """
            create_decisions = """
                        CREATE TABLE IF NOT EXISTS agent_decisions (
                                        id TEXT PRIMARY KEY,
                                                        agent_id TEXT NOT NULL,
                                                                        session_id TEXT,
                                                                                        action TEXT NOT NULL,
                                                                                                        reasoning TEXT,
                                                                                                                        outcome TEXT,
                                                                                                                                        confidence REAL,
                                                                                                                                                        tokens_used INTEGER DEFAULT 0,
                                                                                                                                                                        latency_ms REAL DEFAULT 0,
                                                                                                                                                                                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                                                                                                                                                                                                    )
                                                                                                                                                                                                                """
            create_iocs = """
                        CREATE TABLE IF NOT EXISTS ioc_registry (
                                        id TEXT PRIMARY KEY,
                                                        ioc_type TEXT NOT NULL,
                                                                        ioc_value TEXT NOT NULL UNIQUE,
                                                                                        threat_level TEXT DEFAULT 'medium',
                                                                                                        source TEXT,
                                                                                                                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                                                                                                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                                                                                                                        hit_count INTEGER DEFAULT 1,
                                                                                                                                                                        is_active INTEGER DEFAULT 1,
                                                                                                                                                                                        metadata JSON
                                                                                                                                                                                                    )
                                                                                                                                                                                                                """
            create_incidents = """
                        CREATE TABLE IF NOT EXISTS incidents (
                                        id TEXT PRIMARY KEY,
                                                        title TEXT NOT NULL,
                                                                        severity TEXT NOT NULL,
                                                                                        status TEXT DEFAULT 'open',
                                                                                                        assigned_agent TEXT,
                                                                                                                        description TEXT,
                                                                                                                                        affected_assets TEXT,
                                                                                                                                                        mitre_techniques TEXT,
                                                                                                                                                                        timeline TEXT,
                                                                                                                                                                                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                                                                                                                                                                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                                                                                                                                                                                        resolved_at TIMESTAMP
                                                                                                                                                                                                                                    )
                                                                                                                                                                                                                                                """

            async with self._engine.begin() as conn:
                              for stmt in [create_events, create_decisions, create_iocs, create_incidents]:
                                                    await conn.execute(text(stmt))

                          logger.info("Episodic memory database initialized")
except ImportError:
            logger.warning("SQLAlchemy not installed. Episodic memory disabled.")

    async def log_security_event(
              self,
              event_type: str,
              content: str,
              severity: str = "medium",
              source: str = "",
              session_id: str = "",
              metadata: Optional[Dict] = None,
              tags: Optional[List[str]] = None,
    ) -> str:
              """Log a security event to episodic memory."""
        if self._engine is None:
                      await self.initialize()

        if self._engine is None:
                      return str(uuid.uuid4())

        from sqlalchemy.ext.asyncio import AsyncSession
        from sqlalchemy import text

        event_id = str(uuid.uuid4())
        async with AsyncSession(self._engine) as session:
                      await session.execute(
                                        text("""
                                                        INSERT INTO security_events
                                                                        (id, session_id, event_type, severity, source, content, metadata, tags)
                                                                                        VALUES (:id, :session_id, :event_type, :severity, :source, :content, :metadata, :tags)
                                                                                                        """),
                                        {
                                                              "id": event_id,
                                                              "session_id": session_id,
                                                              "event_type": event_type,
                                                              "severity": severity,
                                                              "source": source,
                                                              "content": content,
                                                              "metadata": json.dumps(metadata or {}),
                                                              "tags": json.dumps(tags or []),
                                        },
                      )
                      await session.commit()

        return event_id

    async def log_agent_decision(
              self,
              agent_id: str,
              action: str,
              reasoning: str,
              outcome: str = "",
              confidence: float = 0.0,
              tokens_used: int = 0,
              latency_ms: float = 0.0,
              session_id: str = "",
    ) -> str:
              """Log an agent's decision for audit trail."""
        if self._engine is None:
                      await self.initialize()

        if self._engine is None:
                      return str(uuid.uuid4())

        from sqlalchemy.ext.asyncio import AsyncSession
        from sqlalchemy import text

        decision_id = str(uuid.uuid4())
        async with AsyncSession(self._engine) as session:
                      await session.execute(
                                        text("""
                                                        INSERT INTO agent_decisions
                                                                        (id, agent_id, session_id, action, reasoning, outcome, confidence, tokens_used, latency_ms)
                                                                                        VALUES (:id, :agent_id, :session_id, :action, :reasoning, :outcome, :confidence, :tokens_used, :latency_ms)
                                                                                                        """),
                                        {
                                                              "id": decision_id,
                                                              "agent_id": agent_id,
                                                              "session_id": session_id,
                                                              "action": action,
                                                              "reasoning": reasoning,
                                                              "outcome": outcome,
                                                              "confidence": confidence,
                                                              "tokens_used": tokens_used,
                                                              "latency_ms": latency_ms,
                                        },
                      )
                      await session.commit()

        return decision_id

    async def register_ioc(
              self,
              ioc_type: str,
              ioc_value: str,
              threat_level: str = "medium",
              source: str = "",
              metadata: Optional[Dict] = None,
    ) -> str:
              """Register or update an IOC."""
        if self._engine is None:
                      await self.initialize()

        from sqlalchemy.ext.asyncio import AsyncSession
        from sqlalchemy import text

        ioc_id = hashlib.sha256(f"{ioc_type}:{ioc_value}".encode()).hexdigest()[:16]

        async with AsyncSession(self._engine) as session:
                      # Upsert IOC
                      await session.execute(
                                        text("""
                                                        INSERT INTO ioc_registry (id, ioc_type, ioc_value, threat_level, source, metadata)
                                                                        VALUES (:id, :ioc_type, :ioc_value, :threat_level, :source, :metadata)
                                                                                        ON CONFLICT(ioc_value) DO UPDATE SET
                                                                                                            last_seen = CURRENT_TIMESTAMP,
                                                                                                                                hit_count = hit_count + 1,
                                                                                                                                                    threat_level = :threat_level
                                                                                                                                                                    """),
                                        {
                                                              "id": ioc_id,
                                                              "ioc_type": ioc_type,
                                                              "ioc_value": ioc_value,
                                                              "threat_level": threat_level,
                                                              "source": source,
                                                              "metadata": json.dumps(metadata or {}),
                                        },
                      )
                      await session.commit()

        return ioc_id

    async def check_ioc(self, ioc_value: str) -> Optional[Dict]:
              """Check if a value is a known IOC."""
        if self._engine is None:
                      await self.initialize()

        from sqlalchemy.ext.asyncio import AsyncSession
        from sqlalchemy import text

        async with AsyncSession(self._engine) as session:
                      result = await session.execute(
                                        text("SELECT * FROM ioc_registry WHERE ioc_value = :val AND is_active = 1"),
                                        {"val": ioc_value},
                      )
                      row = result.fetchone()
                      if row:
                                        return dict(row._mapping)
                                return None

    async def create_incident(self, incident_data: Dict) -> str:
              """Create a new security incident record."""
        if self._engine is None:
                      await self.initialize()

        from sqlalchemy.ext.asyncio import AsyncSession
        from sqlalchemy import text

        incident_id = str(uuid.uuid4())
        async with AsyncSession(self._engine) as session:
                      await session.execute(
                          text("""
                                          INSERT INTO incidents
                                                          (id, title, severity, status, assigned_agent, description, affected_assets, mitre_techniques)
                                                                          VALUES (:id, :title, :severity, :status, :assigned_agent, :description, :affected_assets, :mitre_techniques)
                                                                                          """),
                          {
                                                "id": incident_id,
                                                "title": incident_data.get("title", "Unnamed Incident"),
                                                "severity": incident_data.get("severity", "medium"),
                                                "status": incident_data.get("status", "open"),
                                                "assigned_agent": incident_data.get("assigned_agent", ""),
                                                "description": incident_data.get("description", ""),
                                                "affected_assets": json.dumps(incident_data.get("affected_assets", [])),
                                                "mitre_techniques": json.dumps(incident_data.get("mitre_techniques", [])),
                          },
        )
            await session.commit()

        logger.info(f"Created incident: {incident_id}")
        return incident_id

    async def get_incident_timeline(self, session_id: str) -> List[Dict]:
              """Get full event timeline for an incident session."""
        if self._engine is None:
                      await self.initialize()

        from sqlalchemy.ext.asyncio import AsyncSession
        from sqlalchemy import text

        async with AsyncSession(self._engine) as session:
                      result = await session.execute(
                          text("""
                                          SELECT * FROM security_events
                                                          WHERE session_id = :sid
                                                                          ORDER BY created_at ASC
                                                                                          """),
                          {"sid": session_id},
        )
            return [dict(row._mapping) for row in result.fetchall()]

    async def get_metrics(self) -> Dict[str, Any]:
              """Get episodic memory metrics."""
        if self._engine is None:
                      await self.initialize()

        from sqlalchemy.ext.asyncio import AsyncSession
        from sqlalchemy import text

        async with AsyncSession(self._engine) as session:
                      events_count = (await session.execute(text("SELECT COUNT(*) FROM security_events"))).scalar()
            decisions_count = (await session.execute(text("SELECT COUNT(*) FROM agent_decisions"))).scalar()
            ioc_count = (await session.execute(text("SELECT COUNT(*) FROM ioc_registry WHERE is_active = 1"))).scalar()
            incident_count = (await session.execute(text("SELECT COUNT(*) FROM incidents WHERE status = 'open'"))).scalar()

        return {
                      "total_events": events_count or 0,
                      "total_decisions": decisions_count or 0,
                      "active_iocs": ioc_count or 0,
                      "open_incidents": incident_count or 0,
        }


# ---------------------------------------------------------------------------
# Unified Memory Manager
# ---------------------------------------------------------------------------

class MemoryManager:
      """
          Unified interface for all memory types.
              Orchestrates short-term, long-term, and episodic memory.
                  """

    def __init__(
              self,
              redis_url: str = "redis://localhost:6379",
              vector_backend: str = "chroma",
              db_url: str = "sqlite+aiosqlite:///./data/memory.db",
    ):
              self.short_term = ShortTermMemory(redis_url)
        self.long_term = LongTermMemory(backend=vector_backend)
        self.episodic = EpisodicMemory(db_url=db_url)
        self._working_memory: Dict[str, Any] = {}
        self._initialized = False

    async def initialize(self):
              """Initialize all memory backends."""
        if self._initialized:
                      return

        results = await asyncio.gather(
                      self.long_term.initialize(),
                      self.episodic.initialize(),
                      return_exceptions=True,
        )

        for r in results:
                      if isinstance(r, Exception):
                                        logger.warning(f"Memory backend initialization error: {r}")

        self._initialized = True
        logger.info("MemoryManager initialized")

    # Working Memory (in-process, current session)
    def set_working(self, key: str, value: Any):
              self._working_memory[key] = value

    def get_working(self, key: str, default: Any = None) -> Any:
              return self._working_memory.get(key, default)

    def clear_working(self):
              self._working_memory.clear()

    # Context Management
    async def save_security_context(self, context: SecurityContext) -> bool:
              """Save current security context across all memory tiers."""
        # Short-term: fast access
        await self.short_term.store(
                      f"context:{context.session_id}",
                      context.dict(mode="json"),
                      ttl=7200,
        )

        # Long-term: semantic search
        context_text = f"""
        Security Context Summary:
        Active Incidents: {len(context.active_incidents)}
        Compromised Assets: {', '.join(context.compromised_assets)}
        MITRE Techniques Observed: {', '.join(context.mitre_techniques_observed)}
        Risk Score: {context.risk_score}
        IOCs: {sum(len(v) for v in context.iocs.values())} indicators
                """.strip()

        entry = MemoryEntry(
                      content=context_text,
                      metadata={"session_id": context.session_id, "risk_score": context.risk_score},
                      memory_type=MemoryType.LONG_TERM,
                      tags=["security_context"] + context.mitre_techniques_observed,
                      session_id=context.session_id,
        )
        await self.long_term.store_memory(entry)

        return True

    async def load_security_context(self, session_id: str) -> Optional[SecurityContext]:
              """Load security context from short-term memory."""
        data = await self.short_term.retrieve(f"context:{session_id}")
        if data:
                      return SecurityContext(**data)
        return None

    async def enrich_with_memory(self, query: str, session_id: str = "") -> Dict[str, Any]:
              """
                      Enrich a query with relevant memories.
                              Returns a dict with relevant context from all memory tiers.
                                      """
        results = await asyncio.gather(
                      self.long_term.semantic_search(query, n_results=3),
                      self.short_term.retrieve(f"context:{session_id}") if session_id else asyncio.sleep(0),
                      return_exceptions=True,
        )

        similar_memories = results[0] if not isinstance(results[0], Exception) else []
        current_context = results[1] if not isinstance(results[1], Exception) else None

        return {
                      "similar_past_incidents": similar_memories,
                      "current_session_context": current_context,
                      "working_memory": dict(self._working_memory),
        }

    async def add_ioc(self, ioc_type: str, ioc_value: str, **kwargs) -> str:
              """Register an IOC across memory systems."""
        # Short-term cache
        await self.short_term.store(
                      f"ioc:{ioc_value}",
                      {"type": ioc_type, "value": ioc_value, **kwargs},
                      ttl=86400,
        )

        # Episodic for audit
        return await self.episodic.register_ioc(ioc_type, ioc_value, **kwargs)

    async def check_ioc(self, ioc_value: str) -> Optional[Dict]:
              """Check IOC across all memory tiers (fast path first)."""
        # Check short-term first (fast)
        cached = await self.short_term.retrieve(f"ioc:{ioc_value}")
        if cached:
                      return cached

        # Check episodic (authoritative)
        return await self.episodic.check_ioc(ioc_value)

    async def get_health_status(self) -> Dict[str, Any]:
              """Get health status of all memory backends."""
        redis_ok = await self.short_term.health_check()
        metrics = {}
        try:
                      metrics = await self.episodic.get_metrics()
except Exception:
            pass

        return {
                      "redis_connected": redis_ok,
                      "episodic_metrics": metrics,
                      "working_memory_size": len(self._working_memory),
                      "initialized": self._initialized,
        }


# ---------------------------------------------------------------------------
# Singleton Factory
# ---------------------------------------------------------------------------

_memory_manager: Optional[MemoryManager] = None


async def get_memory_manager(
      redis_url: str = "redis://localhost:6379",
      db_url: str = "sqlite+aiosqlite:///./data/memory.db",
) -> MemoryManager:
      """Get or create the global MemoryManager singleton."""
    global _memory_manager
    if _memory_manager is None:
              _memory_manager = MemoryManager(redis_url=redis_url, db_url=db_url)
        await _memory_manager.initialize()
    return _memory_manager
