"""
BREACH.AI - Qdrant Vector Store
================================

Vector storage for semantic learning and attack pattern retrieval.
Uses Qdrant for fast similarity search.

Features:
- Store and retrieve attack patterns by similarity
- Semantic search for vulnerabilities
- Cross-target learning via embeddings
- Efficient nearest-neighbor retrieval
"""

import hashlib
import json
from typing import Optional, List, Dict, Any
from uuid import UUID, uuid4
from datetime import datetime

import structlog
from qdrant_client import QdrantClient
from qdrant_client.http import models as qdrant_models
from qdrant_client.http.exceptions import UnexpectedResponse

from backend.config import settings

logger = structlog.get_logger(__name__)

# Collection names
ATTACKS_COLLECTION = "breach_attacks"
VULNERABILITIES_COLLECTION = "breach_vulnerabilities"
PATTERNS_COLLECTION = "breach_patterns"

# Embedding dimensions (using OpenAI text-embedding-3-small or similar)
EMBEDDING_DIM = 1536


class VectorStore:
    """
    Qdrant-backed vector store for semantic search.

    Stores embeddings for:
    - Attack patterns (successful attacks with context)
    - Vulnerability descriptions (for similarity matching)
    - Technology patterns (for tech stack identification)
    """

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.url = url or settings.qdrant_url
        self.api_key = api_key or settings.qdrant_api_key
        self._client: Optional[QdrantClient] = None
        self._initialized = False

    @property
    def client(self) -> QdrantClient:
        """Lazy-load Qdrant client."""
        if self._client is None:
            self._client = QdrantClient(
                url=self.url,
                api_key=self.api_key,
                timeout=30,
            )
        return self._client

    async def initialize(self):
        """Initialize collections if they don't exist."""
        if self._initialized:
            return

        try:
            # Create attacks collection
            await self._create_collection_if_not_exists(
                name=ATTACKS_COLLECTION,
                description="Successful attack patterns with embeddings",
            )

            # Create vulnerabilities collection
            await self._create_collection_if_not_exists(
                name=VULNERABILITIES_COLLECTION,
                description="Vulnerability descriptions for similarity search",
            )

            # Create patterns collection
            await self._create_collection_if_not_exists(
                name=PATTERNS_COLLECTION,
                description="General security patterns and techniques",
            )

            self._initialized = True
            logger.info("vector_store_initialized", url=self.url)

        except Exception as e:
            logger.warning(
                "vector_store_init_failed",
                error=str(e),
                url=self.url,
            )
            # Don't fail hard - allow operation without vector store
            self._initialized = True

    async def _create_collection_if_not_exists(
        self,
        name: str,
        description: str,
    ):
        """Create a collection if it doesn't exist."""
        try:
            collections = self.client.get_collections().collections
            if not any(c.name == name for c in collections):
                self.client.create_collection(
                    collection_name=name,
                    vectors_config=qdrant_models.VectorParams(
                        size=EMBEDDING_DIM,
                        distance=qdrant_models.Distance.COSINE,
                    ),
                )
                logger.info("collection_created", name=name)
        except UnexpectedResponse as e:
            if "already exists" not in str(e):
                raise

    # ============== Attack Patterns ==============

    async def store_attack_pattern(
        self,
        attack_type: str,
        description: str,
        embedding: List[float],
        target_id: Optional[UUID] = None,
        payload: Optional[str] = None,
        success: bool = True,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Store a successful attack pattern for future retrieval.

        Args:
            attack_type: Category (sqli, xss, idor, etc.)
            description: Human-readable description
            embedding: Vector embedding of the attack
            target_id: Optional target association
            payload: The actual payload used
            success: Whether this attack succeeded
            context: Additional context (headers, parameters, etc.)

        Returns:
            ID of the stored pattern
        """
        await self.initialize()

        point_id = str(uuid4())

        try:
            self.client.upsert(
                collection_name=ATTACKS_COLLECTION,
                points=[
                    qdrant_models.PointStruct(
                        id=point_id,
                        vector=embedding,
                        payload={
                            "attack_type": attack_type,
                            "description": description,
                            "target_id": str(target_id) if target_id else None,
                            "payload": payload,
                            "success": success,
                            "context": context or {},
                            "created_at": datetime.utcnow().isoformat(),
                        }
                    )
                ],
            )

            logger.debug(
                "attack_pattern_stored",
                id=point_id,
                attack_type=attack_type,
                success=success,
            )

            return point_id

        except Exception as e:
            logger.error("attack_pattern_store_failed", error=str(e))
            return ""

    async def find_similar_attacks(
        self,
        embedding: List[float],
        attack_type: Optional[str] = None,
        target_id: Optional[UUID] = None,
        limit: int = 10,
        min_score: float = 0.7,
    ) -> List[Dict[str, Any]]:
        """
        Find similar attack patterns by embedding similarity.

        Args:
            embedding: Query embedding
            attack_type: Filter by attack type
            target_id: Filter by target
            limit: Max results to return
            min_score: Minimum similarity score (0-1)

        Returns:
            List of similar attack patterns with scores
        """
        await self.initialize()

        try:
            # Build filter
            filter_conditions = []

            if attack_type:
                filter_conditions.append(
                    qdrant_models.FieldCondition(
                        key="attack_type",
                        match=qdrant_models.MatchValue(value=attack_type),
                    )
                )

            if target_id:
                filter_conditions.append(
                    qdrant_models.FieldCondition(
                        key="target_id",
                        match=qdrant_models.MatchValue(value=str(target_id)),
                    )
                )

            query_filter = None
            if filter_conditions:
                query_filter = qdrant_models.Filter(
                    must=filter_conditions,
                )

            results = self.client.search(
                collection_name=ATTACKS_COLLECTION,
                query_vector=embedding,
                query_filter=query_filter,
                limit=limit,
                score_threshold=min_score,
            )

            return [
                {
                    "id": hit.id,
                    "score": hit.score,
                    **hit.payload,
                }
                for hit in results
            ]

        except Exception as e:
            logger.error("similar_attacks_search_failed", error=str(e))
            return []

    # ============== Vulnerability Patterns ==============

    async def store_vulnerability(
        self,
        title: str,
        description: str,
        embedding: List[float],
        severity: str,
        category: str,
        endpoint: Optional[str] = None,
        cwe_id: Optional[str] = None,
        fix_suggestion: Optional[str] = None,
        finding_id: Optional[UUID] = None,
        target_id: Optional[UUID] = None,
    ) -> str:
        """
        Store a vulnerability for similarity search.

        This enables finding similar vulnerabilities across targets.
        """
        await self.initialize()

        point_id = str(uuid4())

        try:
            self.client.upsert(
                collection_name=VULNERABILITIES_COLLECTION,
                points=[
                    qdrant_models.PointStruct(
                        id=point_id,
                        vector=embedding,
                        payload={
                            "title": title,
                            "description": description,
                            "severity": severity,
                            "category": category,
                            "endpoint": endpoint,
                            "cwe_id": cwe_id,
                            "fix_suggestion": fix_suggestion,
                            "finding_id": str(finding_id) if finding_id else None,
                            "target_id": str(target_id) if target_id else None,
                            "created_at": datetime.utcnow().isoformat(),
                        }
                    )
                ],
            )

            return point_id

        except Exception as e:
            logger.error("vulnerability_store_failed", error=str(e))
            return ""

    async def find_similar_vulnerabilities(
        self,
        embedding: List[float],
        severity: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 10,
        min_score: float = 0.7,
    ) -> List[Dict[str, Any]]:
        """
        Find similar vulnerabilities by embedding similarity.

        Useful for:
        - Finding known fixes for similar issues
        - Identifying patterns across targets
        - Suggesting remediation based on past findings
        """
        await self.initialize()

        try:
            filter_conditions = []

            if severity:
                filter_conditions.append(
                    qdrant_models.FieldCondition(
                        key="severity",
                        match=qdrant_models.MatchValue(value=severity),
                    )
                )

            if category:
                filter_conditions.append(
                    qdrant_models.FieldCondition(
                        key="category",
                        match=qdrant_models.MatchValue(value=category),
                    )
                )

            query_filter = None
            if filter_conditions:
                query_filter = qdrant_models.Filter(
                    must=filter_conditions,
                )

            results = self.client.search(
                collection_name=VULNERABILITIES_COLLECTION,
                query_vector=embedding,
                query_filter=query_filter,
                limit=limit,
                score_threshold=min_score,
            )

            return [
                {
                    "id": hit.id,
                    "score": hit.score,
                    **hit.payload,
                }
                for hit in results
            ]

        except Exception as e:
            logger.error("similar_vulns_search_failed", error=str(e))
            return []

    # ============== General Patterns ==============

    async def store_pattern(
        self,
        pattern_type: str,
        name: str,
        description: str,
        embedding: List[float],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Store a general security pattern.

        Pattern types:
        - technology: Tech stack patterns
        - endpoint: Common endpoint patterns
        - parameter: Common parameter patterns
        - technique: Attack techniques
        """
        await self.initialize()

        point_id = str(uuid4())

        try:
            self.client.upsert(
                collection_name=PATTERNS_COLLECTION,
                points=[
                    qdrant_models.PointStruct(
                        id=point_id,
                        vector=embedding,
                        payload={
                            "pattern_type": pattern_type,
                            "name": name,
                            "description": description,
                            "metadata": metadata or {},
                            "created_at": datetime.utcnow().isoformat(),
                        }
                    )
                ],
            )

            return point_id

        except Exception as e:
            logger.error("pattern_store_failed", error=str(e))
            return ""

    async def find_similar_patterns(
        self,
        embedding: List[float],
        pattern_type: Optional[str] = None,
        limit: int = 10,
        min_score: float = 0.7,
    ) -> List[Dict[str, Any]]:
        """Find similar patterns by embedding similarity."""
        await self.initialize()

        try:
            query_filter = None
            if pattern_type:
                query_filter = qdrant_models.Filter(
                    must=[
                        qdrant_models.FieldCondition(
                            key="pattern_type",
                            match=qdrant_models.MatchValue(value=pattern_type),
                        )
                    ],
                )

            results = self.client.search(
                collection_name=PATTERNS_COLLECTION,
                query_vector=embedding,
                query_filter=query_filter,
                limit=limit,
                score_threshold=min_score,
            )

            return [
                {
                    "id": hit.id,
                    "score": hit.score,
                    **hit.payload,
                }
                for hit in results
            ]

        except Exception as e:
            logger.error("similar_patterns_search_failed", error=str(e))
            return []

    # ============== Statistics ==============

    async def get_stats(self) -> Dict[str, Any]:
        """Get vector store statistics."""
        await self.initialize()

        try:
            stats = {}

            for collection_name in [
                ATTACKS_COLLECTION,
                VULNERABILITIES_COLLECTION,
                PATTERNS_COLLECTION,
            ]:
                try:
                    info = self.client.get_collection(collection_name)
                    stats[collection_name] = {
                        "vectors_count": info.vectors_count,
                        "points_count": info.points_count,
                        "status": info.status.value,
                    }
                except Exception:
                    stats[collection_name] = {"status": "not_found"}

            return {
                "connected": True,
                "url": self.url,
                "collections": stats,
            }

        except Exception as e:
            return {
                "connected": False,
                "error": str(e),
            }

    async def clear_collection(self, collection_name: str):
        """Clear all points from a collection."""
        try:
            self.client.delete_collection(collection_name)
            await self._create_collection_if_not_exists(
                collection_name,
                f"Recreated {collection_name}",
            )
            logger.info("collection_cleared", name=collection_name)
        except Exception as e:
            logger.error("collection_clear_failed", name=collection_name, error=str(e))


# ============== Embedding Generation ==============

class EmbeddingGenerator:
    """
    Generate embeddings for text using OpenAI or local models.

    Falls back to simple hash-based pseudo-embeddings if no API key.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.openai_api_key
        self._openai_client = None

    @property
    def openai_client(self):
        """Lazy-load OpenAI client."""
        if self._openai_client is None and self.api_key:
            try:
                from openai import OpenAI
                self._openai_client = OpenAI(api_key=self.api_key)
            except ImportError:
                pass
        return self._openai_client

    async def generate(self, text: str) -> List[float]:
        """
        Generate an embedding for the given text.

        Uses OpenAI if available, otherwise falls back to hash-based.
        """
        if self.openai_client:
            return await self._generate_openai(text)
        return self._generate_hash_based(text)

    async def _generate_openai(self, text: str) -> List[float]:
        """Generate embedding using OpenAI API."""
        try:
            response = self.openai_client.embeddings.create(
                model="text-embedding-3-small",
                input=text,
            )
            return response.data[0].embedding
        except Exception as e:
            logger.warning("openai_embedding_failed", error=str(e))
            return self._generate_hash_based(text)

    def _generate_hash_based(self, text: str) -> List[float]:
        """
        Generate a deterministic pseudo-embedding from text hash.

        This is NOT a real embedding but allows the system to work
        without an embedding API. Similar texts will NOT have similar
        embeddings with this method.
        """
        # Use SHA256 to get a deterministic hash
        hash_bytes = hashlib.sha256(text.encode()).digest()

        # Expand to EMBEDDING_DIM dimensions
        embedding = []
        for i in range(EMBEDDING_DIM):
            # Use different parts of the hash and cycle
            idx = i % len(hash_bytes)
            value = (hash_bytes[idx] + i) / 255.0 - 0.5  # Normalize to [-0.5, 0.5]
            embedding.append(value)

        return embedding


# ============== Global Instance ==============

_vector_store: Optional[VectorStore] = None
_embedding_generator: Optional[EmbeddingGenerator] = None


def get_vector_store() -> VectorStore:
    """Get the global vector store instance."""
    global _vector_store
    if _vector_store is None:
        _vector_store = VectorStore()
    return _vector_store


def get_embedding_generator() -> EmbeddingGenerator:
    """Get the global embedding generator instance."""
    global _embedding_generator
    if _embedding_generator is None:
        _embedding_generator = EmbeddingGenerator()
    return _embedding_generator


# ============== Convenience Functions ==============

async def store_attack_learning(
    attack_type: str,
    description: str,
    payload: Optional[str] = None,
    success: bool = True,
    target_id: Optional[UUID] = None,
    context: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Store an attack pattern with auto-generated embedding.

    Convenience function for the common use case.
    """
    store = get_vector_store()
    generator = get_embedding_generator()

    # Create text for embedding
    text = f"{attack_type}: {description}"
    if payload:
        text += f" Payload: {payload[:200]}"  # Truncate long payloads

    embedding = await generator.generate(text)

    return await store.store_attack_pattern(
        attack_type=attack_type,
        description=description,
        embedding=embedding,
        target_id=target_id,
        payload=payload,
        success=success,
        context=context,
    )


async def store_vulnerability_learning(
    title: str,
    description: str,
    severity: str,
    category: str,
    endpoint: Optional[str] = None,
    fix_suggestion: Optional[str] = None,
    finding_id: Optional[UUID] = None,
    target_id: Optional[UUID] = None,
) -> str:
    """
    Store a vulnerability with auto-generated embedding.
    """
    store = get_vector_store()
    generator = get_embedding_generator()

    text = f"{severity} {category}: {title}. {description}"
    if fix_suggestion:
        text += f" Fix: {fix_suggestion[:200]}"

    embedding = await generator.generate(text)

    return await store.store_vulnerability(
        title=title,
        description=description,
        embedding=embedding,
        severity=severity,
        category=category,
        endpoint=endpoint,
        fix_suggestion=fix_suggestion,
        finding_id=finding_id,
        target_id=target_id,
    )


async def find_similar_attack_patterns(
    description: str,
    attack_type: Optional[str] = None,
    target_id: Optional[UUID] = None,
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """
    Find similar attack patterns by description.
    """
    store = get_vector_store()
    generator = get_embedding_generator()

    embedding = await generator.generate(description)

    return await store.find_similar_attacks(
        embedding=embedding,
        attack_type=attack_type,
        target_id=target_id,
        limit=limit,
    )


async def find_similar_vulnerability_patterns(
    description: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """
    Find similar vulnerabilities by description.
    """
    store = get_vector_store()
    generator = get_embedding_generator()

    embedding = await generator.generate(description)

    return await store.find_similar_vulnerabilities(
        embedding=embedding,
        severity=severity,
        category=category,
        limit=limit,
    )
