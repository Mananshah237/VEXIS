"""
LLM client: Gemini (primary) → Ollama → Anthropic fallback chain.
Gemini uses response_mime_type=application/json for guaranteed valid JSON.

Optimizations:
- Redis prompt-hash cache (1h TTL) — avoids re-calling LLM for identical prompts
- 30-second Gemini timeout (down from 60) — fail fast, don't block the pipeline
"""
from __future__ import annotations
import hashlib
import json
from typing import Any

import httpx
import structlog

from app.config import settings

log = structlog.get_logger()

GEMINI_MODEL = "gemini-flash-latest"
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
OLLAMA_MODEL = "llama3:latest"

# Gemini HTTP timeout — fail fast rather than blocking the whole pipeline
GEMINI_TIMEOUT = 30.0


# Concrete example values for known schema field names.
# Used to show the LLM a filled-in example rather than the raw schema definition.
_FIELD_EXAMPLES: dict[str, Any] = {
    "sanitizer_effective": False,
    "bypass_possible": True,
    "bypass_technique": "use ' OR 1=1-- to bypass quote escaping",
    "confidence": 0.85,
    "reasoning": "The tainted value flows directly to the sink without effective sanitization, allowing injection.",
    "exploitable": True,
    "attack_vector": "GET /search?q=' OR '1'='1 HTTP/1.1",
    "payload": "' OR '1'='1",
    "preconditions": ["endpoint reachable", "no additional auth layer"],
    "expected_outcome": "Full database read or authentication bypass",
    "why_not_exploitable": "None identified — no sanitization present",
    "vulnerable": True,
    "vulnerability_type": "sqli",
    "explanation": "Tainted input reaches a dangerous sink without sanitization.",
    "chain_possible": False,
    "chain_description": "",
    "chain_steps": [],
    "component_ids": [],
    "severity_upgrade": "critical",
    # Pass 3 batched response
    "chains": [],
    "component_indices": [0, 1],
    "combined_severity": "high",
    "analysis_summary": "No chains found.",
}


class LLMClient:
    def __init__(self) -> None:
        self._total_tokens = 0
        self._total_calls = 0
        self._cache_hits = 0

    def _prompt_cache_key(self, system: str, user: str) -> str:
        return hashlib.sha256(f"{system}\n\n{user}".encode()).hexdigest()

    async def _get_cached(self, cache_key: str) -> dict[str, Any] | None:
        try:
            import redis.asyncio as aioredis
            r = aioredis.from_url(settings.redis_url, decode_responses=True)
            raw = await r.get(f"llm_cache:{cache_key}")
            await r.aclose()
            if raw:
                return json.loads(raw)
        except Exception:
            pass
        return None

    async def _set_cached(self, cache_key: str, result: dict[str, Any]) -> None:
        try:
            import redis.asyncio as aioredis
            r = aioredis.from_url(settings.redis_url, decode_responses=True)
            await r.setex(f"llm_cache:{cache_key}", 3600, json.dumps(result))
            await r.aclose()
        except Exception:
            pass

    def _validate_schema(self, result: dict[str, Any], schema: dict[str, Any]) -> list[str]:
        """Return list of missing required fields. Empty list means valid."""
        required = schema.get("required", [])
        return [f for f in required if f not in result]

    def _build_example_prompt(self, schema: dict[str, Any]) -> str:
        """Build a concrete filled-in JSON example from the schema for use in the prompt."""
        type_defaults: dict[str, Any] = {"boolean": True, "number": 0.85, "string": "...", "array": [], "object": {}}
        props = schema.get("properties", {})
        example: dict[str, Any] = {}
        for field in schema.get("required", []):
            example[field] = _FIELD_EXAMPLES.get(field, type_defaults.get(props.get(field, {}).get("type", "string"), "..."))
        for field, prop in props.items():
            if field not in example:
                example[field] = _FIELD_EXAMPLES.get(field, type_defaults.get(prop.get("type", "string"), "..."))
        return json.dumps(example, indent=2)

    async def analyze(self, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        """Call LLM with JSON output. Provider chain: Gemini → Ollama → Anthropic.
        Checks Redis cache first — returns immediately on hit."""
        self._total_calls += 1
        required_fields = schema.get("required", [])
        example_json = self._build_example_prompt(schema)
        full_user = (
            f"{user}\n\nRespond ONLY with valid JSON. Example format:\n{example_json}"
        )

        # Cache lookup — skip LLM entirely if we've seen this exact prompt before
        cache_key = self._prompt_cache_key(system, full_user)
        cached = await self._get_cached(cache_key)
        if cached is not None:
            self._cache_hits += 1
            log.debug("llm.cache_hit", cache_key=cache_key[:16])
            return cached

        result = None

        if settings.google_api_key:
            result = await self._call_gemini(system, full_user)
            if result is not None:
                missing = self._validate_schema(result, schema)
                if missing:
                    log.warning("llm.missing_fields_retry", missing=missing)
                    retry_user = (
                        f"{full_user}\n\nIMPORTANT: Your previous response was missing required fields: "
                        f"{missing}. You MUST include ALL of: {required_fields}."
                    )
                    result = await self._call_gemini(system, retry_user)
                if result is not None and not self._validate_schema(result, schema):
                    await self._set_cached(cache_key, result)
                    return result
                if result is not None:
                    result = self._fill_defaults(result, schema)
                    await self._set_cached(cache_key, result)
                    return result

        if settings.ollama_base_url:
            result = await self._call_ollama(system, full_user)
            if result is not None:
                missing = self._validate_schema(result, schema)
                if missing:
                    retry_user = (
                        f"{full_user}\n\nYour response was missing: {missing}. Include ALL required fields."
                    )
                    result = await self._call_ollama(system, retry_user) or result
                result = self._fill_defaults(result, schema)
                await self._set_cached(cache_key, result)
                return result

        if settings.anthropic_api_key:
            result = await self._call_anthropic(system, full_user)
            result = self._fill_defaults(result, schema)
            await self._set_cached(cache_key, result)
            return result

        log.error("llm.no_provider")
        return {"error": "No LLM provider available"}

    def _fill_defaults(self, result: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
        """Fill any missing required fields with type-appropriate defaults."""
        type_defaults: dict[str, Any] = {"boolean": False, "number": 0.5, "string": "", "array": []}
        props = schema.get("properties", {})
        for field in schema.get("required", []):
            if field not in result:
                field_type = props.get(field, {}).get("type", "string")
                result[field] = type_defaults.get(field_type, "")
                log.warning("llm.filled_default", field=field, default=result[field])
        return result

    async def _call_gemini(self, system: str, user: str) -> dict[str, Any] | None:
        """
        Call Gemini with response_mime_type=application/json.
        30-second timeout — fail fast rather than blocking the pipeline.
        """
        url = f"{GEMINI_BASE}/{GEMINI_MODEL}:generateContent?key={settings.google_api_key}"
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generation_config": {
                "temperature": 0.1,
                "max_output_tokens": 2048,
                "response_mime_type": "application/json",
            },
        }
        try:
            async with httpx.AsyncClient(timeout=GEMINI_TIMEOUT) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                content = data["candidates"][0]["content"]["parts"][0]["text"]
                usage = data.get("usageMetadata", {})
                self._total_tokens += usage.get("totalTokenCount", len(content) // 4)
                log.debug("llm.gemini_ok", tokens=usage.get("totalTokenCount", "?"))
                return json.loads(content)
        except httpx.TimeoutException:
            log.warning("llm.gemini_timeout", timeout=GEMINI_TIMEOUT)
            return None
        except httpx.HTTPStatusError as e:
            log.error("llm.gemini_http_error", status=e.response.status_code, body=e.response.text[:300])
            return None
        except (KeyError, json.JSONDecodeError) as e:
            log.error("llm.gemini_parse_error", error=str(e))
            return None
        except Exception as e:
            log.error("llm.gemini_error", error_type=type(e).__name__, error=str(e))
            return None

    async def _call_ollama(self, system: str, user: str) -> dict[str, Any] | None:
        """Call Ollama /api/chat (llama3 local). Hard timeout 90s, capped output."""
        payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 2048},
        }
        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                resp = await client.post(
                    f"{settings.ollama_base_url.rstrip('/')}/api/chat", json=payload
                )
                resp.raise_for_status()
                content = resp.json()["message"]["content"]
                self._total_tokens += len(content) // 4
                return self._parse_json(content)
        except httpx.ConnectError:
            log.warning("llm.ollama_unreachable")
            return None
        except Exception as e:
            log.error("llm.ollama_error", error_type=type(e).__name__, error=str(e)[:100])
            return None

    async def _call_anthropic(self, system: str, user: str) -> dict[str, Any]:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
            response = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=2048,
                temperature=0.1,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            content = response.content[0].text
            self._total_tokens += response.usage.input_tokens + response.usage.output_tokens
            return self._parse_json(content)
        except Exception as e:
            log.error("llm.anthropic_error", error=str(e))
            return {"error": str(e)}

    def _parse_json(self, content: str) -> dict[str, Any]:
        import re
        content = content.strip()
        try:
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            return json.loads(content)
        except json.JSONDecodeError as e:
            # Recover from LLMs that embed Python triple-quoted strings inside JSON.
            # Pattern: {"script": """...""", "description": "..."}
            m = re.search(r'"script"\s*:\s*"""(.*?)"""', content, re.DOTALL)
            if m:
                script_text = m.group(1)
                desc_m = re.search(r'"description"\s*:\s*"([^"]*)"', content)
                return {
                    "script": script_text,
                    "description": desc_m.group(1) if desc_m else "",
                }
            log.error("llm.json_parse_error", error=str(e), raw=content[:200])
            return {"error": "JSON parse failed", "raw": content[:500]}

    def get_usage(self) -> dict[str, int]:
        return {
            "total_tokens": self._total_tokens,
            "total_calls": self._total_calls,
            "cache_hits": self._cache_hits,
        }
