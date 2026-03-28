"""
LLM client: Gemini (primary) → Ollama → Anthropic fallback chain.
Gemini uses response_mime_type=application/json for guaranteed valid JSON.
"""
from __future__ import annotations
import json
from typing import Any

import httpx
import structlog

from app.config import settings

log = structlog.get_logger()

GEMINI_MODEL = "gemini-flash-latest"
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
OLLAMA_MODEL = "llama3:latest"


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
}


class LLMClient:
    def __init__(self) -> None:
        self._total_tokens = 0
        self._total_calls = 0

    def _validate_schema(self, result: dict[str, Any], schema: dict[str, Any]) -> list[str]:
        """Return list of missing required fields. Empty list means valid."""
        required = schema.get("required", [])
        return [f for f in required if f not in result]

    def _build_example_prompt(self, schema: dict[str, Any]) -> str:
        """Build a concrete filled-in JSON example from the schema for use in the prompt.
        Shows the LLM what the OUTPUT should look like, not the schema definition."""
        type_defaults: dict[str, Any] = {"boolean": True, "number": 0.85, "string": "...", "array": [], "object": {}}
        props = schema.get("properties", {})
        example: dict[str, Any] = {}
        # Required fields first
        for field in schema.get("required", []):
            example[field] = _FIELD_EXAMPLES.get(field, type_defaults.get(props.get(field, {}).get("type", "string"), "..."))
        # Optional fields
        for field, prop in props.items():
            if field not in example:
                example[field] = _FIELD_EXAMPLES.get(field, type_defaults.get(prop.get("type", "string"), "..."))
        return json.dumps(example, indent=2)

    async def analyze(self, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        """Call LLM with JSON output. Provider chain: Gemini → Ollama → Anthropic.
        All providers receive a concrete example of the expected output (not the raw schema
        definition) to prevent models from echoing the schema back."""
        self._total_calls += 1
        required_fields = schema.get("required", [])
        example_json = self._build_example_prompt(schema)
        # Append a concrete example to the user prompt so the model knows exactly what
        # format to produce. This works for all providers including Gemini.
        full_user = (
            f"{user}\n\nRespond ONLY with valid JSON. Example format:\n{example_json}"
        )

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
                    return result
                if result is not None:
                    result = self._fill_defaults(result, schema)
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
                return self._fill_defaults(result, schema)

        if settings.anthropic_api_key:
            result = await self._call_anthropic(system, full_user)
            return self._fill_defaults(result, schema)

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
        We do NOT send response_schema — it causes Gemini to echo the schema definition
        rather than produce values. Instead, a concrete example is embedded in the user
        prompt (see _build_example_prompt).
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
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                content = data["candidates"][0]["content"]["parts"][0]["text"]
                usage = data.get("usageMetadata", {})
                self._total_tokens += usage.get("totalTokenCount", len(content) // 4)
                log.debug("llm.gemini_ok", tokens=usage.get("totalTokenCount", "?"))
                return json.loads(content)
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
            "options": {"temperature": 0.1, "num_predict": 512},
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
                model="claude-sonnet-4-20250514",
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
        content = content.strip()
        try:
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            return json.loads(content)
        except json.JSONDecodeError as e:
            log.error("llm.json_parse_error", error=str(e), raw=content[:200])
            return {"error": "JSON parse failed", "raw": content[:500]}

    def get_usage(self) -> dict[str, int]:
        return {"total_tokens": self._total_tokens, "total_calls": self._total_calls}
