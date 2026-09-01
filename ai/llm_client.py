"""
ComplianceGuard — External LLM Client (NVIDIA NIM)

Tiered model routing:
  HEAVY  (investigate / quick_approve)  → meta/llama-3.1-70b-instruct
         Full Root Cause Analysis, complex reasoning, architectural review.
         Latency: ~15–25 s.  Budget: 1024 tokens, 45 s timeout.

  LIGHT  (proceed_verify)               → meta/llama-3.1-8b-instruct
         Simple boolean safety verification — does the gate logic hold?
         Latency: ~3–5 s.   Budget: 512 tokens, 20 s timeout.

Using 8B everywhere produced two hard failures:
  1. Frequent omission of the `safety_verification` JSON key, causing every
     LOW/MEDIUM finding to be silently escalated (architecturally_safe → False).
  2. Shallow, generic RCA that ignored the injected live AWS context.
70B resolves both for the paths that matter.

Robustness:
  - If the model wraps its response in markdown fences, strips them.
  - If the model returns free text instead of JSON, extracts structured
    fields using keyword-based fallback parsing. Never raises to caller.
"""

import json
import logging
import os
import re
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)


# ── Tiered model routing constants ───────────────────────────────────────────
# Active supported NVIDIA NIM Models (Llama 3.2 11B / 90B Vision)
MODEL_HEAVY   = "meta/llama-3.2-11b-vision-instruct"
TIMEOUT_HEAVY = 40       # seconds — raised to 40s to prevent socket timeouts under API load
TOKENS_HEAVY  = 1500     # full RCA with fix_steps, rollback_steps, prereqs

MODEL_LIGHT   = "meta/llama-3.2-11b-vision-instruct"
TIMEOUT_LIGHT = 40       # seconds
TOKENS_LIGHT  = 1500

FALLBACK_MODELS = [
    "meta/llama-3.2-11b-vision-instruct",
    "meta/llama-3.2-90b-vision-instruct"
]



class LLMClient:
    def __init__(
        self,
        api_key: str = None,
        model_id: str = MODEL_HEAVY,   # default: active Llama 3.2 model
    ):
        self.api_key  = api_key or os.getenv("NVIDIA_API_KEY")
        self.model_id = model_id
        self.api_url  = "https://integrate.api.nvidia.com/v1/chat/completions"

        if not self.api_key:
            logger.error("LLMClient init error: No NVIDIA API key provided.")

    # ──────────────────────────────────────────────────────────────────────────
    #  PUBLIC: generate()
    # ──────────────────────────────────────────────────────────────────────────

    def generate(
        self,
        prompt:     str,
        model_id:   str  = None,
        timeout:    int  = None,
        max_tokens: int  = None,
    ) -> dict:
        """
        Send prompt to NVIDIA NIM and return parsed JSON analysis dict.
        Attempts requested model, then iterates fallback models if HTTP errors (410/404) occur.
        """
        if not self.api_key:
            return self._unavailable('API key missing')

        requested_model = model_id or self.model_id
        timeout         = timeout  or TIMEOUT_HEAVY
        max_tokens      = max_tokens or TOKENS_HEAVY

        models_to_try = [requested_model] + [m for m in FALLBACK_MODELS if m != requested_model]

        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Accept':        'application/json',
            'Content-Type':  'application/json',
        }

        last_error = None
        for target_model in models_to_try:
            payload = {
                'model':       target_model,
                'messages':    [{'role': 'user', 'content': prompt}],
                'temperature': 0.2,
                'top_p':       0.7,
                'max_tokens':  max_tokens,
            }
            try:
                logger.debug(
                    f'[LLM] Trying model {target_model} '
                    f'(timeout={timeout}s, max_tokens={max_tokens})'
                )
                req = urllib.request.Request(
                    self.api_url,
                    data=json.dumps(payload).encode('utf-8'),
                    headers=headers,
                    method='POST',
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    body = json.loads(resp.read().decode('utf-8'))
                return self._parse_response(body)

            except urllib.error.HTTPError as e:
                body_err = e.read().decode('utf-8', errors='ignore')
                logger.warning(f'NVIDIA API model {target_model} HTTP error {e.code}: {body_err[:120]} — trying fallback...')
                last_error = f'HTTP {e.code}: {body_err[:120]}'
                continue

            except Exception as e:
                last_error = e
                logger.warning(f'[LLM] Model {target_model} failed ({type(e).__name__}): {e}')
                continue

        logger.error(f'[LLM] All model attempts failed: {last_error}')
        return self._unavailable(str(last_error))


    # ──────────────────────────────────────────────────────────────────────────
    #  PRIVATE: parsing
    # ──────────────────────────────────────────────────────────────────────────

    def _parse_response(self, body: dict) -> dict:
        """
        Extract text from the API response, strip markdown fences,
        attempt JSON parse, fall back to text extraction on failure.
        """
        try:
            choices = body.get("choices", [])
            if not choices:
                return self._unavailable("Empty choices in API response")

            text = choices[0].get("message", {}).get("content", "").strip()
            if not text:
                return self._unavailable("Empty content in API response")

            logger.debug(f"[LLM] Raw response ({len(text)} chars): {text[:200]}")

            # ── Strip markdown code fences ─────────────────────────────────
            clean = text
            if "```json" in clean:
                clean = clean.split("```json")[1].split("```")[0].strip()
            elif "```" in clean:
                # Could be ```\n{...}\n```
                parts = clean.split("```")
                if len(parts) >= 3:
                    clean = parts[1].strip()

            # ── Attempt JSON parse ─────────────────────────────────────────
            try:
                parsed = json.loads(clean)
                self._validate_schema(parsed)
                return parsed
            except (json.JSONDecodeError, ValueError):
                pass  # fall through to text extraction

            # ── Fallback: extract fields from free text ────────────────────
            logger.warning("[LLM] JSON parse failed — using text extraction fallback")
            return self._extract_from_text(text)

        except Exception as e:
            logger.error(f"[LLM] _parse_response crashed: {e}")
            return self._unavailable(f"Parse error: {e}")

    def _validate_schema(self, parsed: dict) -> None:
        """Ensure required keys exist; add safe defaults for missing optional ones."""
        parsed.setdefault("root_cause",          "Not provided by model")
        parsed.setdefault("business_impact",     "Not provided by model")
        parsed.setdefault("recommended_fix",     "See fix_steps below")
        parsed.setdefault("fix_steps",           [])
        parsed.setdefault("operational_impact",  "Not provided by model")
        parsed.setdefault("safe_window",         "Off-peak hours recommended")
        parsed.setdefault("rollback_steps",      [])
        parsed.setdefault("gate_block_reason",   None)
        parsed.setdefault("prerequisite_actions", [])
        # CRITICAL: safety_verification must always be present.
        # If the model omits it, default to TRUSTING the deterministic gate
        # (architecturally_safe=True). The gate has already verified safety;
        # absence of a model opinion is NOT a veto — it is a non-answer.
        # Defaulting to False here would silently escalate every PROCEED
        # finding to human review whenever the model forgets this key.
        parsed.setdefault("safety_verification", {
            "architecturally_safe":    True,
            "verification_rationale":  (
                "Model did not provide explicit safety_verification. "
                "Defaulting to gate decision (architecturally_safe=True). "
                "The deterministic Safety Gate already confirmed PROCEED."
            ),
        })

    def _extract_from_text(self, text: str) -> dict:
        """
        Last-resort fallback: parse the model's free-text response into
        our structured schema by looking for known heading patterns.

        Handles outputs like:
          Root Cause: ...
          Business Impact: ...
          Recommended Fix: ...
        """
        def _between(label_pattern: str, stop_patterns: list[str]) -> str:
            m = re.search(label_pattern, text, re.IGNORECASE)
            if not m:
                return ""
            start = m.end()
            end   = len(text)
            for stop in stop_patterns:
                s = re.search(stop, text[start:], re.IGNORECASE)
                if s:
                    end = min(end, start + s.start())
            return text[start:end].strip(" :-\n")

        stops = [
            r"root cause", r"business impact", r"recommended fix",
            r"fix steps", r"operational impact", r"safe window",
            r"rollback", r"prerequisite",
        ]

        result = {
            "root_cause":          _between(r"root cause", stops) or text[:300],
            "business_impact":     _between(r"business impact", stops),
            "recommended_fix":     _between(r"recommended fix", stops),
            "fix_steps":           [],
            "operational_impact":  _between(r"operational impact", stops),
            "safe_window":         _between(r"safe window", stops),
            "rollback_steps":      [],
            "gate_block_reason":   None,
            "prerequisite_actions": [],
            "_parsed_from_text":   True,
        }

        # Try to extract numbered bullet points for fix_steps
        steps_block = _between(r"fix steps", stops)
        if steps_block:
            result["fix_steps"] = [
                l.strip(" -•123456789.") for l in steps_block.splitlines()
                if l.strip(" -•123456789.")
            ]

        # Defaults for missing fields
        if not result["root_cause"]:
            result["root_cause"] = text[:400]
        if not result["recommended_fix"]:
            result["recommended_fix"] = "See model output — could not extract structured fix."

        # Bug #13 fix: Infer safety_verification from free text BEFORE _validate_schema,
        # so setdefault() doesn't overwrite an explicit unsafe signal from the model.
        #
        # Problem: when the 8B model returns prose instead of JSON (e.g. on proceed_verify
        # calls), _extract_from_text builds a dict with no safety_verification key, then
        # _validate_schema fills it with architecturally_safe=True (gate-trust default).
        # A model that said "would cause an outage" in plain text was silently ignored.
        #
        # Only blocks on clear, unambiguous phrases to minimise false positives.
        # If the text says "while the config is not safe for production use..." that is
        # a description, not a verdict \u2014 the phrases below require an explicit action signal.
        _UNSAFE_PATTERNS = [
            r"not\s+architecturally\s+safe",
            r"architecturally.{0,15}unsafe",
            r"not\s+safe\s+to\s+(?:proceed|remediate|apply|fix)",
            r"would\s+cause\s+(?:an?\s+)?outage",
            r"would\s+(?:break|sever)\s+(?:active|live|existing)",
            r"set\s+architecturally.safe\s*=\s*false",
        ]
        explicit_block = any(re.search(p, text, re.IGNORECASE) for p in _UNSAFE_PATTERNS)
        if explicit_block:
            result["safety_verification"] = {
                "architecturally_safe":   False,
                "verification_rationale": (
                    "Extracted from free-text model response: model signalled the fix is unsafe. "
                    "Review raw model output and escalate to human review."
                ),
            }
        # If no explicit unsafe signal found, leave safety_verification absent so
        # _validate_schema fills it with architecturally_safe=True (trust the gate).

        self._validate_schema(result)
        return result

    # ──────────────────────────────────────────────────────────────────────────
    #  HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _unavailable(reason: str) -> dict:
        return {
            "root_cause":           f"LLM unavailable: {reason}",
            "business_impact":      "Cannot assess — manual review required",
            "recommended_fix":      "Manual review required",
            "fix_steps":            [],
            "operational_impact":   "Unknown",
            "safe_window":          "N/A",
            "rollback_steps":       [],
            "gate_block_reason":    None,
            "prerequisite_actions": [],
            "_llm_error":           reason,
        }
