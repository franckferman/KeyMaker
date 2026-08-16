"""Optional LLM-backed text variant generator — stdlib only, opt-in via --llm flag.

Providers: ollama | deepseek | anthropic | openai | kimi
Spec format: 'provider' or 'provider:model'
"""

from __future__ import annotations

import json
import os
import random
import re
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Prompt pools per category — rotate framing so the LLM sees varied requests
# ---------------------------------------------------------------------------

_PROMPTS: dict[str, list[str]] = {
    "it_comment": [
        'Return {n} short IT script comment phrases similar to "{seed}". '
        "3-6 words, imperative form. Respond with a JSON array of strings only.",
        'List {n} concise sysadmin script comment variants for "{seed}". '
        "Fragment style, 2-5 words. JSON array of strings, no explanation.",
        'Paraphrase "{seed}" as {n} brief IT script comment phrases. '
        "Respond only with a JSON string array.",
        'Generate {n} short IT maintenance script comments like "{seed}". '
        "2-5 words each, varied wording. JSON array only.",
    ],
    "verbose_msg": [
        'Return {n} short PowerShell Write-Verbose log string variants of "{seed}". '
        "1-3 words, action-oriented. JSON array of strings only.",
        'List {n} brief script status message variants for "{seed}". '
        "Short nouns or gerunds, varied. JSON array, no explanation.",
        'Paraphrase "{seed}" as {n} terse script verbose log messages. '
        "JSON string array only.",
        'Generate {n} brief sysadmin log message variants of "{seed}". '
        "1-2 words preferred. JSON array only.",
    ],
    "ps_func_name": [
        'Return {n} PowerShell function names in Verb-Noun format for "{seed}". '
        "Use approved PS verbs. JSON array of strings only.",
        'List {n} realistic PowerShell Verb-Noun function names related to "{seed}". '
        "Approved verbs (Get/Set/New/Remove/Start/Stop/Test). JSON array only.",
        'Generate {n} plausible PS function names for "{seed}". '
        "Verb-Noun style, professional. JSON string array only.",
    ],
    "config_key": [
        'Return {n} IT script config variable names related to "{seed}". '
        "CamelCase, professional. JSON array of strings only.",
        'List {n} realistic script parameter names for concept "{seed}". '
        "CamelCase preferred. JSON array, no explanation.",
        'Generate {n} plausible configuration key names for "{seed}". '
        "IT/sysadmin naming conventions. JSON string array only.",
        'Name {n} config variables for a script dealing with "{seed}". '
        "Professional, CamelCase. JSON array only.",
    ],
}


# ---------------------------------------------------------------------------
# Response parser — tolerates markdown fences, prose preambles, and line lists
# ---------------------------------------------------------------------------


def _parse_response(text: str) -> list[str]:
    """Extract a string list from an LLM response regardless of formatting."""
    # Strip code fences
    text = re.sub(r"```(?:json|JSON)?\s*", "", text)
    text = re.sub(r"```\s*", "", text).strip()

    # Attempt whole-text JSON parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [
                s
                for x in parsed
                if (s := str(x).strip())
                and not s.startswith("{")
                and not s.startswith("[")
            ]
    except json.JSONDecodeError:
        pass

    # Attempt first [...] block
    m = re.search(r"\[.*?\]", text, re.DOTALL)
    if m:
        try:
            parsed = json.loads(m.group())
            if isinstance(parsed, list):
                return [
                    s
                    for x in parsed
                    if (s := str(x).strip())
                    and not s.startswith("{")
                    and not s.startswith("[")
                ]
        except json.JSONDecodeError:
            pass

    # Line-by-line fallback (handles numbered lists, bullets, bare lines)
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        # Strip leading list markers
        line = re.sub(r"^[\d]+[.)]\s*", "", line)
        line = line.strip("-*•·").strip('"').strip("'").strip(",").strip()
        if (
            line
            and not line.startswith("[")
            and not line.startswith("]")
            and not line.startswith("{")
            and len(line) > 1
        ):
            lines.append(line)
    return lines


# ---------------------------------------------------------------------------
# Backend callers — one per provider
# ---------------------------------------------------------------------------


def _call_ollama(prompt: str, model: str, base_url: str) -> list[str]:
    payload = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.9, "num_predict": 256},
        }
    ).encode()
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    return _parse_response(data.get("response", ""))


def _call_openai_compat(
    prompt: str,
    model: str,
    api_key: str,
    base_url: str,
) -> list[str]:
    payload = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.9,
            "max_tokens": 256,
        }
    ).encode()
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    content = data["choices"][0]["message"]["content"]
    return _parse_response(content)


def _call_anthropic(prompt: str, model: str, api_key: str) -> list[str]:
    payload = json.dumps(
        {
            "model": model,
            "max_tokens": 256,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    content = data["content"][0]["text"]
    return _parse_response(content)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class LLMProvider:
    """Configured LLM provider for text variant and cert profile generation.

    Instantiate once per build; call augment() per pool category or
    generate_cert_profile() for a coherent cert identity.
    Results are cached by (category, pool sample) — safe to call multiple times.
    """

    _DEFAULTS: dict[str, str] = {
        "ollama": "llama3.2",
        "deepseek": "deepseek-chat",
        "anthropic": "claude-haiku-4-5-20251001",
        "openai": "gpt-4o-mini",
        "kimi": "moonshot-v1-8k",
    }

    def __init__(self, spec: str) -> None:
        """spec: 'provider' or 'provider:model'"""
        parts = spec.split(":", 1)
        self.provider = parts[0].lower().strip()
        self.model = (
            parts[1] if len(parts) > 1 else self._DEFAULTS.get(self.provider, "")
        )
        if self.provider not in self._DEFAULTS:
            raise ValueError(
                f"Unknown LLM provider {self.provider!r}. "
                f"Valid: {', '.join(self._DEFAULTS)}"
            )
        self._cache: dict[str, list[str]] = {}

    def _call_raw(self, prompt: str, rng: "random.Random") -> "str | None":
        """Call the provider and return raw text response, or None on failure."""
        try:
            if self.provider == "ollama":
                url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
                payload = json.dumps(
                    {
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": 0.7, "num_predict": 300},
                    }
                ).encode()
                req = urllib.request.Request(
                    f"{url.rstrip('/')}/api/generate",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read()).get("response", "")
            if self.provider in ("deepseek", "openai"):
                urls = {
                    "deepseek": "https://api.deepseek.com/v1",
                    "openai": "https://api.openai.com/v1",
                }
                keys = {
                    "deepseek": os.environ.get("DEEPSEEK_API_KEY", ""),
                    "openai": os.environ.get("OPENAI_API_KEY", ""),
                }
                payload = json.dumps(
                    {
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.7,
                        "max_tokens": 300,
                    }
                ).encode()
                req = urllib.request.Request(
                    f"{urls[self.provider]}/chat/completions",
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {keys[self.provider]}",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read())["choices"][0]["message"]["content"]
            if self.provider == "kimi":
                key = os.environ.get("MOONSHOT_API_KEY", "")
                payload = json.dumps(
                    {
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.7,
                        "max_tokens": 300,
                    }
                ).encode()
                req = urllib.request.Request(
                    "https://api.moonshot.cn/v1/chat/completions",
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {key}",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read())["choices"][0]["message"]["content"]
            if self.provider == "anthropic":
                key = os.environ.get("ANTHROPIC_API_KEY", "")
                payload = json.dumps(
                    {
                        "model": self.model,
                        "max_tokens": 300,
                        "messages": [{"role": "user", "content": prompt}],
                    }
                ).encode()
                req = urllib.request.Request(
                    "https://api.anthropic.com/v1/messages",
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": key,
                        "anthropic-version": "2023-06-01",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read())["content"][0]["text"]
        except (urllib.error.URLError, KeyError, json.JSONDecodeError, OSError):
            pass
        return None

    def generate_cert_profile(
        self,
        context: str,
        rng: "random.Random",
    ) -> "dict | None":
        """Generate a coherent software company cert profile.

        Returns dict with keys: org, unit, country, email, cn — or None on failure.
        Prompt deliberately avoids security-tool framing.
        """
        prompts = [
            f"Generate a realistic software company profile for a code-signing certificate "
            f'in the "{context}" sector. '
            f'Return JSON with keys: org (company legal name), unit (department, e.g. "Software Engineering"), '
            f"country (ISO 3166-1 alpha-2 code), email (contact email), "
            f"cn (common name for the cert, usually same as org). "
            f"JSON object only, no explanation.",
            f'Create a plausible IT company identity for "{context}" environment. '
            f"JSON keys: org (full company name), unit (department name), country (2-letter country code), "
            f"email (company email), cn (certificate common name). JSON only.",
            f'Write a realistic company profile for a software vendor in the "{context}" space. '
            f"Return JSON: org, unit, country (ISO alpha-2), email, cn. JSON object only.",
        ]
        prompt = rng.choice(prompts)
        raw = self._call_raw(prompt, rng)
        if raw is None:
            return None
        # Strip fences and parse JSON
        raw = re.sub(r"```(?:json|JSON)?\s*", "", raw)
        raw = re.sub(r"```\s*", "", raw).strip()
        try:
            d = json.loads(raw)
            if isinstance(d, dict) and "org" in d:
                return d
        except json.JSONDecodeError:
            pass
        # Try to find first {...} block
        m = re.search(r"\{[^{}]*\}", raw, re.DOTALL)
        if m:
            try:
                d = json.loads(m.group())
                if isinstance(d, dict) and "org" in d:
                    return d
            except json.JSONDecodeError:
                pass
        return None

    def variants(
        self,
        category: str,
        seed: str,
        n: int,
        rng: random.Random,
    ) -> list[str]:
        """Call the LLM once and return up to n variant strings.

        Returns empty list on network/auth failure — caller handles fallback.
        Prompt template is picked at random from the pool for that category.
        """
        prompt_pool = _PROMPTS.get(category, _PROMPTS["it_comment"])
        prompt = rng.choice(prompt_pool).format(n=n, seed=seed)
        try:
            if self.provider == "ollama":
                url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
                return _call_ollama(prompt, self.model, url)
            if self.provider == "deepseek":
                key = os.environ.get("DEEPSEEK_API_KEY", "")
                return _call_openai_compat(
                    prompt, self.model, key, "https://api.deepseek.com/v1"
                )
            if self.provider == "anthropic":
                key = os.environ.get("ANTHROPIC_API_KEY", "")
                return _call_anthropic(prompt, self.model, key)
            if self.provider == "openai":
                key = os.environ.get("OPENAI_API_KEY", "")
                return _call_openai_compat(
                    prompt, self.model, key, "https://api.openai.com/v1"
                )
            if self.provider == "kimi":
                key = os.environ.get("MOONSHOT_API_KEY", "")
                return _call_openai_compat(
                    prompt, self.model, key, "https://api.moonshot.cn/v1"
                )
        except (urllib.error.URLError, KeyError, json.JSONDecodeError, OSError):
            pass
        return []

    def augment(
        self,
        category: str,
        base_pool: list[str],
        n: int,
        rng: random.Random,
    ) -> list[str]:
        """Return base_pool + LLM-generated variants (cached per category+sample).

        Falls back silently to base_pool on any LLM failure.
        n: number of new variants to request (the LLM may return fewer).
        """
        cache_key = f"{category}:{','.join(sorted(base_pool[:3]))}"
        if cache_key not in self._cache:
            seed = rng.choice(base_pool) if base_pool else category
            generated = self.variants(category, seed, n, rng)
            self._cache[cache_key] = base_pool + [v for v in generated if v]
        return self._cache[cache_key]


# ---------------------------------------------------------------------------
# Industry-specific org identity — standalone, no persistent LLMProvider needed
# ---------------------------------------------------------------------------


def llm_org_identity(
    spec: str,
    industry: str,
    country: str = "FR",
    rng: "random.Random | None" = None,
) -> "dict | None":
    """Generate a realistic X.509 cert identity for a given industry via LLM.

    Returns dict with keys: CN, O, OU, emailAddress, C, L, ST
    Returns None on any failure — caller uses static pool as fallback.

    spec: 'provider' or 'provider:model'
    Prompt avoids any security/attack terminology.
    """
    if not spec:
        return None
    try:
        llm = LLMProvider(spec)
    except ValueError:
        return None

    if rng is None:
        rng = random.Random()

    _prompts = [
        f"Generate a realistic enterprise software company identity for the {industry} sector in {country}. "
        f"Return JSON with keys: CN (common name, software product name), O (organization), "
        f"OU (department), emailAddress (support email), L (city), ST (state/region). "
        f"Use realistic {country} company and product names. JSON only, no explanation.",
        f"Create a plausible company profile for a software vendor in the {industry} sector based in {country}. "
        f"JSON keys: CN (product/brand name), O (full company name), OU (department), "
        f"emailAddress (contact email), L (city), ST (region). JSON object only.",
        f"Write a realistic {country} software company identity for the {industry} industry. "
        f"Return JSON: CN, O, OU, emailAddress, L, ST. JSON only.",
    ]
    prompt = rng.choice(_prompts)
    raw = llm._call_raw(prompt, rng)
    if raw is None:
        return None

    # strip code fences
    raw = re.sub(r"```(?:json|JSON)?\s*", "", raw)
    raw = re.sub(r"```\s*", "", raw).strip()

    required = {"CN", "O", "OU", "emailAddress", "L", "ST"}

    def _validate(d: object) -> "dict | None":
        if not isinstance(d, dict):
            return None
        if not (required & set(d)):
            return None
        # normalise C to 2-char ISO code regardless of source
        if "C" in d:
            d["C"] = str(d["C"])[:2].upper()
        else:
            d["C"] = country[:2].upper()
        return d

    try:
        d = json.loads(raw)
        result = _validate(d)
        if result is not None:
            return result
    except json.JSONDecodeError:
        pass

    # try first {...} block
    m = re.search(r"\{[^{}]*\}", raw, re.DOTALL)
    if m:
        try:
            d = json.loads(m.group())
            result = _validate(d)
            if result is not None:
                return result
        except json.JSONDecodeError:
            pass

    return None
