"""Tests for llm_org_identity() and --industry CLI flag."""

from __future__ import annotations

import json
import random
import sys
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from keymaker.cli import build_parser
from keymaker.llm import LLMProvider, llm_org_identity

# ── llm_org_identity unit tests ────────────────────────────────────────────────


class TestLLMOrgIdentity:
    def test_empty_spec_returns_none(self):
        """Empty spec → None without any network call."""
        result = llm_org_identity("", "finance")
        assert result is None

    def test_unknown_provider_returns_none(self):
        """Unknown LLM provider → None (no ValueError propagated)."""
        result = llm_org_identity("notaprovider", "healthcare")
        assert result is None

    def test_url_error_returns_none(self):
        """Network failure → None (silent fallback)."""
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            result = llm_org_identity("ollama", "finance", "FR")
        assert result is None

    def test_call_raw_none_returns_none(self):
        """_call_raw returning None propagates as None."""
        with patch.object(LLMProvider, "_call_raw", return_value=None):
            result = llm_org_identity("ollama", "finance", "FR", random.Random(0))
        assert result is None

    def test_returns_dict_with_required_keys(self):
        """Successful LLM call → dict containing all required keys."""
        mock_payload = json.dumps(
            {
                "CN": "HealthSoft Pro",
                "O": "MediCorp SAS",
                "OU": "Software Development",
                "emailAddress": "cert@medicorp.fr",
                "L": "Paris",
                "ST": "Île-de-France",
                "C": "FR",
            }
        )
        with patch.object(LLMProvider, "_call_raw", return_value=mock_payload):
            result = llm_org_identity("ollama", "healthcare", "FR", random.Random(0))
        assert result is not None
        required = {"CN", "O", "OU", "emailAddress", "L", "ST"}
        assert required <= set(result), f"missing keys: {required - set(result)}"
        assert result["CN"] == "HealthSoft Pro"
        assert result["O"] == "MediCorp SAS"
        assert result["OU"] == "Software Development"
        assert result["L"] == "Paris"
        assert result["ST"] == "Île-de-France"

    def test_adds_c_from_country_arg_when_missing(self):
        """C key injected from country arg when LLM omits it."""
        mock_payload = json.dumps(
            {
                "CN": "FinTech Pro",
                "O": "CapSoft SA",
                "OU": "Engineering",
                "emailAddress": "code@capsoft.fr",
                "L": "Lyon",
                "ST": "Auvergne-Rhône-Alpes",
            }
        )
        with patch.object(LLMProvider, "_call_raw", return_value=mock_payload):
            result = llm_org_identity("ollama", "finance", "FR", random.Random(0))
        assert result is not None
        assert result.get("C") == "FR"

    def test_invalid_json_returns_none(self):
        """Garbled LLM response → None."""
        with patch.object(
            LLMProvider, "_call_raw", return_value="not valid json at all!"
        ):
            result = llm_org_identity("ollama", "retail", "FR", random.Random(0))
        assert result is None

    def test_json_missing_required_keys_returns_none(self):
        """JSON parsed but none of the required keys present → None."""
        mock_payload = json.dumps({"name": "Bad Corp", "region": "North"})
        with patch.object(LLMProvider, "_call_raw", return_value=mock_payload):
            result = llm_org_identity("ollama", "energy", "FR", random.Random(0))
        assert result is None

    def test_fenced_json_parsed(self):
        """Response wrapped in code fences is still parsed."""
        inner = json.dumps(
            {
                "CN": "RetailSoft",
                "O": "ShopTech SA",
                "OU": "Dev",
                "emailAddress": "dev@shoptech.fr",
                "L": "Bordeaux",
                "ST": "Nouvelle-Aquitaine",
            }
        )
        fenced = f"```json\n{inner}\n```"
        with patch.object(LLMProvider, "_call_raw", return_value=fenced):
            result = llm_org_identity("deepseek", "retail", "FR", random.Random(1))
        assert result is not None
        assert result["O"] == "ShopTech SA"

    def test_embedded_json_block_parsed(self):
        """JSON object embedded inside prose is extracted."""
        inner = json.dumps(
            {
                "CN": "EduPro",
                "O": "LearningCorp",
                "OU": "R&D",
                "emailAddress": "cert@learningcorp.fr",
                "L": "Nantes",
                "ST": "Pays-de-la-Loire",
            }
        )
        raw = f"Sure! Here is the identity: {inner} Hope this helps."
        with patch.object(LLMProvider, "_call_raw", return_value=raw):
            result = llm_org_identity("anthropic", "education", "FR", random.Random(2))
        assert result is not None
        assert result["CN"] == "EduPro"

    def test_country_truncated_to_two_chars(self):
        """C field from LLM truncated to 2-char ISO code."""
        mock_payload = json.dumps(
            {
                "CN": "TeleNet",
                "O": "TeleCorp SA",
                "OU": "Infra",
                "emailAddress": "cert@telecorp.fr",
                "L": "Paris",
                "ST": "IDF",
                "C": "FRA",  # 3-char code from LLM
            }
        )
        with patch.object(LLMProvider, "_call_raw", return_value=mock_payload):
            result = llm_org_identity("openai", "telecom", "FR", random.Random(3))
        assert result is not None
        assert result["C"] == "FR"

    def test_none_rng_uses_default(self):
        """Passing rng=None does not raise."""
        with patch.object(LLMProvider, "_call_raw", return_value=None):
            result = llm_org_identity("ollama", "manufacturing", "DE", rng=None)
        assert result is None


# ── --industry CLI flag ────────────────────────────────────────────────────────


class TestCLIIndustryFlag:
    def setup_method(self):
        self.p = build_parser()

    def test_industry_flag_parseable(self):
        args = self.p.parse_args(["gen", "--industry", "healthcare"])
        assert args.industry == "healthcare"

    def test_industry_default_empty(self):
        args = self.p.parse_args(["gen"])
        assert args.industry == ""

    def test_industry_with_llm(self):
        args = self.p.parse_args(["gen", "--llm", "ollama", "--industry", "finance"])
        assert args.llm == "ollama"
        assert args.industry == "finance"

    def test_no_industry_no_regression(self):
        """Without --industry, gen args are unchanged from before."""
        args = self.p.parse_args(["gen"])
        assert args.llm == ""
        assert args.industry == ""
        assert args.pool == "enterprise"
        assert args.llm_context == ""

    def test_all_sectors_parseable(self):
        sectors = [
            "healthcare",
            "finance",
            "retail",
            "manufacturing",
            "telecom",
            "energy",
            "legal",
            "education",
        ]
        for sector in sectors:
            args = self.p.parse_args(["gen", "--industry", sector])
            assert args.industry == sector

    def test_industry_without_llm_parseable(self):
        """--industry is accepted even without --llm (fallback silently to static)."""
        args = self.p.parse_args(["gen", "--industry", "finance"])
        assert args.industry == "finance"
        assert args.llm == ""


# ── kimi provider ─────────────────────────────────────────────────────────────


def test_kimi_no_key_returns_none(monkeypatch):
    """llm_org_identity("kimi", ...) → None when MOONSHOT_API_KEY absent."""
    import urllib.error

    monkeypatch.delenv("MOONSHOT_API_KEY", raising=False)
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *a, **kw: (_ for _ in ()).throw(urllib.error.URLError("refused")),
    )
    result = llm_org_identity("kimi", "finance")
    assert result is None


def test_kimi_default_model():
    p = LLMProvider("kimi")
    assert p.provider == "kimi"
    assert p.model == "moonshot-v1-8k"
