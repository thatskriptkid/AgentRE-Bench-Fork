from __future__ import annotations

import os

from .openai_provider import OpenAIProvider

# Alibaba DashScope: region-specific OpenAI-compatible endpoints
# See https://help.aliyun.com/zh/model-studio/error-code#apikey-error
DASHSCOPE_BASE_URL_BEIJING = "https://dashscope.aliyuncs.com/compatible-mode/v1"
DASHSCOPE_BASE_URL_SINGAPORE = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
DASHSCOPE_BASE_URL_US = "https://dashscope-us.aliyuncs.com/compatible-mode/v1"
# Coding Plan keys (sk-sp-*): China vs International (Singapore) have different endpoints
# See Model Studio → Coding Plan → Plan Exclusive Base URL
DASHSCOPE_BASE_URL_CODING = "https://coding.dashscope.aliyuncs.com/v1"  # China
DASHSCOPE_BASE_URL_CODING_INTL = "https://coding-intl.dashscope.aliyuncs.com/v1"  # Singapore (ap-southeast-1)


def _resolve_qwen_base_url(api_key: str, base_url: str | None) -> str:
    if base_url:
        return base_url.rstrip("/")
    # Override via env (required for Singapore Coding Plan; optional for other regions)
    env_url = os.environ.get("DASHSCOPE_BASE_URL", "").strip()
    if env_url:
        return env_url.rstrip("/")
    # Coding Plan API keys (sk-sp-*) must use a dedicated endpoint; default is China
    if api_key.strip().startswith("sk-sp-"):
        return DASHSCOPE_BASE_URL_CODING
    return DASHSCOPE_BASE_URL_BEIJING


class QwenProvider(OpenAIProvider):
    """Alibaba Qwen via DashScope (OpenAI-compatible API)."""

    def __init__(self, api_key: str, model: str, base_url: str | None = None):
        super().__init__(
            api_key=api_key,
            model=model,
            base_url=_resolve_qwen_base_url(api_key, base_url),
        )

    def _token_param(self) -> str:
        return "max_tokens"
