"""
Thin wrapper around the Anthropic Python SDK.

This is the *only* module in the codebase that communicates directly with the
LLM. All other modules that need natural-language reasoning must call through
``complete`` or ``stream_complete``; they must not instantiate an
``anthropic.Anthropic`` client themselves.

Environment variables
---------------------
ANTHROPIC_API_KEY : str
    Required. Obtain from https://console.anthropic.com/
"""

from __future__ import annotations

import os
from typing import Generator

import anthropic

_DEFAULT_MODEL = "claude-sonnet-4-5-20250929"
_DEFAULT_MAX_TOKENS = 4096


def _client() -> anthropic.Anthropic:
    """Return an Anthropic client, raising clearly if the key is missing."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY environment variable is not set. "
            "Add it to your .env.local file or Vercel project settings."
        )
    return anthropic.Anthropic(api_key=api_key)


def complete(
    prompt: str,
    system: str | None = None,
    model: str = _DEFAULT_MODEL,
    max_tokens: int = _DEFAULT_MAX_TOKENS,
) -> str:
    """
    Send a single prompt and return the complete text response.

    Parameters
    ----------
    prompt : str
        The user-turn message to send.
    system : str | None
        Optional system prompt that sets context and persona.
    model : str
        Claude model identifier.
    max_tokens : int
        Maximum tokens to generate.

    Returns
    -------
    str
        The model's text response.

    Raises
    ------
    EnvironmentError
        If ANTHROPIC_API_KEY is not set.
    ConnectionError
        If the Anthropic API cannot be reached.
    RuntimeError
        If the API returns a non-success status.
    """
    kwargs: dict = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system

    try:
        message = _client().messages.create(**kwargs)
        block = message.content[0]
        if block.type != "text":
            raise RuntimeError(f"Unexpected content block type: {block.type}")
        return block.text
    except anthropic.APIConnectionError as exc:
        raise ConnectionError(
            f"Could not connect to Anthropic API: {exc}"
        ) from exc
    except anthropic.APIStatusError as exc:
        raise RuntimeError(
            f"Anthropic API error {exc.status_code}: {exc.message}"
        ) from exc


def stream_complete(
    prompt: str,
    system: str | None = None,
    model: str = _DEFAULT_MODEL,
    max_tokens: int = _DEFAULT_MAX_TOKENS,
) -> Generator[str, None, None]:
    """
    Stream a response, yielding text chunks as they arrive from the API.

    Parameters
    ----------
    prompt : str
        The user-turn message to send.
    system : str | None
        Optional system prompt.
    model : str
        Claude model identifier.
    max_tokens : int
        Maximum tokens to generate.

    Yields
    ------
    str
        Successive text deltas from the streaming response.

    Raises
    ------
    EnvironmentError
        If ANTHROPIC_API_KEY is not set.
    ConnectionError
        If the Anthropic API cannot be reached.
    RuntimeError
        If the API returns a non-success status.
    """
    kwargs: dict = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system

    try:
        with _client().messages.stream(**kwargs) as stream:
            for text_chunk in stream.text_stream:
                yield text_chunk
    except anthropic.APIConnectionError as exc:
        raise ConnectionError(
            f"Could not connect to Anthropic API: {exc}"
        ) from exc
    except anthropic.APIStatusError as exc:
        raise RuntimeError(
            f"Anthropic API error {exc.status_code}: {exc.message}"
        ) from exc
