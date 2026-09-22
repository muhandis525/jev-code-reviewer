from __future__ import annotations

import re

SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|api[_-]?key|secret|access[_-]?token)\s*[:=]\s*)(['\"])(.*?)(\2)"
)
TOKEN_LIKE = re.compile(r"\b(?:apikey_|sk-|ghp_|github_pat_)[A-Za-z0-9_-]{12,}\b")
BEARER = re.compile(
    r"(?i)(\b(?:authorization\s*[:=]\s*)?[\"']?bearer\s+)[A-Za-z0-9._~+/=-]{12,}"
)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
)


def redact(text: str) -> str:
    text = SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]{match.group(2)}",
        text,
    )
    text = TOKEN_LIKE.sub("[REDACTED_TOKEN]", text)
    text = BEARER.sub(r"\1[REDACTED_TOKEN]", text)
    text = JWT.sub("[REDACTED_JWT]", text)
    text = AWS_ACCESS_KEY.sub("[REDACTED_AWS_KEY]", text)
    return PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", text)
