"""
Módulo de Base de Conhecimento e Regras de Segurança do TeXGuardIA.
"""

from .owasp_rules import (
    OWASP_CATEGORIES,
    SAST_DETECTION_RULES,
    WEB_SECURITY_HEADERS,
    SENSITIVE_PORTS,
    VulnerabilityInfo,
)

__all__ = [
    "OWASP_CATEGORIES",
    "SAST_DETECTION_RULES",
    "WEB_SECURITY_HEADERS",
    "SENSITIVE_PORTS",
    "VulnerabilityInfo",
]
