"""
Utilitários de Segurança, Validação e Sanitização do TeXuGo-GuardIA.

Previne vulnerabilidades operacionais como Path Traversal (CWE-22),
injeção de comandos e valida limites de portas de rede (1-65535).
"""

import os
from pathlib import Path
import re
from typing import List, Optional, Tuple, Union


def sanitize_filename_target(target: str) -> str:
    """Gera um identificador e sufixo de arquivo estritamente seguro baseado no alvo.

    Remove sequências de path traversal (ex: ../, ..\\), esquemas de URL,
    caracteres especiais e barras de diretório, garantindo que o resultado
    seja apenas um nome de arquivo plano sem capacidade de escape de diretório.
    """
    if not target:
        return "alvo"

    # Remove protocolos web
    cleaned = re.sub(r"^https?://", "", str(target).strip(), flags=re.IGNORECASE)
    # Remove sequências de traversal (.. ou .)
    cleaned = re.sub(r"\.\.+[/\\ ]*", "", cleaned)
    # Substitui caracteres perigosos no sistema de arquivos
    cleaned = re.sub(r"[/\\:*?\"<>|\x00-\x1f]", "_", cleaned)
    # Colapsa múltiplos underscores e hífens
    cleaned = re.sub(r"_+", "_", cleaned).strip("._ -")
    # Limita tamanho para não estourar limites do sistema de arquivos
    cleaned = cleaned[:50]

    return cleaned if cleaned else "alvo"


def validate_port(port_val: Union[int, str]) -> Optional[int]:
    """Valida se uma porta específica pertence ao intervalo válido do protocolo TCP/UDP (1 a 65535)."""
    try:
        p = int(str(port_val).strip())
        if 1 <= p <= 65535:
            return p
        return None
    except (ValueError, TypeError):
        return None


def validate_port_list(ports_input: Union[str, List[Union[int, str]]]) -> Tuple[List[int], List[str]]:
    """Analisa e valida uma lista ou string de portas separadas por vírgula.

    Retorna uma tupla contendo:
      - valid_ports: Lista ordenada e sem duplicatas de portas válidas (1-65535).
      - invalid_entries: Lista com os tokens ou números que falharam na validação.
    """
    if isinstance(ports_input, str):
        tokens = [t.strip() for t in ports_input.split(",") if t.strip()]
    else:
        tokens = [str(t).strip() for t in ports_input if str(t).strip()]

    valid_ports = set()
    invalid_entries = []

    for token in tokens:
        p = validate_port(token)
        if p is not None:
            valid_ports.add(p)
        else:
            invalid_entries.append(token)

    return sorted(list(valid_ports)), invalid_entries
