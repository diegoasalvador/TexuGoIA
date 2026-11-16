"""
Analisador SAST (Static Application Security Testing) do TeXuGo-GuardIA.

Varre arquivos de código-fonte em busca de padrões de vulnerabilidades conhecidas,
credenciais expostas e práticas inseguras de programação.
"""

from pathlib import Path
import re
from typing import List, Set
from TeXGuardIA.knowledge.owasp_rules import SAST_DETECTION_RULES, VulnerabilityInfo


class CodeAnalyzer:
    """Motor de análise estática de segurança de código."""

    # Extensões comumente analisadas
    SUPPORTED_EXTENSIONS: Set[str] = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".php",
        ".java", ".go", ".rb", ".cs", ".env", ".yml", ".yaml"
    }

    # Diretórios a serem ignorados por padrão
    IGNORED_DIRS: Set[str] = {
        ".git", ".venv", "venv", "env", "node_modules",
        "__pycache__", ".pytest_cache", ".idea", ".vscode", "dist", "build"
    }

    def __init__(self, custom_rules: List[dict] = None):
        self.rules = custom_rules or SAST_DETECTION_RULES
        self._compiled_rules = [
            {**rule, "_regex": re.compile(rule["pattern"])}
            for rule in self.rules
        ]

    def scan_path(self, target_path: str) -> List[VulnerabilityInfo]:
        """Varre um arquivo específico ou percorre um diretório recursivamente."""
        path = Path(target_path)
        vulnerabilities: List[VulnerabilityInfo] = []

        if not path.exists():
            raise FileNotFoundError(f"Caminho não encontrado: {target_path}")

        if path.is_file():
            return self.scan_file(path)

        for item in path.rglob("*"):
            # Ignorar diretórios e caminhos indesejados
            if any(ignored in item.parts for ignored in self.IGNORED_DIRS):
                continue

            if item.is_file() and (item.suffix.lower() in self.SUPPORTED_EXTENSIONS or item.name.startswith(".env")):
                try:
                    findings = self.scan_file(item)
                    vulnerabilities.extend(findings)
                except Exception:
                    # Continua a análise caso algum arquivo individual falhe na leitura
                    continue

        return vulnerabilities

    def scan_file(self, file_path: Path) -> List[VulnerabilityInfo]:
        """Varre um único arquivo de código em busca de vulnerabilidades."""
        findings: List[VulnerabilityInfo] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            return findings

        for line_num, line in enumerate(lines, start=1):
            stripped_line = line.strip()
            # Ignorar comentários puros simples
            if stripped_line.startswith("#") or stripped_line.startswith("//") or stripped_line.startswith("*"):
                continue

            for rule in self._compiled_rules:
                if rule["_regex"].search(stripped_line):
                    findings.append(
                        VulnerabilityInfo(
                            id=rule["id"],
                            title=rule["title"],
                            category=rule["category"],
                            cwe=rule["cwe"],
                            severity=rule["severity"],
                            description=rule["description"],
                            impact=rule["impact"],
                            remediation=rule["remediation"],
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=stripped_line[:120],
                            target=str(file_path),
                        )
                    )

        return findings
