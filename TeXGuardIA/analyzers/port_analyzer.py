"""
Analisador de Portas e Superfície de Rede do TeXuGo-GuardIA.

Realiza verificações de conectividade em portas comuns e identifica serviços de risco,
protocolos sem criptografia e bancos de dados expostos.
"""

import concurrent.futures
import socket
from typing import Dict, List, Optional
from TeXGuardIA.config import settings
from TeXGuardIA.knowledge.owasp_rules import SENSITIVE_PORTS, VulnerabilityInfo


class PortAnalyzer:
    """Motor de análise e diagnóstico defensivo de portas e serviços."""

    # Portas padrão avaliadas na análise rápida
    DEFAULT_PORTS: List[int] = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 27017, 9200]

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    def scan_host(self, host: str, ports: Optional[List[int]] = None) -> List[VulnerabilityInfo]:
        """Varre o host indicado avaliando portas abertas e seus riscos associados de forma concorrente."""
        target_ports = sorted(list(set(ports or self.DEFAULT_PORTS)))
        findings: List[VulnerabilityInfo] = []

        # Remove prefixos de protocolo se fornecido (ex: http:// ou https://)
        clean_host = host.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        open_ports: List[int] = []
        max_workers = min(30, max(len(target_ports), 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(self._is_port_open, clean_host, p): p for p in target_ports}
            for future in concurrent.futures.as_completed(future_to_port):
                p = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(p)
                except Exception:
                    pass

        open_ports.sort()
        for port in open_ports:
            # Se for uma porta sensível conhecida, gera apontamento de risco
            if port in SENSITIVE_PORTS:
                port_meta = SENSITIVE_PORTS[port]
                findings.append(
                    VulnerabilityInfo(
                        id=f"NET-PORT-{port}",
                        title=f"Serviço Sensível Aberto: {port_meta['service']} (Porta {port}/TCP)",
                        category="A05:2021",
                        cwe="CWE-16",
                        severity=port_meta["severity"],
                        description=f"A porta {port} ({port_meta['service']}) foi detectada aberta e acessível.",
                        impact=port_meta["risk"],
                        remediation=port_meta["remediation"],
                        target=f"{clean_host}:{port}",
                    )
                )
            else:
                # Porta genérica aberta (informativa)
                findings.append(
                    VulnerabilityInfo(
                        id=f"NET-INFO-{port}",
                        title=f"Porta Aberta Detectada: Porta {port}/TCP",
                        category="A05:2021",
                        cwe="CWE-16",
                        severity="INFORMATIVA",
                        description=f"A porta TCP {port} respondeu positivamente à conexão.",
                        impact="Aumento da superfície de exposição de rede.",
                        remediation="Garanta que apenas serviços estritamente necessários estejam expostos via regras de firewall.",
                        target=f"{clean_host}:{port}",
                    )
                )

        return findings

    def _is_port_open(self, host: str, port: int) -> bool:
        """Verifica se uma porta TCP está aceitando conexões de forma não intrusiva."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((host, port))
            return result == 0
        except Exception:
            return False
        finally:
            sock.close()
