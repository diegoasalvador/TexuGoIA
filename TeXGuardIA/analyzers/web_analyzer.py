"""
Analisador Web do TeXuGo-GuardIA.

Examina cabeçalhos HTTP de segurança, políticas de cookies e configurações de superfícies web.
"""

from typing import List, Dict
from urllib.parse import urlparse
import ssl

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    import urllib.request
    import http.client

from TeXGuardIA.config import settings
from TeXGuardIA.knowledge.owasp_rules import WEB_SECURITY_HEADERS, VulnerabilityInfo


class WebAnalyzer:
    """Motor de análise e auditoria de configurações web e cabeçalhos HTTP."""

    def __init__(self, timeout: int = None):
        self.timeout = timeout or settings.network_timeout

    def _fetch_headers_urllib(self, target_url: str) -> tuple[Dict[str, str], list]:
        """Fallback nativo via urllib caso requests não esteja instalado."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "TeXuGo-GuardIA-SecurityScanner/1.0 (Auditoria Defensiva)"}
        )

        with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            raw_cookies = response.headers.get_all("Set-Cookie") or []
            return headers, raw_cookies

    def scan_url(self, target_url: str) -> List[VulnerabilityInfo]:
        """Realiza requisição ao alvo e audita a postura de segurança web."""
        findings: List[VulnerabilityInfo] = []

        # Normaliza URL
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        parsed = urlparse(target_url)

        # 1. Verificação de transporte não criptografado (HTTP simples)
        if parsed.scheme == "http":
            findings.append(
                VulnerabilityInfo(
                    id="WEB-001",
                    title="Tráfego Web Não Criptografado (HTTP em vez de HTTPS)",
                    category="A02:2021",
                    cwe="CWE-319",
                    severity="ALTA",
                    description="O alvo está sendo acessado via protocolo HTTP desprovido de criptografia TLS.",
                    impact="Permite interceptação e manipulação de credenciais e dados em trânsito (MitM).",
                    remediation="Habilite HTTPS com certificado TLS válido e force o redirecionamento automático 301.",
                    target=target_url,
                )
            )

        # 2. Requisição para obtenção dos cabeçalhos
        response_headers: Dict[str, str] = {}
        cookies_list = []

        try:
            if REQUESTS_AVAILABLE:
                headers_req = {
                    "User-Agent": "TeXuGo-GuardIA-SecurityScanner/1.0 (Auditoria Defensiva)"
                }
                response = requests.get(
                    target_url,
                    headers=headers_req,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
                response_headers = {k.lower(): v for k, v in response.headers.items()}
                cookies_list = [
                    (c.name, c.has_nonstandard_attr("HttpOnly") or c._rest.get("httponly"), c.secure)
                    for c in response.cookies
                ]
            else:
                response_headers, raw_cookies = self._fetch_headers_urllib(target_url)
                for rc in raw_cookies:
                    c_name = rc.split("=")[0].strip() if "=" in rc else "cookie"
                    c_httponly = "httponly" in rc.lower()
                    c_secure = "secure" in rc.lower()
                    cookies_list.append((c_name, c_httponly, c_secure))
        except Exception as e:
            findings.append(
                VulnerabilityInfo(
                    id="WEB-ERR",
                    title="Falha de Comunicação com Alvo Web",
                    category="A05:2021",
                    cwe="CWE-16",
                    severity="INFORMATIVA",
                    description=f"Não foi possível conectar ao alvo: {str(e)}",
                    impact="Impossibilidade de auditar a superfície web no momento.",
                    remediation="Verifique conectividade, regras de firewall e disponibilidade do host.",
                    target=target_url,
                )
            )
            return findings

        # 3. Auditoria de cabeçalhos ausentes recomendados
        for header_name, meta in WEB_SECURITY_HEADERS.items():
            if header_name.lower() not in response_headers:
                findings.append(
                    VulnerabilityInfo(
                        id=f"WEB-HDR-{header_name[:4].upper()}",
                        title=meta["title"],
                        category=meta["category"],
                        cwe=meta["cwe"],
                        severity=meta["severity"],
                        description=meta["description"],
                        impact="Redução das barreiras de defesa em profundidade no navegador do usuário.",
                        remediation=meta["remediation"],
                        target=target_url,
                    )
                )

        # 4. Divulgação de informações sobre o servidor / stack tecnológica
        for leak_header in ["server", "x-powered-by", "x-aspnet-version"]:
            if leak_header in response_headers:
                value = response_headers[leak_header]
                findings.append(
                    VulnerabilityInfo(
                        id="WEB-LEAK",
                        title=f"Vazamento de Banner Tecnológico no Cabeçalho ({leak_header.title()})",
                        category="A05:2021",
                        cwe="CWE-200",
                        severity="BAIXA",
                        description=f"O servidor expõe tecnologias e versões detalhadas no cabeçalho '{leak_header}': '{value}'.",
                        impact="Facilita o reconhecimento por atacantes em busca de exploits específicos para essa versão.",
                        remediation="Oculte ou remova cabeçalhos de identificação na configuração do servidor web.",
                        target=target_url,
                    )
                )

        # 5. Auditoria de Cookies (Flags de Segurança)
        for c_name, c_httponly, c_secure in cookies_list:
            missing_flags = []
            if not c_httponly:
                missing_flags.append("HttpOnly (proteção contra roubo via XSS)")
            if not c_secure and parsed.scheme == "https":
                missing_flags.append("Secure (tráfego restrito a HTTPS)")

            if missing_flags:
                findings.append(
                    VulnerabilityInfo(
                        id="WEB-COOKIE",
                        title=f"Cookie com Flags de Segurança Ausentes ('{c_name}')",
                        category="A05:2021",
                        cwe="CWE-614",
                        severity="MÉDIA",
                        description=f"O cookie '{c_name}' foi emitido sem: {', '.join(missing_flags)}.",
                        impact="Aumenta o risco de sequestro de sessão através de scripts maliciosos ou conexões inseguras.",
                        remediation="Configure os atributos HttpOnly; Secure; SameSite=Lax (ou Strict) para todos os cookies de sessão.",
                        target=target_url,
                    )
                )

        return findings
