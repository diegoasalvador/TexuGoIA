"""
Testes Unitários Automatizados - TeXuGo-GuardIA
"""

import json
import unittest
from pathlib import Path

from TeXGuardIA.analyzers.code_analyzer import CodeAnalyzer
from TeXGuardIA.analyzers.port_analyzer import PortAnalyzer
from TeXGuardIA.knowledge.owasp_rules import VulnerabilityInfo
from TeXGuardIA.reporters.report_generator import ReportGenerator


class TestTeXGuardIAAnalyzers(unittest.TestCase):
    """Bateria de testes dos analisadores de segurança."""

    def setUp(self):
        self.code_analyzer = CodeAnalyzer()
        self.port_analyzer = PortAnalyzer()
        self.sample_code_path = Path("samples/vulnerable_code_test.py")

    def test_code_analyzer_detects_vulnerabilities(self):
        """Verifica se o CodeAnalyzer detecta as falhas no código de exemplo."""
        self.assertTrue(self.sample_code_path.exists(), "Arquivo sample de teste não encontrado.")
        findings = self.code_analyzer.scan_path(str(self.sample_code_path))
        self.assertGreaterEqual(len(findings), 4, "Esperado pelo menos 4 vulnerabilidades no sample.")

        cwes = [f.cwe for f in findings]
        self.assertIn("CWE-798", cwes, "Deveria detectar credencial hardcoded (CWE-798).")
        self.assertIn("CWE-502", cwes, "Deveria detectar desserialização insegura (CWE-502).")
        self.assertIn("CWE-94", cwes, "Deveria detectar eval dinâmico (CWE-94).")
        self.assertIn("CWE-89", cwes, "Deveria detectar injeção SQL (CWE-89).")
        self.assertIn("CWE-22", cwes, "Deveria detectar Path Traversal (CWE-22).")
        self.assertIn("CWE-79", cwes, "Deveria detectar XSS (CWE-79).")
        self.assertIn("CWE-918", cwes, "Deveria detectar SSRF (CWE-918).")
        self.assertIn("CWE-611", cwes, "Deveria detectar XXE (CWE-611).")

    def test_port_analyzer_host_sanitization(self):
        """Verifica a sanitização de hosts com prefixos de URL no PortAnalyzer."""
        # Não deve levantar exceção ao passar URL com protocolo
        findings = self.port_analyzer.scan_host("http://127.0.0.1:8080", ports=[])
        self.assertIsInstance(findings, list)

    def test_web_security_headers_rules(self):
        """Verifica a integridade e presença de regras essenciais de cabeçalhos web."""
        from TeXGuardIA.knowledge.owasp_rules import WEB_SECURITY_HEADERS
        self.assertIn("Strict-Transport-Security", WEB_SECURITY_HEADERS)
        self.assertIn("Content-Security-Policy", WEB_SECURITY_HEADERS)
        self.assertIn("X-Frame-Options", WEB_SECURITY_HEADERS)

    def test_report_generator_json_and_md(self):
        """Testa a geração de relatórios JSON e Markdown em memória/disco."""
        dummy_vulns = [
            VulnerabilityInfo(
                id="SAST-001",
                title="Teste de Injeção SQL",
                category="A03:2021",
                cwe="CWE-89",
                severity="CRÍTICA",
                description="Parâmetro vulnerável.",
                impact="Risco de vazamento de dados ou bypass de autenticação.",
                remediation="Use consultas parametrizadas.",
                code_snippet="SELECT * FROM users WHERE id = ' + user_id",
                file_path="teste.py",
                line_number=10,
            )
        ]
        reporter = ReportGenerator(
            target_name="teste.py",
            scan_type="SAST"
        )

        md = reporter.generate_markdown(dummy_vulns, ai_summary="Parecer sintético de teste.")
        self.assertIn("Teste de Injeção SQL", md)
        self.assertIn("CWE-89", md)

        json_str = reporter.generate_json(dummy_vulns)
        data = json.loads(json_str)
        self.assertEqual(data["scan_type"], "SAST")
        self.assertEqual(len(data["findings"]), 1)


if __name__ == "__main__":
    unittest.main()
