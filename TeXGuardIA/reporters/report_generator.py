"""
Gerador de Relatórios Técnicos e Executivos do TeXuGo-GuardIA.

Exporta diagnósticos em formatos Markdown, JSON e exibição formatada no terminal.
"""

from dataclasses import asdict
from datetime import datetime
import json
from pathlib import Path
from typing import Dict, List
from TeXGuardIA.knowledge.owasp_rules import VulnerabilityInfo

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class ReportGenerator:
    """Responsável por consolidar vulnerabilidades e produzir relatórios."""

    def __init__(self, target_name: str, scan_type: str):
        self.target_name = target_name
        self.scan_type = scan_type
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def count_by_severity(self, vulnerabilities: List[VulnerabilityInfo]) -> Dict[str, int]:
        """Calcula a contagem de vulnerabilidades por nível de severidade."""
        counts = {"CRÍTICA": 0, "ALTA": 0, "MÉDIA": 0, "BAIXA": 0, "INFORMATIVA": 0}
        for v in vulnerabilities:
            sev = v.severity.upper()
            if sev in counts:
                counts[sev] += 1
            else:
                counts[sev] = 1
        return counts

    def generate_json(self, vulnerabilities: List[VulnerabilityInfo], output_path: str = None) -> str:
        """Gera relatório estruturado em formato JSON."""
        data = {
            "scanner": "TeXuGo-GuardIA",
            "version": "1.0.0",
            "target": self.target_name,
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "severity_counts": self.count_by_severity(vulnerabilities),
            },
            "findings": [asdict(v) for v in vulnerabilities],
        }

        json_str = json.dumps(data, indent=2, ensure_ascii=False)

        if output_path:
            out_file = Path(output_path)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(json_str, encoding="utf-8")

        return json_str

    def generate_markdown(self, vulnerabilities: List[VulnerabilityInfo], output_path: str = None, ai_summary: str = None) -> str:
        """Gera relatório completo e legível em formato Markdown."""
        counts = self.count_by_severity(vulnerabilities)

        md = []
        md.append("# 🛡️ TeXuGo-GuardIA - Relatório de Auditoria e Vulnerabilidades\n")
        md.append(f"- **Alvo Analisado:** `{self.target_name}`")
        md.append(f"- **Tipo de Auditoria:** {self.scan_type}")
        md.append(f"- **Data da Execução:** {self.timestamp}")
        md.append(f"- **Total de Apontamentos:** {len(vulnerabilities)}\n")

        md.append("## 📊 Resumo Executivo de Severidades\n")
        md.append("| Severidade | Quantidade | Status de Risco |")
        md.append("| :--- | :---: | :--- |")
        md.append(f"| 🔴 **CRÍTICA** | **{counts['CRÍTICA']}** | Requer correção imediata |")
        md.append(f"| 🟠 **ALTA** | **{counts['ALTA']}** | Alta prioridade no backlog |")
        md.append(f"| 🟡 **MÉDIA** | **{counts['MÉDIA']}** | Mitigar em ciclo regular |")
        md.append(f"| 🟢 **BAIXA** | **{counts['BAIXA']}** | Melhoria de segurança preventiva |")
        md.append(f"| 🔵 **INFORMATIVA** | **{counts['INFORMATIVA']}** | Observação de superfície |")
        md.append("")

        if ai_summary:
            md.append("## 🤖 Parecer e Análise do Agente Inteligente TeXuGo-GuardIA\n")
            md.append(f"{ai_summary}\n")

        md.append("## 🔍 Detalhamento das Vulnerabilidades\n")
        if not vulnerabilities:
            md.append("✅ *Nenhuma vulnerabilidade foi identificada pelos padrões avaliados.* Conforme boas práticas, continue mantendo atualizações regulares.")
        else:
            for idx, v in enumerate(vulnerabilities, start=1):
                md.append(f"### {idx}. [{v.severity}] {v.title}")
                md.append(f"- **Identificador:** `{v.id}` | **CWE:** `{v.cwe}` | **OWASP:** `{v.category}`")
                if v.target:
                    md.append(f"- **Alvo / Endpoint:** `{v.target}`")
                if v.file_path:
                    loc = f"`{v.file_path}`"
                    if v.line_number:
                        loc += f" (Linha {v.line_number})"
                    md.append(f"- **Localização:** {loc}")
                if v.code_snippet:
                    md.append("```")
                    md.append(v.code_snippet)
                    md.append("```")
                md.append(f"- **Descrição:** {v.description}")
                md.append(f"- **Impacto Potencial:** {v.impact}")
                md.append(f"- **Plano de Remediação:** {v.remediation}\n")

        md.append("---\n*Relatório gerado automaticamente pelo TeXuGo-GuardIA - Agente Inteligente de Cibersegurança.*")

        full_md = "\n".join(md)
        if output_path:
            out_file = Path(output_path)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(full_md, encoding="utf-8")

        return full_md

    def print_terminal_summary(self, vulnerabilities: List[VulnerabilityInfo], ai_summary: str = None) -> None:
        """Exibe resumo visual estilizado no terminal."""
        counts = self.count_by_severity(vulnerabilities)

        if RICH_AVAILABLE:
            console = Console()
            console.print("\n")
            console.rule("[bold cyan]🛡️ TeXuGo-GuardIA - Relatório Consolidado[/bold cyan]")

            table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
            table.add_column("Severidade", style="bold", width=15)
            table.add_column("Total", justify="center", width=10)
            table.add_column("Ação Recomendada", style="dim")

            table.add_row("[bold red]CRÍTICA[/bold red]", str(counts["CRÍTICA"]), "Correção emergencial imediata")
            table.add_row("[bold yellow]ALTA[/bold yellow]", str(counts["ALTA"]), "Mitigar prioritariamente")
            table.add_row("[yellow]MÉDIA[/yellow]", str(counts["MÉDIA"]), "Planejar remediação na sprint")
            table.add_row("[green]BAIXA[/green]", str(counts["BAIXA"]), "Reforço defensivo")
            table.add_row("[blue]INFORMATIVA[/blue]", str(counts["INFORMATIVA"]), "Registro de inventário")

            console.print(table)

            if ai_summary:
                console.print(Panel(ai_summary, title="[bold green]🤖 Parecer do Agente TeXuGo-GuardIA[/bold green]", border_style="cyan"))

            if vulnerabilities:
                console.print("\n[bold underline]Principais Apontamentos Detectados:[/bold underline]")
                for v in vulnerabilities[:10]:
                    color = "red" if v.severity in ["CRÍTICA", "ALTA"] else "yellow" if v.severity == "MÉDIA" else "cyan"
                    loc = f" ({v.file_path}:{v.line_number})" if v.file_path else f" ({v.target})" if v.target else ""
                    console.print(f" • [{color}][{v.severity}][/{color}] [bold]{v.title}[/bold]{loc}")
                if len(vulnerabilities) > 10:
                    console.print(f" ... e mais {len(vulnerabilities) - 10} apontamentos registrados no relatório completo.")
            console.print("\n")
        else:
            print("\n================== RESUMO TEXUGO-GUARDIA ==================")
            print(f"Alvo: {self.target_name} ({self.scan_type})")
            for sev, cnt in counts.items():
                print(f"[{sev}]: {cnt}")
            if ai_summary:
                print(f"\nParecer da IA:\n{ai_summary}")
            print("====================================================\n")
