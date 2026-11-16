#!/usr/bin/env python3
"""
TeXuGo-GuardIA - Agente Inteligente para Cibersegurança e Análise de Vulnerabilidades.

Ponto de entrada principal da aplicação (CLI interativo e linha de comando).
Fornece suporte unificado a varreduras SAST de código, auditoria web de cabeçalhos
e mapeamento de superfície de rede com modelos de IA generativa e heurística offline.
"""

import argparse
import glob
from pathlib import Path
import re
import sys

# Auto-detecta dependências em .venv se executado diretamente via 'python3 main.py'
_base_dir = Path(__file__).resolve().parent
_venv_pkgs = glob.glob(str(_base_dir / ".venv/lib/python*/site-packages"))
if _venv_pkgs and _venv_pkgs[0] not in sys.path:
    sys.path.insert(0, _venv_pkgs[0])

if str(_base_dir) not in sys.path:
    sys.path.insert(0, str(_base_dir))

from typing import Any, Callable, Dict, List, Optional, Tuple

from TeXGuardIA.agent import TeXGuardIAAgent, GuardAIAgent, TeXuGoGuardIA, AGENT_PERSONAS
from TeXGuardIA.config import settings
from TeXGuardIA.reporters.report_generator import ReportGenerator
from TeXGuardIA.ui import (
    console_print,
    console_rule,
    console_panel,
    console_table,
    console_prompt,
    clear_screen,
    console_spinner,
    strip_markup,
    RICH_AVAILABLE,
)
from TeXGuardIA.utils.security import (
    sanitize_filename_target,
    validate_port,
    validate_port_list,
)
from TeXGuardIA.utils.model_fetcher import (
    fetch_openrouter_models_resilient,
    fetch_alibaba_models_resilient,
    fetch_gemini_models_resilient,
)
from TeXGuardIA.utils.executor import (
    execute_system_command,
    extract_executable_commands,
    KNOWN_SECURITY_TOOLS,
    has_placeholders,
    substitute_placeholders,
    parse_command_selection,
)


BANNER = r"""
  _____   __  __      ____             _____                     _ _____
 |_   _|__\ \/ /_   _/ ___|___        / ____|                   | |_   _|
   | |/ _ \\  /| | | | |  _/ _ \ _____| |  __ _   _  __ _ _ __ __| | | |  
   | |  __//  \| |_| | |_| | (_) |_____| | |_ | | | |/ _` | '__/ _` | | | |  
   |_|\___/_/\_\\__,_|\____|\___/       \_____|\__,_|\__,_|_|  \__,_|_|___|  
     [ TeXuGo-GuardIA • Agente Inteligente de Cibersegurança ]
"""


# =====================================================================
# 1. Cabeçalho e Apresentação do Sistema
# =====================================================================

def show_banner(agent: TeXGuardIAAgent) -> None:
    """Exibe o cabeçalho estilizado do TeXuGo-GuardIA com status atual do ambiente."""
    persona = agent.get_active_persona()
    console_panel(BANNER, border_style="bright_blue")

    if settings.has_ai_credentials:
        model_info = getattr(settings, f"{settings.ai_provider}_model", "padrão")
        status_ai = f"[bold green]Ativa ({settings.ai_provider.upper()} - {model_info})[/bold green]"
    else:
        status_ai = "[bold yellow]Modo Heurístico Offline (sem chave de API configurada)[/bold yellow]"

    console_print(f" • [dim]Engine de IA:[/dim] {status_ai}")
    console_print(f" • [dim]Perfil do Agente:[/dim] [bold magenta]{persona['title']}[/bold magenta]")
    console_print(f" • [dim]Diretório Base:[/dim] [cyan]{settings.base_dir}[/cyan]")
    console_print(f" • [dim]Pasta de Saída Padrão:[/dim] [bold green]{settings.output_dir_name}/[/bold green]\n")


# =====================================================================
# 2. Motor Unificado de Execução de Varreduras (Scan Runner)
# =====================================================================

def run_unified_scan(
    agent: TeXGuardIAAgent,
    scan_type: str,
    target_raw: str,
    analyze_callable: Callable[[], Tuple[List[Any], str]],
    default_prefix: str,
    md_out: Optional[str] = None,
    json_out: Optional[str] = None,
    use_ai: bool = True
) -> None:
    """Executa o fluxo consolidado de análise, relatórios técnicos e persistência de artefatos.

    Extrai o boilerplate comum compartilhado entre SAST, Web e Port Scanners:
      1. Sanitização do identificador do alvo prevenindo path traversal;
      2. Resolução de caminhos seguros dentro de output_dir (relatorios/);
      3. Execução da análise com indicador de progresso (spinner);
      4. Apresentação do resumo tabular executivo;
      5. Geração de relatórios em Markdown e JSON estruturado.
    """
    clean_stem = Path(target_raw).stem if "/" in target_raw else target_raw
    target_clean = sanitize_filename_target(clean_stem)

    default_md = settings.resolve_output_path(md_out, f"{default_prefix}_{target_clean}.md")
    default_json = settings.resolve_output_path(json_out, f"{default_prefix}_{target_clean}.json") if json_out else None

    console_print(f"\n[cyan]🔍 Iniciando auditoria de {scan_type} em:[/cyan] [bold]{target_raw}[/bold]...")

    with console_spinner(f"Analisando {scan_type}..."):
        vulns, summary = analyze_callable()

    reporter = ReportGenerator(target_name=target_raw, scan_type=scan_type)
    reporter.print_terminal_summary(vulns, summary)
    reporter.generate_markdown(vulns, output_path=str(default_md), ai_summary=summary)

    if default_json:
        reporter.generate_json(vulns, output_path=str(default_json))

    console_print(f"📄 [green]Relatório Markdown salvo em:[/green] [bold cyan]{default_md}[/bold cyan]")
    if default_json:
        console_print(f"📊 [green]Relatório JSON salvo em:[/green] [bold cyan]{default_json}[/bold cyan]")
    console_print()


def run_code_scan(agent: TeXGuardIAAgent, path: str, md_out: str = None, json_out: str = None, use_ai: bool = True) -> None:
    """Executa auditoria SAST de código-fonte em arquivo ou diretório."""
    run_unified_scan(
        agent=agent,
        scan_type="SAST de Código-Fonte",
        target_raw=path,
        analyze_callable=lambda: agent.analyze_code(path, use_ai=use_ai),
        default_prefix="relatorio_sast",
        md_out=md_out,
        json_out=json_out,
        use_ai=use_ai
    )


def run_web_scan(agent: TeXGuardIAAgent, url: str, md_out: str = None, json_out: str = None, use_ai: bool = True) -> None:
    """Executa auditoria de cabeçalhos HTTP defensivos e segurança web."""
    run_unified_scan(
        agent=agent,
        scan_type="Superfície Web & Headers",
        target_raw=url,
        analyze_callable=lambda: agent.analyze_web(url, use_ai=use_ai),
        default_prefix="relatorio_web",
        md_out=md_out,
        json_out=json_out,
        use_ai=use_ai
    )


def run_port_scan(agent: TeXGuardIAAgent, host: str, ports: Optional[List[int]] = None, md_out: str = None, json_out: str = None, use_ai: bool = True) -> None:
    """Executa auditoria concorrente de portas e serviços de rede expostos."""
    clean_host = host.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    run_unified_scan(
        agent=agent,
        scan_type="Portas e Serviços de Rede",
        target_raw=clean_host,
        analyze_callable=lambda: agent.analyze_network(clean_host, ports=ports, use_ai=use_ai),
        default_prefix="relatorio_portas",
        md_out=md_out,
        json_out=json_out,
        use_ai=use_ai
    )


# =====================================================================
# 3. Perfis e Seleção Modular de Portas
# =====================================================================

PORT_PROFILES: Dict[str, Dict[str, Any]] = {
    "1": {
        "name": "⚡ Portas Essenciais Rápidas",
        "desc": "21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080",
        "ports": [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080],
    },
    "2": {
        "name": "🌐 Serviços Web & HTTP",
        "desc": "80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000",
        "ports": [80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000],
    },
    "3": {
        "name": "🗄️ Bancos de Dados",
        "desc": "1433-MSSQL, 1521-Oracle, 3306-MySQL, 5432-Postgres, 6379-Redis, 9200-Elastic, 11211-Memcached, 27017-MongoDB",
        "ports": [1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017],
    },
    "4": {
        "name": "🖥️ Acesso Remoto & Administração",
        "desc": "21-FTP, 22-SSH, 23-Telnet, 445-SMB, 3389-RDP, 5900-VNC, 5985-WinRM",
        "ports": [21, 22, 23, 445, 3389, 5900, 5985],
    },
    "5": {
        "name": "🚀 Infraestrutura, DevOps & Mensageria",
        "desc": "25-SMTP, 53-DNS, 110-POP3, 143-IMAP, 161-SNMP, 389-LDAP, 2375-Docker, 5672-RabbitMQ, 9092-Kafka",
        "ports": [25, 53, 110, 143, 161, 389, 2375, 5672, 9092],
    },
}


def display_port_menu(all_ports: List[int]) -> None:
    """Exibe o menu visual estruturado para opções de escaneamento de portas."""
    console_print("\n[bold cyan]Escolha o tipo de varredura de portas e serviços:[/bold cyan]")
    for k, prof in PORT_PROFILES.items():
        console_print(f" [{k}] {prof['name']} [dim]({prof['desc'][:60]}...)[/dim]")
    console_print(f" [6] 🌟 TODOS OS SERVIÇOS (Varredura Completa: Todas as {len(all_ports)} portas dos grupos 1 a 5)")
    console_print(" [7] 🎯 Portas Personalizadas (digite a lista separada por vírgula)")
    console_print(" [8] 🔢 Range Numérico de Portas (ex: 20-1024)")
    console_print("\n[dim]💡 Dica: Você pode digitar [bold]6[/bold] para todos ou combinar números como [bold]1,2,3,4[/bold]![/dim]")


def prompt_custom_ports() -> Tuple[List[int], str]:
    """Solicita e valida portas personalizadas com validação estrita (1-65535)."""
    while True:
        raw = console_prompt("Digite as portas separadas por vírgula (ex: 80,443,8080)", default="80,443")
        valid, invalid = validate_port_list(raw)
        if invalid:
            console_print(f"[yellow]⚠️ Entradas inválidas ou fora do range (1-65535) ignoradas: {', '.join(invalid)}[/yellow]")
        if valid:
            return valid, f"Personalizado ({len(valid)} portas)"
        console_print("[red]❌ Nenhuma porta válida foi inserida. Tente novamente.[/red]")


def prompt_port_range() -> Tuple[List[int], str]:
    """Solicita e valida um range contínuo de portas dentro dos limites TCP/UDP."""
    while True:
        raw = console_prompt("Digite o range de portas (ex: 20-100)", default="1-100")
        try:
            parts = [x.strip() for x in raw.split("-") if x.strip()]
            if len(parts) == 2:
                start_p, end_p = int(parts[0]), int(parts[1])
                start_p = max(1, min(start_p, 65535))
                end_p = max(1, min(end_p, 65535))
                if start_p > end_p:
                    start_p, end_p = end_p, start_p
                # Limite máximo de segurança para varredura por socket
                if (end_p - start_p) > 2000:
                    console_print("[yellow]⚠️ Ranges maiores que 2000 portas podem demorar excessivamente. Limitando a 2000 portas.[/yellow]")
                    end_p = start_p + 2000
                ports = list(range(start_p, end_p + 1))
                return ports, f"Range {start_p}-{end_p} ({len(ports)} portas)"
        except Exception:
            pass
        console_print("[red]❌ Formato de range inválido. Utilize o formato 'inicio-fim' (ex: 80-100).[/red]")


def parse_port_selection(raw_choice: str, all_ports: List[int]) -> Tuple[List[int], str]:
    """Processa a seleção digitada pelo usuário, suportando multi-seleção combinada."""
    clean_input = raw_choice.strip().upper()

    # Todos os serviços
    if clean_input in ["6", "T", "TODOS", "ALL", "A", "*"]:
        return all_ports, f"Todos os Serviços ({len(all_ports)} portas)"

    # Personalizadas
    if clean_input == "7":
        return prompt_custom_ports()

    # Range
    if clean_input == "8":
        return prompt_port_range()

    # Multi-seleção combinada (ex: "1,2,3,4")
    parts = [p.strip() for p in re.split(r"[,;+\s]+", clean_input) if p.strip()]
    combined_ports: List[int] = []
    category_names: List[str] = []

    for p in parts:
        if p in PORT_PROFILES:
            combined_ports.extend(PORT_PROFILES[p]["ports"])
            category_names.append(PORT_PROFILES[p]["name"].split()[1])
        elif p.isdigit():
            valid_p = validate_port(p)
            if valid_p:
                combined_ports.append(valid_p)
                category_names.append(f"P:{valid_p}")

    if combined_ports:
        unique_ports = sorted(list(set(combined_ports)))
        label = f"Combinado ({', '.join(category_names)})" if category_names else "Serviços Selecionados"
        return unique_ports, label

    return all_ports, f"Todos os Serviços ({len(all_ports)} portas)"


def select_port_profile() -> Tuple[List[int], str]:
    """Orquestra o menu modular de seleção e combinação de perfis de portas."""
    all_ports = sorted(list(set(p for prof in PORT_PROFILES.values() for p in prof["ports"])))
    display_port_menu(all_ports)
    raw_choice = console_prompt("\n[bold yellow]Selecione uma opção (ou combine ex: 1,2,3,4)[/bold yellow]", default="6")
    return parse_port_selection(raw_choice, all_ports)


# =====================================================================
# 4. Catálogos Dinâmicos de Modelos de IA
# =====================================================================

def browse_openrouter_models() -> Optional[str]:
    """Interface de busca, catálogo e seleção dinâmica de modelos no OpenRouter."""
    with console_spinner("Carregando catálogo de modelos do OpenRouter (com cache local)..."):
        models = fetch_openrouter_models_resilient(force_refresh=False)

    if not models:
        console_print("[yellow]⚠️ Não foi possível carregar a lista remota em tempo real. Digite o nome manualmente.[/yellow]")
        return console_prompt("Model ID")

    while True:
        console_rule("Catálogo Dinâmico de Modelos (OpenRouter)")
        console_print(" [1] 🌟 Listar Modelos 100% Gratuitos Ativos (:free)")
        console_print(" [2] 🔎 Pesquisar Modelos por Palavra (ex: north, grok, llama, deepseek, gemini, qwen)")
        console_print(" [3] 🔄 Forçar Atualização do Catálogo Remoto (Limpar Cache)")
        console_print(" [4] ⌨️  Digitar ID Manualmente (com Autocomplete via TAB)")
        console_print(" [0] 🔙 Cancelar / Manter Atual")

        sub = console_prompt("\n[bold yellow]Selecione uma opção[/bold yellow]", choices=["1", "2", "3", "4", "0"], default="1")

        if sub == "1":
            free_models = [
                m for m in models
                if m.get("id", "").endswith(":free") or float(m.get("pricing", {}).get("prompt", 1)) == 0
            ]
            if not free_models:
                free_models = [{"id": "cohere/north-mini-code:free", "name": "Cohere: North Mini Code (free)"}]

            table_rows = []
            for idx, m in enumerate(free_models, 1):
                name = m.get("name", m.get("id", ""))[:45]
                table_rows.append([str(idx), m.get("id", ""), name])

            console_table(
                headers=["#", "Model ID (Exato)", "Descrição / Nome"],
                rows=table_rows,
                title="Modelos 100% Gratuitos Disponíveis no OpenRouter"
            )

            choice_str = console_prompt("\n[bold yellow]Digite o número do modelo desejado (ou 0 para cancelar)[/bold yellow]", default="1")
            if choice_str.isdigit() and 1 <= int(choice_str) <= len(free_models):
                return free_models[int(choice_str) - 1]["id"]

        elif sub == "2":
            term = console_prompt("\n[bold yellow]Digite o termo de busca (ex: north, coder, grok, llama, gemini, deepseek, qwen)[/bold yellow]").strip().lower()
            if not term:
                continue

            matches = [
                m for m in models
                if term in m.get("id", "").lower() or term in m.get("name", "").lower()
            ]

            if not matches:
                console_print(f"[bold red]Nenhum modelo encontrado contendo '{term}'.[/bold red]")
                continue

            matches = matches[:25]
            table_rows = []
            for idx, m in enumerate(matches, 1):
                is_free = m.get("id", "").endswith(":free") or float(m.get("pricing", {}).get("prompt", 1)) == 0
                price_badge = "[bold green]GRATUITO (:free)[/bold green]" if is_free else "[yellow]Pago por Token[/yellow]"
                table_rows.append([str(idx), m.get("id", ""), price_badge])

            console_table(
                headers=["#", "Model ID", "Categoria de Preço"],
                rows=table_rows,
                title=f"Resultados para '{term}'"
            )

            choice_str = console_prompt("\n[bold yellow]Digite o número do modelo escolhido (ou 0 para cancelar)[/bold yellow]", default="1")
            if choice_str.isdigit() and 1 <= int(choice_str) <= len(matches):
                return matches[int(choice_str) - 1]["id"]

        elif sub == "3":
            with console_spinner("Atualizando catálogo do OpenRouter diretamente da API..."):
                models = fetch_openrouter_models_resilient(force_refresh=True)
            console_print(f"✅ Catálogo atualizado com sucesso! ({len(models)} modelos carregados)")

        elif sub == "4":
            try:
                import readline
                all_ids = [m.get("id", "") for m in models if m.get("id")]

                def completer(text, state):
                    options = [i for i in all_ids if text.lower() in i.lower()]
                    return options[state] if state < len(options) else None

                readline.set_completer_delims(" \t\n")
                readline.parse_and_bind("tab: complete")
                readline.set_completer(completer)
            except Exception:
                pass

            console_print("\n[dim]Dica: Digite parte do nome e aperte [bold]TAB[/bold] para autocompletar.[/dim]")
            typed = console_prompt("Model ID")
            if typed.strip():
                return typed.strip()

        elif sub == "0":
            return None

    return None


def browse_alibaba_models(agent: TeXGuardIAAgent) -> Optional[str]:
    """Interface dinâmica de busca e seleção de modelos do Alibaba Model Studio."""
    with console_spinner("Consultando catálogo da sua conta Alibaba..."):
        models = fetch_alibaba_models_resilient(agent)

    confirmed_free = [
        ("qwen-flash-character", "⚡ 1M Tokens Grátis Ativos (Super Rápido / Baixa Latência)"),
        ("qwen-plus-character", "🌟 1M Tokens Grátis Ativos (Model Studio)"),
        ("qwen-plus", "Qwen Plus (Requer ativação no Console)"),
        ("qwen-turbo", "Qwen Turbo (Econômico)"),
        ("qwen3.8-flash", "Nova Geração Qwen 3.8 Flash"),
        ("kimi-k3", "Modelo Kimi K3 (Disponível via DashScope)"),
        ("deepseek-v4.1-flash", "DeepSeek v4.1 Flash (Disponível via DashScope)"),
    ]

    while True:
        console_rule("Catálogo Dinâmico de Modelos (Alibaba Model Studio)")
        console_print(" [1] 🌟 Modelos com Cota Gratuita Ativa (qwen-flash-character, qwen-plus-character)")
        console_print(f" [2] 📋 Listar Todos os Modelos da Sua Conta ({len(models)} modelos detectados)")
        console_print(" [3] 🔎 Pesquisar Modelos por Palavra (ex: character, flash, plus, coder, deepseek)")
        console_print(" [4] ⌨️  Digitar Model ID Manualmente")
        console_print(" [0] 🔙 Cancelar / Manter Atual")

        sub = console_prompt("\n[bold yellow]Selecione uma opção[/bold yellow]", choices=["1", "2", "3", "4", "0"], default="1")

        if sub == "1":
            table_rows = [[str(idx), m_id, desc] for idx, (m_id, desc) in enumerate(confirmed_free, 1)]
            console_table(
                headers=["#", "Model ID", "Status / Detalhes"],
                rows=table_rows,
                title="Modelos Recomendados Alibaba Model Studio"
            )
            choice = console_prompt("Número do modelo desejado (ou 0 para cancelar)", default="1")
            if choice.isdigit() and 1 <= int(choice) <= len(confirmed_free):
                return confirmed_free[int(choice) - 1][0]

        elif sub == "2":
            table_rows = [[str(idx), m] for idx, m in enumerate(models, 1)]
            console_table(headers=["#", "Model ID"], rows=table_rows[:40], title="Modelos da Conta Alibaba")
            choice = console_prompt("Número do modelo desejado (ou 0 para cancelar)", default="1")
            if choice.isdigit() and 1 <= int(choice) <= len(models):
                return models[int(choice) - 1]

        elif sub == "3":
            term = console_prompt("Digite o termo de busca").strip().lower()
            if not term:
                continue
            matches = [m for m in models if term in m.lower()]
            if not matches:
                console_print(f"[bold red]Nenhum modelo encontrado contendo '{term}'.[/bold red]")
                continue
            table_rows = [[str(idx), m] for idx, m in enumerate(matches[:25], 1)]
            console_table(headers=["#", "Model ID"], rows=table_rows, title=f"Resultados para '{term}'")
            choice = console_prompt("Número do modelo escolhido", default="1")
            if choice.isdigit() and 1 <= int(choice) <= len(matches):
                return matches[int(choice) - 1]

        elif sub == "4":
            typed = console_prompt("Model ID")
            if typed.strip():
                return typed.strip()

        elif sub == "0":
            return None

    return None


def browse_gemini_models(agent: TeXGuardIAAgent) -> Optional[str]:
    """Interface dinâmica de busca e catálogo de modelos do Google Gemini."""
    with console_spinner("Consultando modelos disponíveis no Google Gemini..."):
        models = fetch_gemini_models_resilient(getattr(settings, "gemini_api_key", ""))

    recommended = [
        ("gemini-1.5-flash", "⚡ Mais Rápido & Econômico (Recomendado / Cota Gratuita Alta)"),
        ("gemini-1.5-pro", "🧠 Raciocínio Profundo & Análise Complexa de Vulnerabilidades"),
        ("gemini-2.0-flash", "🚀 Nova Geração 2.0 (Super Rápido & Multimodal)"),
        ("gemini-2.0-flash-lite", "🪶 Ultraleve & Baixíssima Latência"),
        ("gemini-1.5-flash-8b", "📦 Modelo Compacto para Tarefas Rápidas"),
    ]

    while True:
        console_rule("Catálogo Dinâmico de Modelos (Google Gemini)")
        console_print(" [1] 🌟 Modelos Recomendados (gemini-1.5-flash, gemini-2.0-flash, gemini-1.5-pro)")
        console_print(f" [2] 📋 Listar Todos os Modelos da API ({len(models)} modelos detectados)")
        console_print(" [3] 🔎 Pesquisar Modelos por Palavra (ex: flash, pro, 2.0, exp)")
        console_print(" [4] ⌨️  Digitar Model ID Manualmente")
        console_print(" [0] 🔙 Cancelar / Manter Atual")

        sub = console_prompt("\n[bold yellow]Selecione uma opção[/bold yellow]", choices=["1", "2", "3", "4", "0"], default="1")

        if sub == "1":
            table_rows = [[str(idx), m_id, desc] for idx, (m_id, desc) in enumerate(recommended, 1)]
            console_table(
                headers=["#", "Model ID", "Descrição / Destaque"],
                rows=table_rows,
                title="Modelos Recomendados Google Gemini"
            )
            choice = console_prompt("Número do modelo desejado (ou 0 para cancelar)", default="1")
            if choice.isdigit() and 1 <= int(choice) <= len(recommended):
                return recommended[int(choice) - 1][0]

        elif sub == "2":
            table_rows = [[str(idx), m[0], m[1]] for idx, m in enumerate(models, 1)]
            console_table(headers=["#", "Model ID", "Display Name / Info"], rows=table_rows[:35], title="Modelos da API Google Gemini")
            choice = console_prompt("Número do modelo desejado (ou 0 para cancelar)", default="1")
            if choice.isdigit() and 1 <= int(choice) <= len(models):
                return models[int(choice) - 1][0]

        elif sub == "3":
            term = console_prompt("Digite o termo de busca (ex: flash, pro, 2.0)").strip().lower()
            if not term:
                continue
            matches = [m for m in models if term in m[0].lower() or term in m[1].lower()]
            if not matches:
                console_print(f"[bold red]Nenhum modelo encontrado contendo '{term}'.[/bold red]")
                continue
            table_rows = [[str(idx), m[0], m[1]] for idx, m in enumerate(matches[:25], 1)]
            console_table(headers=["#", "Model ID", "Display Name / Info"], rows=table_rows, title=f"Resultados para '{term}'")
            choice = console_prompt("Número do modelo escolhido", default="1")
            if choice.isdigit() and 1 <= int(choice) <= len(matches):
                return matches[int(choice) - 1][0]

        elif sub == "4":
            typed = console_prompt("Model ID (ex: gemini-1.5-flash, gemini-2.0-flash)")
            if typed.strip():
                return typed.strip()

        elif sub == "0":
            return None

    return None



# =====================================================================
# 5. Configurações de APIs e Chaves
# =====================================================================

def api_settings_menu(agent: TeXGuardIAAgent) -> None:
    """Menu para gerenciar, testar e salvar configurações de IA."""
    while True:
        console_rule("Configurações de APIs & Provedores de IA")
        console_print(f" Provedor Ativo: [bold green]{settings.ai_provider.upper()}[/bold green]")
        model_name = getattr(settings, f"{settings.ai_provider}_model", "N/A")
        console_print(f" Modelo Ativo:   [bold cyan]{model_name}[/bold cyan]")
        base_url = getattr(settings, f"{settings.ai_provider}_base_url", "")
        if base_url:
            console_print(f" Endpoint URL:   [dim]{base_url}[/dim]")
        curr_key = getattr(settings, f"{settings.ai_provider}_api_key", "")
        if curr_key and curr_key.strip():
            masked = curr_key[:6] + "••••••••" + curr_key[-4:] if len(curr_key) > 12 else "••••••"
            key_display = f"✅ Configurada ([bold green]{masked}[/bold green] | {len(curr_key)} caracteres)"
        else:
            key_display = "❌ [red]Ausente / Não informada[/red]"
        console_print(f" Chave de API:   {key_display}\n")

        console_print(" [1] 🧪 Testar Conexão com a API Atual")
        console_print(" [2] 🔄 Trocar Provedor (OpenRouter, Alibaba, SpaceXAI, OpenCode, Gemini, OpenAI, Offline)")
        console_print(" [3] 🔑 Informar / Alterar Chave de API (com entrada mascarada)")
        console_print(" [4] 🤖 Selecionar Modelo (Model ID)")
        console_print(" [5] 🌐 Alternar Endpoint / Região (ex: Internacional vs China)")
        console_print(" [6] 💾 Salvar Configurações no Arquivo .env")
        console_print(" [0] 🔙 Voltar ao Menu Principal")

        choice = console_prompt("\n[bold yellow]Selecione uma opção[/bold yellow]", choices=["1", "2", "3", "4", "5", "6", "0"], default="1")

        if choice == "1":
            console_print("\n[cyan]Enviando teste de conectividade para o provedor...[/cyan]")
            with console_spinner("Testando conexão com a API..."):
                success, msg = agent.test_connection()
            if success:
                console_panel(f"✅ {msg}", title="[bold green]Sucesso na Conexão[/bold green]", border_style="green")
            else:
                console_panel(f"❌ {msg}", title="[bold red]Falha na Conexão[/bold red]", border_style="red")

        elif choice == "2":
            console_print("\nEscolha o provedor de IA:")
            console_print(" [1] OpenRouter (Free / Multi-modelos - ex: Cohere North Mini Code)")
            console_print(" [2] Alibaba Cloud Model Studio (Qwen / DashScope)")
            console_print(" [3] SpaceXAI / xAI (Grok)")
            console_print(" [4] OpenCode (Inference Gratuita)")
            console_print(" [5] Google Gemini")
            console_print(" [6] OpenAI Oficial")
            console_print(" [7] Offline (Heurístico Local Sem API)")
            p_opt = console_prompt("Provedor", choices=["1", "2", "3", "4", "5", "6", "7"], default="1")

            providers_map = {
                "1": "openrouter",
                "2": "alibaba",
                "3": "spacexai",
                "4": "opencode",
                "5": "gemini",
                "6": "openai",
                "7": "offline"
            }
            settings.ai_provider = providers_map.get(p_opt, "openrouter")
            agent.reload_config()
            console_print(f"✅ Provedor alterado para: [bold green]{settings.ai_provider.upper()}[/bold green]")

        elif choice == "3":
            console_print(f"\n[cyan]🔑 Digite ou cole a chave de API para [bold]{settings.ai_provider.upper()}[/bold]:[/cyan]")
            console_print("[dim](A chave não será exibida no terminal para proteção de credenciais)[/dim]")
            new_key = console_prompt("Chave de API", password=True)
            if new_key:
                setattr(settings, f"{settings.ai_provider}_api_key", new_key)
                agent.reload_config()
                masked = new_key[:6] + "••••••••" + new_key[-4:] if len(new_key) > 12 else "••••••"
                console_print(f"✅ [bold green]Chave recebida com sucesso![/bold green] ({masked} | {len(new_key)} caracteres)")
                console_print("[yellow]💡 Lembre-se de salvar permanentemente no arquivo .env na opção [6].[/yellow]")
            else:
                console_print("[yellow]⚠️ Nenhuma chave informada. O valor anterior foi preservado.[/yellow]")

        elif choice == "4":
            if settings.ai_provider == "openrouter":
                chosen = browse_openrouter_models()
                if chosen:
                    settings.openrouter_model = chosen
                    agent.reload_config()
                    console_print(f"\n✅ Modelo OpenRouter definido para: [bold green]{chosen}[/bold green]")
            elif settings.ai_provider in ["alibaba", "dashscope"]:
                chosen = browse_alibaba_models(agent)
                if chosen:
                    settings.alibaba_model = chosen
                    agent.reload_config()
                    console_print(f"\n✅ Modelo Alibaba definido para: [bold green]{chosen}[/bold green]")
            elif settings.ai_provider in ["spacexai", "xai"]:
                console_print("\nModelos SpaceXAI / xAI:")
                console_print(" [1] grok-2")
                console_print(" [2] grok-beta")
                console_print(" [3] grok-vision-beta")
                console_print(" [4] Digitar outro")
                opt_sx = console_prompt("Opção", choices=["1", "2", "3", "4"], default="1")
                sx_map = {"1": "grok-2", "2": "grok-beta", "3": "grok-vision-beta"}
                settings.spacexai_model = sx_map.get(opt_sx, console_prompt("Nome do modelo SpaceXAI", default="grok-2"))
                agent.reload_config()
                console_print(f"✅ Modelo SpaceXAI definido para: [bold green]{settings.spacexai_model}[/bold green]")
            elif settings.ai_provider == "opencode":
                console_print("\nModelos OpenCode:")
                console_print(" [1] meta-llama/llama-3.1-8b-instruct")
                console_print(" [2] mistralai/mistral-7b-instruct")
                console_print(" [3] qwen/qwen-2.5-coder-32b")
                console_print(" [4] Digitar outro")
                opt_oc = console_prompt("Opção", choices=["1", "2", "3", "4"], default="1")
                oc_map = {
                    "1": "meta-llama/llama-3.1-8b-instruct",
                    "2": "mistralai/mistral-7b-instruct",
                    "3": "qwen/qwen-2.5-coder-32b"
                }
                settings.opencode_model = oc_map.get(opt_oc, console_prompt("Nome do modelo", default="meta-llama/llama-3.1-8b-instruct"))
                agent.reload_config()
                console_print(f"✅ Modelo OpenCode definido para: [bold green]{settings.opencode_model}[/bold green]")
            elif settings.ai_provider == "gemini":
                chosen = browse_gemini_models(agent)
                if chosen:
                    settings.gemini_model = chosen
                    agent.reload_config()
                    console_print(f"\n✅ Modelo Google Gemini definido para: [bold green]{chosen}[/bold green]")
            elif settings.ai_provider == "openai":
                console_print("\nModelos OpenAI:")
                console_print(" [1] gpt-4o-mini (Econômico / Rápido)")
                console_print(" [2] gpt-4o (Avançado)")
                console_print(" [3] o1-mini (Raciocínio Rápido)")
                console_print(" [4] o3-mini (Raciocínio Avançado)")
                console_print(" [5] Digitar outro")
                opt_oa = console_prompt("Opção", choices=["1", "2", "3", "4", "5"], default="1")
                oa_map = {
                    "1": "gpt-4o-mini",
                    "2": "gpt-4o",
                    "3": "o1-mini",
                    "4": "o3-mini"
                }
                settings.openai_model = oa_map.get(opt_oa, console_prompt("Nome do modelo OpenAI", default="gpt-4o-mini"))
                agent.reload_config()
                console_print(f"✅ Modelo OpenAI definido para: [bold green]{settings.openai_model}[/bold green]")
            else:
                custom = console_prompt(f"Nome do modelo para {settings.ai_provider}")
                if custom.strip():
                    setattr(settings, f"{settings.ai_provider}_model", custom.strip())
                agent.reload_config()
                console_print(f"✅ Modelo atualizado com sucesso!")

        elif choice == "5":
            current_url = getattr(settings, f"{settings.ai_provider}_base_url", "")
            if settings.ai_provider in ["alibaba", "dashscope"]:
                console_print(f"\n[cyan]Endpoint atual: [bold]{current_url}[/bold][/cyan]")
                console_print("Escolha a região do Alibaba Model Studio:")
                console_print(" [1] 🌏 Internacional / Singapura: https://dashscope-intl.aliyuncs.com/compatible-mode/v1")
                console_print(" [2] 🇨🇳 China Continental:        https://dashscope.aliyuncs.com/compatible-mode/v1")
                console_print(" [3] ✏️  Digitar URL Customizada")
                ep = console_prompt("Opção", choices=["1", "2", "3"], default="1")
                if ep == "1":
                    settings.alibaba_base_url = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
                elif ep == "2":
                    settings.alibaba_base_url = "https://dashscope.aliyuncs.com/compatible-mode/v1"
                else:
                    settings.alibaba_base_url = console_prompt("URL do Endpoint", default=settings.alibaba_base_url)
                agent.reload_config()
                console_print(f"✅ Endpoint Alibaba atualizado para: [bold green]{settings.alibaba_base_url}[/bold green]")
            else:
                custom = console_prompt(f"URL do Endpoint para {settings.ai_provider.upper()}", default=current_url)
                if custom.strip():
                    setattr(settings, f"{settings.ai_provider}_base_url", custom.strip())
                    agent.reload_config()
                    console_print(f"✅ Endpoint atualizado para: [bold green]{custom.strip()}[/bold green]")

        elif choice == "6":
            settings.save_to_env()
            console_print(f"💾 [bold green]Configurações salvas permanentemente no arquivo .env![/bold green]")

        elif choice == "0":
            break


# =====================================================================
# 6. Dicionário e Perfis de Atuação do Agente
# =====================================================================

def show_persona_dictionary() -> None:
    """Exibe um guia completo sobre as capacidades, comandos e ferramentas de cada persona."""
    console_rule("Dicionário & Guia de Perfis do TeXuGo-GuardIA")
    colors = {
        "appsec": "green",
        "redteam": "red",
        "blueteam": "blue",
        "compliance": "magenta"
    }
    for k, p in AGENT_PERSONAS.items():
        color = colors.get(k, "cyan")
        can_req_txt = "\n".join([f"  • {item}" for item in p.get("can_request", [])])
        sample_cmd_txt = "\n".join([f"  [yellow]$ {cmd}[/yellow]" for cmd in p.get("sample_commands", [])])
        content = (
            f"[bold]🎯 Missão:[/bold] {p.get('mission', p['description'])}\n\n"
            f"[bold]💡 O que você pode solicitar ao agente:[/bold]\n{can_req_txt}\n\n"
            f"[bold]🛠️ Programas e Ferramentas recomendadas:[/bold]\n"
            f"  [cyan]{', '.join(p.get('programs', []))}[/cyan]\n\n"
            f"[bold]⌨️ Comandos Típicos que domina e orienta:[/bold]\n{sample_cmd_txt}"
        )
        console_panel(content, title=f"Perfil: {p['title']}", border_style=color)


def agent_persona_menu(agent: TeXGuardIAAgent) -> None:
    """Menu interativo para alternar entre diferentes personas e visualizar capacidades."""
    while True:
        console_rule("Configurar Perfil do Agente")
        console_print("Escolha o perfil de atuação para as análises, relatórios e o chat interativo:\n")

        table_rows = []
        for idx, (k, p) in enumerate(AGENT_PERSONAS.items(), 1):
            ativo = " [bold green](Ativo)[/bold green]" if k == agent.current_persona_key else ""
            progs = ", ".join(p.get("programs", [])[:4])
            table_rows.append([str(idx), f"{p['title']}{ativo}", p.get("mission", p["description"])[:75] + "...", progs])

        console_table(
            headers=["Opção", "Perfil", "Missão & Especialidade", "Ferramentas"],
            rows=table_rows,
            title="Perfis Disponíveis no TeXuGo-GuardIA"
        )

        console_print(" [D] 📖 Ver Dicionário Completo de Capacidades (O que pedir, comandos e ferramentas)")
        console_print(" [0] 🔙 Voltar ao Menu Principal")
        opt = console_prompt("\n[bold yellow]Selecione uma opção[/bold yellow]", choices=["1", "2", "3", "4", "D", "d", "0"], default="1")

        if opt.upper() == "D":
            show_persona_dictionary()
            console_prompt("\n[dim]Pressione Enter para voltar à seleção de perfis...[/dim]")
            continue

        keys = list(AGENT_PERSONAS.keys())
        if opt in ["1", "2", "3", "4"]:
            chosen_key = keys[int(opt) - 1]
            agent.set_persona(chosen_key)
            persona = agent.get_active_persona()
            console_print(f"\n✅ Perfil ativo alterado para: [bold green]{persona['title']}[/bold green]\n")
            break
        elif opt == "0":
            break


# =====================================================================
# 7. Consultor Interativo (Chat com Salvamento Automático & Execução em Fila)
# =====================================================================

def run_command_batch(
    chosen_cmds: List[str],
    agent: TeXGuardIAAgent,
    default_target: str = "10.23.30.149"
) -> Tuple[str, str]:
    """Executa uma lista de comandos selecionados pelo usuário com resolução de placeholders."""
    if not chosen_cmds:
        return "", ""

    target_ip = default_target
    if any(has_placeholders(c) for c in chosen_cmds):
        prompt_target = console_prompt(
            "🎯 Os comandos contêm marcadores (<TARGET>/<ALVO>). Digite o IP ou alvo",
            default=target_ip
        )
        if prompt_target.strip():
            target_ip = prompt_target.strip()

    combined_outputs: List[str] = []
    total = len(chosen_cmds)
    for step_num, orig_cmd in enumerate(chosen_cmds, 1):
        final_cmd = substitute_placeholders(orig_cmd, target_ip)
        if total > 1:
            console_rule(f"Executando [{step_num}/{total}]: {final_cmd}")
        exit_code, cmd_output = execute_system_command(final_cmd, agent=agent)
        combined_outputs.append(
            f"### Execução [{step_num}/{total}]: `{final_cmd}` (Código de Saída: {exit_code})\n```\n{cmd_output.strip()}\n```"
        )
        if exit_code == 130 and step_num < total:
            stop_queue = console_prompt("Deseja interromper os próximos comandos da fila? [S/n]", default="s")
            if stop_queue.lower().startswith("s"):
                break

    all_output_text = "\n\n".join(combined_outputs)
    diag_result = ""
    if any(out.strip() for out in combined_outputs):
        ask_diag = console_prompt("🤖 Deseja que o TeXuGo-GuardIA analise o resultado consolidado dessas execuções? [S/n]", default="s")
        if ask_diag.lower().startswith("s"):
            diag_prompt = (
                f"Analise criticamente as evidências técnicas retornadas pela execução dos comandos:\n\n"
                f"{all_output_text[:4000]}\n\n"
                f"Quais vulnerabilidades, portas abertas ou achados de segurança foram detectados e quais as recomendações imediatas?"
            )
            console_print("\n[cyan]Consultando IA para diagnóstico das evidências coletadas...[/cyan]")
            with console_spinner("TeXuGo-GuardIA analisando evidências consolidadas..."):
                diag_result = agent.chat_security_consultant(diag_prompt)
            console_panel(diag_result, title="TeXuGo-GuardIA - Diagnóstico Consolidado da Execução", border_style="green")

    return all_output_text, diag_result


def run_interactive_consultant(agent: TeXGuardIAAgent) -> None:
    """Sessão conversacional interativa com suporte a comandos e salvamento automático em arquivo."""
    persona = agent.get_active_persona()
    console_rule(f"Consultor Interativo de Cibersegurança [{persona['title']}]")
    console_print("[dim]💡 Recursos Inteligentes:[/dim]")
    console_print("  • Executar comandos: digite [bold]'/exec <cmd>'[/bold], [bold]'!<cmd>'[/bold] ou selecione números sugeridos ([bold]1,2,3[/bold] ou [bold]'todos'[/bold])")
    console_print("  • Varredura rápida de rede: digite [bold]'/scan <ip/host>'[/bold]")
    console_print("  • Salvar em arquivo: peça [bold]'crie um relatorio.md e salve'[/bold] ou use [bold]'/salvar [arquivo.md]'[/bold]")
    console_print("  • Trocar perfil: digite [bold]'/perfil'[/bold]")
    console_print("  • Limpar tela: digite [bold]'/limpar'[/bold]")
    console_print("  • Encerrar: digite [bold]'sair'[/bold] ou [bold]'voltar'[/bold]\n")

    last_response = ""
    last_suggested_cmds: List[str] = []
    last_target_ip = "10.23.30.149"

    while True:
        try:
            q = console_prompt("[bold green]Você[/bold green]")
        except (KeyboardInterrupt, EOFError):
            console_print("\nRetornando ao menu principal...")
            break

        q_clean = q.strip()
        if not q_clean:
            continue

        if q_clean.lower() in ["sair", "exit", "voltar"]:
            break

        if q_clean.lower() in ["/limpar", "clear"]:
            agent.clear_chat_history()
            clear_screen()
            console_print("[dim]Histórico da conversa limpo.[/dim]\n")
            continue

        if q_clean.lower() in ["/ajuda", "/help"]:
            console_print("\n[bold cyan]Comandos Rápidos do Chat:[/bold cyan]")
            console_print(" • [bold]/analisar <arquivo>[/bold] ou [bold]/ler <arquivo>[/bold] - Lê e submete relatório/log/config à IA")
            console_print(" • [bold]/exec <comando>[/bold] ou [bold]!<comando>[/bold] - Executa comando Linux no terminal com confirmação")
            console_print(" • [bold]1,2,3... ou 'todos'[/bold] - Executa um ou todos os comandos sugeridos pelo agente")
            console_print(" • [bold]/scan <ip/host>[/bold]  - Dispara varredura de portas diretamente no alvo")
            console_print(" • [bold]/salvar [nome.md][/bold]- Salva a última resposta da IA em relatorios/")
            console_print(" • [bold]/perfil[/bold]          - Visualiza ou troca o perfil do agente")
            console_print(" • [bold]/limpar[/bold]          - Limpa o terminal")
            console_print(" • [bold]sair[/bold]             - Retorna ao menu principal\n")
            continue

        if q_clean.lower().startswith("/perfil"):
            agent_persona_menu(agent)
            persona = agent.get_active_persona()
            console_print(f"[cyan]Perfil ativo agora: [bold]{persona['title']}[/bold][/cyan]\n")
            continue

        # Suporte a leitura e análise de arquivos no chat (/analisar, /ler, ou menção a arquivo existente)
        file_to_analyze = None
        if q_clean.lower().startswith(("/analisar", "/ler")):
            parts = q_clean.split(maxsplit=1)
            if len(parts) >= 2 and parts[1].strip():
                candidate = parts[1].strip().strip("'\"`")
                p_cand = Path(candidate)
                if not p_cand.exists():
                    p_cand = settings.base_dir / candidate
                if p_cand.exists() and p_cand.is_file():
                    file_to_analyze = p_cand
                else:
                    console_print(f"[bold red]❌ Arquivo não encontrado: {candidate}[/bold red]\n")
                    continue
        else:
            # Verifica se na frase há menção explícita a um caminho de arquivo existente (ex: "analise o relatorios/auditoria2026.md")
            words = q_clean.replace("`", "").replace("'", "").replace('"', '').split()
            for w in words:
                clean_w = w.strip(".,;:?!()")
                if "/" in clean_w or clean_w.endswith((".md", ".txt", ".log", ".cfg", ".conf", ".py", ".json")):
                    p_cand = Path(clean_w)
                    if not p_cand.is_absolute():
                        p_base = settings.base_dir / clean_w
                        if p_base.exists() and p_base.is_file():
                            file_to_analyze = p_base
                            break
                    elif p_cand.exists() and p_cand.is_file():
                        file_to_analyze = p_cand
                        break

        if file_to_analyze:
            try:
                content = file_to_analyze.read_text(encoding="utf-8", errors="ignore")
                console_print(f"📖 [cyan]Carregando conteúdo de [bold]{file_to_analyze.name}[/bold] ({len(content):,} caracteres) para análise pela IA...[/cyan]")
                preview = content[:45000]
                if len(content) > 45000:
                    preview += f"\n\n[... Truncado para caber no limite de contexto ({len(content)} bytes totais) ...]"
                q_clean = (
                    f"Você está avaliando como auditor de segurança o conteúdo do seguinte arquivo ({file_to_analyze.name}):\n\n"
                    f"```text\n{preview}\n```\n\n"
                    f"Instrução do Auditor: {q_clean}"
                )
            except Exception as e:
                console_print(f"[yellow]⚠️ Não foi possível ler o arquivo {file_to_analyze}: {e}[/yellow]")

        # Memoriza IP mencionado pelo usuário para reutilizar em placeholders
        m_ip = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', q_clean)
        if m_ip:
            last_target_ip = m_ip.group(0)

        # Se o usuário digitou seleção de comandos diretamente no chat (ex: 1,2,3,4,5 ou 'todos' ou 'execute todos')
        if last_suggested_cmds:
            clean_sel = q_clean.strip().lower()
            if any(clean_sel.startswith(p) for p in ["executar ", "execute ", "rodar ", "rode "]):
                clean_sel = re.sub(r"^(?:executar|execute|rodar|rode)\s+(?:o\s+|os\s+)?(?:comando[s]?\s+)?", "", clean_sel).strip()

            sel_from_chat = parse_command_selection(clean_sel, len(last_suggested_cmds))
            if sel_from_chat and (clean_sel in ["todos", "all", "tudo", "t", "*"] or "," in clean_sel or "-" in clean_sel or clean_sel.isdigit()):
                chosen = [last_suggested_cmds[i - 1] for i in sel_from_chat]
                out_text, diag = run_command_batch(chosen, agent, default_target=last_target_ip)
                if diag:
                    last_response = diag
                elif out_text:
                    last_response = out_text
                continue

        # Detecção de comando de execução: /exec, !, $ ou ferramentas de segurança diretas
        cmd_to_run = None
        if q_clean.lower().startswith("/exec"):
            parts = q_clean.split(maxsplit=1)
            if len(parts) >= 2 and parts[1].strip():
                cmd_to_run = parts[1].strip()
            else:
                console_print("[yellow]⚠️ Uso: /exec <comando> ou !<comando> (ex: /exec ping -c 3 10.23.30.149 ou !nmap -sS 10.23.30.149)[/yellow]\n")
                continue
        elif q_clean.startswith(("!", "$")):
            cmd_to_run = q_clean[1:].strip()
        elif any(q_clean.lower().startswith(p) for p in ["rode ", "rodar ", "execute ", "executar "]):
            potential_cmd = re.sub(r"^(?:rode|rodar|execute|executar)\s+(?:o\s+comando\s+|comando\s+)?", "", q_clean, flags=re.IGNORECASE).strip()
            first_w = potential_cmd.split()[0].lower() if potential_cmd.split() else ""
            if first_w in KNOWN_SECURITY_TOOLS:
                confirm = console_prompt(f"⚡ Detectado comando operacional: [bold green]$ {potential_cmd}[/bold green]. Deseja executá-lo agora? [S/n]", default="s")
                if confirm.lower().startswith("s"):
                    cmd_to_run = potential_cmd
        else:
            first_w = q_clean.split()[0].lower() if q_clean.split() else ""
            if first_w in KNOWN_SECURITY_TOOLS and len(q_clean.split()) > 1:
                confirm = console_prompt(f"⚡ Detectado comando Linux: [bold green]$ {q_clean}[/bold green]. Deseja executar no terminal agora? [S/n]", default="s")
                if confirm.lower().startswith("s"):
                    cmd_to_run = q_clean

        if cmd_to_run:
            if has_placeholders(cmd_to_run):
                prompt_target = console_prompt(
                    "🎯 O comando contém marcador (<TARGET>/<ALVO>). Digite o IP ou alvo",
                    default=last_target_ip
                )
                if prompt_target.strip():
                    last_target_ip = prompt_target.strip()
                cmd_to_run = substitute_placeholders(cmd_to_run, last_target_ip)

            exit_code, cmd_output = execute_system_command(cmd_to_run, agent=agent)
            last_response = f"Comando Executado: `{cmd_to_run}`\nCódigo: {exit_code}\n\nSaída:\n```\n{cmd_output}\n```"

            if cmd_output.strip():
                ask_diag = console_prompt("🤖 Deseja que o TeXuGo-GuardIA analise o resultado dessa execução? [S/n]", default="s")
                if ask_diag.lower().startswith("s"):
                    diag_prompt = (
                        f"Analise criticamente o resultado real retornado pelo comando:\n"
                        f"Comando: `{cmd_to_run}` (Código: {exit_code})\n\n"
                        f"Saída Obtida:\n```\n{cmd_output[:3500]}\n```\n\n"
                        f"Forneça o diagnóstico técnico de cibersegurança, portas/serviços identificados e recomende os próximos passos."
                    )
                    console_print("\n[cyan]Consultando IA para diagnóstico das evidências...[/cyan]")
                    with console_spinner("TeXuGo-GuardIA analisando evidências coletadas..."):
                        diag_resp = agent.chat_security_consultant(diag_prompt)
                    last_response = diag_resp
                    console_panel(diag_resp, title="TeXuGo-GuardIA - Diagnóstico da Execução", border_style="green")
            continue

        # Comando rápido de varredura nativa: /scan <alvo>
        if q_clean.lower().startswith("/scan"):
            parts = q_clean.split(maxsplit=1)
            target_to_scan = parts[1].strip() if len(parts) > 1 else ""
            if not target_to_scan:
                target_to_scan = console_prompt("Digite o IP ou domínio para varredura", default=last_target_ip)
            console_print(f"\n[cyan]Disparando varredura nativa no alvo: [bold]{target_to_scan}[/bold][/cyan]")
            ports, profile_name = select_port_profile()
            run_port_scan(agent, target_to_scan, ports=ports)
            continue

        # Comando explícito /salvar
        if q_clean.lower().startswith("/salvar"):
            parts = q_clean.split(maxsplit=1)
            target_name = parts[1].strip() if len(parts) > 1 else "relatorio_chat.md"
            if not target_name.endswith((".md", ".txt", ".json")):
                target_name += ".md"

            if not last_response:
                console_print("[yellow]⚠️ Nenhuma resposta anterior disponível para salvar.[/yellow]\n")
                continue

            try:
                save_path = settings.resolve_output_path(target_name)
                save_path.write_text(last_response, encoding="utf-8")
                console_print(f"📄 [bold green]Arquivo salvo com sucesso em:[/bold green] [cyan]{save_path}[/cyan] ({len(last_response)} caracteres)\n")
            except Exception as e:
                console_print(f"[red]❌ Erro ao salvar arquivo: {e}[/red]\n")
            continue

        # Detecção automática de pedido de salvar no próprio prompt natural
        q_low = q_clean.lower()
        is_save_request = any(w in q_low for w in ["salve", "salvar", "crie um relatorio", "criar relatorio", "gere um relatorio", "exporte", "grave"])
        m = re.search(r'([a-zA-Z0-9_\-]+\.(?:md|txt|json))', q_clean, re.IGNORECASE)
        target_filename = m.group(1) if m else ("relatorio_vulnerabilidade.md" if is_save_request else None)

        # Análise Inteligente de Documentos: se o usuário citou arquivos (.md, .py, .json, etc.), anexa para a IA
        file_candidates = re.findall(r'([a-zA-Z0-9_\-\./]+\.(?:md|py|json|txt|conf|yaml|yml|log))', q_clean)
        attached_docs = []
        for fc in file_candidates:
            f_path = Path(fc)
            if not f_path.is_absolute():
                f_path = settings.base_dir / f_path
            if f_path.exists() and f_path.is_file():
                try:
                    f_content = f_path.read_text(encoding="utf-8", errors="ignore")
                    attached_docs.append(f"\n\n[📄 Conteúdo do arquivo `{fc}`]:\n```markdown\n{f_content[:4500]}\n```")
                    console_print(f"📎 [dim]Arquivo lido e anexado para análise:[/dim] [cyan]{fc}[/cyan]")
                except Exception:
                    pass

        consult_prompt = q_clean + "".join(attached_docs)

        console_print(f"\n[cyan]Consultando IA ({persona['title']})...[/cyan]")

        with console_spinner("TeXuGo-GuardIA formulando resposta técnica..."):
            resp = agent.chat_security_consultant(consult_prompt)
        last_response = resp

        console_panel(resp, title=f"TeXuGo-GuardIA ({persona['title']})", border_style="blue")

        # Se o usuário pediu para salvar em arquivo, grava no disco imediatamente!
        if is_save_request and target_filename:
            try:
                save_path = settings.resolve_output_path(target_filename)
                save_path.write_text(resp, encoding="utf-8")
                console_panel(
                    f"✅ [bold green]Arquivo criado e salvo com sucesso na pasta de relatórios:[/bold green]\n"
                    f"📁 [cyan]{save_path}[/cyan]\n"
                    f"[dim]Tamanho: {len(resp)} caracteres | Formato: Markdown[/dim]",
                    title="Documento Gravado no Disco",
                    border_style="green"
                )
            except Exception as e:
                console_print(f"[red]❌ Falha ao salvar arquivo no disco: {e}[/red]")

        # Execução Assistida: detecta comandos operacionais sugeridos pela IA
        detected_cmds = extract_executable_commands(resp)
        last_suggested_cmds = detected_cmds[:5]
        if detected_cmds:
            console_print("\n[bold cyan]⚡ Comandos operacionais sugeridos pelo agente:[/bold cyan]")
            for idx, c in enumerate(detected_cmds[:5], 1):
                console_print(f"  [[bold yellow]{idx}[/bold yellow]] [green]$ {c}[/green]")

            console_print("[dim]Escolha os comandos: ex: 1, ou 1,2,3,4,5, ou 1-5, ou 'todos'. Pressione Enter para ignorar.[/dim]")
            run_choice = console_prompt("Digite o número do(s) comando(s) para rodar", default="")
            sel_indices = parse_command_selection(run_choice, len(detected_cmds[:5]))
            if sel_indices:
                chosen = [detected_cmds[i - 1] for i in sel_indices]
                out_text, diag = run_command_batch(chosen, agent, default_target=last_target_ip)
                if diag:
                    last_response = diag
                elif out_text:
                    last_response = out_text
            elif run_choice.strip():
                console_print("[yellow]⚠️ Seleção não reconhecida. Use números (ex: 1, 1,2,3 ou 'todos').[/yellow]\n")


# =====================================================================
# 8. Menu Interativo Principal
# =====================================================================

def run_interactive_menu(agent: TeXGuardIAAgent) -> None:
    """Menu interativo principal do TeXuGo-GuardIA com tratamento de sinais."""
    while True:
        try:
            show_banner(agent)
            console_rule("Menu Principal de Auditoria")
            console_print(" [1] 🔎 Analisar Código-Fonte (SAST)")
            console_print(" [2] 🌐 Analisar Superfície Web & Cabeçalhos HTTP")
            console_print(" [3] 🔌 Analisar Portas e Serviços de Rede (com seleção de portas)")
            console_print(" [4] 🤖 Consultor Interativo de Cibersegurança (Chat com Salvamento)")
            console_print(" [5] 🎭 Configurar Perfil do Agente (AppSec, Red Team, Blue Team, Compliance)")
            console_print(" [6] ⚙️  Configurar APIs & Modelos de IA (Testar conexão e salvar .env)")
            console_print(" [0] 🚪 Sair")

            choice = console_prompt(
                "\n[bold yellow]Digite o número da opção desejada (0 a 6)[/bold yellow]",
                choices=["1", "2", "3", "4", "5", "6", "0"],
                default="1"
            )

            if choice == "1":
                target = console_prompt("Digite o caminho do arquivo ou pasta", default="samples/vulnerable_code_test.py")
                run_code_scan(agent, target.strip())

            elif choice == "2":
                target = console_prompt("Digite a URL ou domínio", default="https://example.com")
                run_web_scan(agent, target.strip())

            elif choice == "3":
                host = console_prompt("Digite o host ou IP a ser verificado", default="127.0.0.1")
                ports, profile_name = select_port_profile()
                console_print(f"🎯 [dim]Perfil selecionado:[/dim] [cyan]{profile_name}[/cyan] ({len(ports)} portas)")
                run_port_scan(agent, host.strip(), ports=ports)

            elif choice == "4":
                run_interactive_consultant(agent)

            elif choice == "5":
                agent_persona_menu(agent)

            elif choice == "6":
                api_settings_menu(agent)

            elif choice in ["0", "sair", "exit"]:
                console_print("\n[bold cyan]Encerrando TeXuGo-GuardIA. Mantenha sua infraestrutura protegida! 🛡️[/bold cyan]\n")
                break

        except KeyboardInterrupt:
            console_print("\n\n[yellow]Operação interrompida pelo usuário (Ctrl+C). Retornando ao menu principal...[/yellow]\n")
            continue


# =====================================================================
# 9. Ponto de Entrada CLI Headless / Terminal
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="TeXuGo-GuardIA - Agente Inteligente para Cibersegurança e Análise de Vulnerabilidades"
    )
    parser.add_argument("--scan-code", type=str, help="Executa análise SAST no arquivo ou pasta especificada")
    parser.add_argument("--scan-web", type=str, help="Executa auditoria em URL ou endpoint web")
    parser.add_argument("--scan-ports", type=str, help="Executa verificação de portas no host ou IP")
    parser.add_argument("--ports", type=str, help="Lista de portas separadas por vírgula para verificação (ex: 80,443,8080)")
    parser.add_argument("--persona", type=str, choices=list(AGENT_PERSONAS.keys()), default="appsec", help="Perfil de atuação do agente")
    parser.add_argument("--out-md", type=str, help="Caminho do arquivo Markdown para exportação")
    parser.add_argument("--out-json", type=str, help="Caminho do arquivo JSON para exportação")
    parser.add_argument("--no-ai", action="store_true", help="Desativa consultas a APIs externas de IA")

    args = parser.parse_args()
    agent = TeXGuardIAAgent()
    if args.persona:
        agent.set_persona(args.persona)

    # Se nenhum argumento de linha de comando foi passado, abre menu interativo
    if not (args.scan_code or args.scan_web or args.scan_ports):
        try:
            run_interactive_menu(agent)
        except (KeyboardInterrupt, EOFError):
            console_print("\n[bold cyan]Encerrando TeXuGo-GuardIA.[/bold cyan]\n")
        return

    use_ai = not args.no_ai

    if args.scan_code:
        run_code_scan(agent, args.scan_code, md_out=args.out_md, json_out=args.out_json, use_ai=use_ai)
    if args.scan_web:
        run_web_scan(agent, args.scan_web, md_out=args.out_md, json_out=args.out_json, use_ai=use_ai)
    if args.scan_ports:
        custom_ports = None
        if args.ports:
            valid_ports, invalid_entries = validate_port_list(args.ports)
            if invalid_entries:
                console_print(f"[yellow]⚠️ Portas inválidas ignoradas: {', '.join(invalid_entries)}[/yellow]")
            custom_ports = valid_ports if valid_ports else None
        run_port_scan(agent, args.scan_ports, ports=custom_ports, md_out=args.out_md, json_out=args.out_json, use_ai=use_ai)


if __name__ == "__main__":
    main()
