"""
Módulo Inteligente de Detecção de SO e Instalação Automatizada de Ferramentas.

Identifica o sistema operacional e gerenciador de pacotes do usuário (Arch Linux,
Debian/Ubuntu, Fedora, Alpine, macOS) e orienta a instalação interativa de programas
ausentes requeridos para comandos de cibersegurança e auditoria.
"""

from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
from typing import Any, Dict, Optional, Tuple

from TeXGuardIA.ui import console_print, console_panel, console_prompt


# Dicionário pré-mapeado de ferramentas essenciais por gerenciador de pacotes
KNOWN_PACKAGES: Dict[str, Dict[str, str]] = {
    "gobuster": {"pacman": "gobuster", "apt": "gobuster", "dnf": "gobuster", "brew": "gobuster"},
    "sqlmap": {"pacman": "sqlmap", "apt": "sqlmap", "dnf": "sqlmap", "brew": "sqlmap"},
    "nmap": {"pacman": "nmap", "apt": "nmap", "dnf": "nmap", "brew": "nmap"},
    "masscan": {"pacman": "masscan", "apt": "masscan", "dnf": "masscan", "brew": "masscan"},
    "nikto": {"pacman": "nikto", "apt": "nikto", "dnf": "nikto", "brew": "nikto"},
    "ffuf": {"pacman": "ffuf", "apt": "ffuf", "dnf": "ffuf", "brew": "ffuf"},
    "traceroute": {"pacman": "traceroute", "apt": "traceroute", "dnf": "traceroute", "brew": "traceroute"},
    "whois": {"pacman": "whois", "apt": "whois", "dnf": "whois", "brew": "whois"},
    "nc": {"pacman": "gnu-netcat", "apt": "netcat-openbsd", "dnf": "nmap-ncat", "brew": "netcat"},
    "netcat": {"pacman": "gnu-netcat", "apt": "netcat-openbsd", "dnf": "nmap-ncat", "brew": "netcat"},
    "tcpdump": {"pacman": "tcpdump", "apt": "tcpdump", "dnf": "tcpdump", "brew": "tcpdump"},
    "tshark": {"pacman": "wireshark-cli", "apt": "tshark", "dnf": "wireshark-cli", "brew": "wireshark"},
    "hydra": {"pacman": "hydra", "apt": "hydra", "dnf": "hydra", "brew": "hydra"},
    "john": {"pacman": "john", "apt": "john", "dnf": "john", "brew": "john"},
    "lynis": {"pacman": "lynis", "apt": "lynis", "dnf": "lynis", "brew": "lynis"},
    "bandit": {"pacman": "bandit", "apt": "bandit", "pip": "bandit"},
    "semgrep": {"pip": "semgrep"},
    "ufw": {"pacman": "ufw", "apt": "ufw", "dnf": "ufw"},
    "fail2ban": {"pacman": "fail2ban", "apt": "fail2ban", "dnf": "fail2ban"},
    "curl": {"pacman": "curl", "apt": "curl", "dnf": "curl", "brew": "curl"},
    "jq": {"pacman": "jq", "apt": "jq", "dnf": "jq", "brew": "jq"},
}


def detect_system_environment() -> Dict[str, str]:
    """Detecta com precisão o sistema operacional, distribuição e gerenciador de pacotes."""
    system = platform.system().lower()
    info: Dict[str, str] = {
        "system": system,
        "distro_id": "linux" if system == "linux" else system,
        "distro_name": "Linux",
        "pkg_manager": "",
        "install_template": "",
    }

    if system == "linux":
        os_release = Path("/etc/os-release")
        if os_release.exists():
            try:
                content = os_release.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    if line.startswith("ID="):
                        info["distro_id"] = line.split("=", 1)[1].strip('"\'').lower()
                    elif line.startswith("PRETTY_NAME="):
                        info["distro_name"] = line.split("=", 1)[1].strip('"\'')
            except Exception:
                pass

        if shutil.which("pacman"):
            info["pkg_manager"] = "pacman"
            info["install_template"] = "sudo pacman -S --noconfirm {pkg}"
        elif shutil.which("apt-get"):
            info["pkg_manager"] = "apt"
            info["install_template"] = "sudo apt-get update && sudo apt-get install -y {pkg}"
        elif shutil.which("dnf"):
            info["pkg_manager"] = "dnf"
            info["install_template"] = "sudo dnf install -y {pkg}"
        elif shutil.which("apk"):
            info["pkg_manager"] = "apk"
            info["install_template"] = "apk add {pkg}"
        elif shutil.which("zypper"):
            info["pkg_manager"] = "zypper"
            info["install_template"] = "sudo zypper install -y {pkg}"

    elif system == "darwin":
        info["distro_name"] = "macOS"
        if shutil.which("brew"):
            info["pkg_manager"] = "brew"
            info["install_template"] = "brew install {pkg}"

    elif system == "windows":
        info["distro_name"] = "Windows"
        if shutil.which("winget"):
            info["pkg_manager"] = "winget"
            info["install_template"] = "winget install {pkg}"
        elif shutil.which("choco"):
            info["pkg_manager"] = "choco"
            info["install_template"] = "choco install -y {pkg}"

    return info


def resolve_install_command(tool_name: str, agent: Optional[Any] = None) -> Optional[str]:
    """Resolve o comando exato de instalação para o sistema atual via mapeamento ou IA."""
    env = detect_system_environment()
    pkg_mgr = env.get("pkg_manager", "")
    distro_name = env.get("distro_name", "Linux")
    template = env.get("install_template", "")

    tool_clean = tool_name.strip().lower()

    # 1. Procura no mapeamento local rápido
    if tool_clean in KNOWN_PACKAGES:
        pkg_mapping = KNOWN_PACKAGES[tool_clean]
        if pkg_mgr and pkg_mgr in pkg_mapping and template:
            pkg_name = pkg_mapping[pkg_mgr]
            return template.format(pkg=pkg_name)
        elif "pip" in pkg_mapping and shutil.which("pip"):
            return f"python3 -m pip install {pkg_mapping['pip']}"

    # 2. Se o gerenciador for conhecido, tenta o nome direto do binário
    if template:
        return template.format(pkg=tool_clean)

    # 3. Se não tiver template padrão ou for desconhecido, consulta a IA com contexto do SO
    if agent and hasattr(agent, "chat_security_consultant"):
        try:
            ai_query = (
                f"Qual é o comando de terminal exato para instalar o programa '{tool_clean}' "
                f"no sistema operacional '{distro_name}'? "
                f"Responda EXCLUSIVAMENTE com o comando de shell em uma linha, sem introduções e sem markdown."
            )
            resp = agent.chat_security_consultant(ai_query)
            # Extrai linha do comando limpo
            for line in resp.strip().splitlines():
                line_str = line.strip().strip("`$ \t")
                if line_str and not line_str.startswith("#"):
                    return line_str
        except Exception:
            pass

    return None


def prompt_and_install_missing_tool(tool_name: str, agent: Optional[Any] = None) -> bool:
    """Avisa o usuário de forma intuitiva sobre o programa ausente e oferece instalação no SO."""
    env = detect_system_environment()
    distro_name = env.get("distro_name", "Linux")

    console_panel(
        f"⚠️ [bold red]Programa Ausente no Sistema:[/bold red] [bold yellow]{tool_name}[/bold yellow]\n\n"
        f"O comando solicitado requer a ferramenta [cyan]{tool_name}[/cyan], porém ela "
        f"[bold red]não está instalada[/bold red] no seu sistema operacional ([bold green]{distro_name}[/bold green]).\n\n"
        f"[bold]ℹ️ Por motivo de falta desse programa no sistema, não posso executar este comando agora![/bold]",
        title="⚠️ Ferramenta Não Encontrada",
        border_style="yellow"
    )

    ask_install = console_prompt(
        f"🤖 Deseja que o TeXuGo-GuardIA instale o programa '{tool_name}' no seu {distro_name}? [S/n]",
        default="s"
    )

    if not ask_install.lower().startswith("s"):
        console_print(f"[yellow]⏭️ Operação cancelada pelo usuário. Pulando a execução deste comando.[/yellow]\n")
        return False

    console_print(f"\n[cyan]🔍 Identificando método de instalação para [bold]{distro_name}[/bold]...[/cyan]")
    install_cmd = resolve_install_command(tool_name, agent=agent)

    if not install_cmd:
        console_print(f"[red]❌ Não foi possível determinar o comando de instalação para '{tool_name}' neste ambiente.[/red]\n")
        return False

    console_print(f"📦 [bold cyan]Comando de instalação preparado:[/bold cyan] [bold green]$ {install_cmd}[/bold green]")
    confirm_run = console_prompt("Confirmar execução da instalação agora? [S/n]", default="s")
    if not confirm_run.lower().startswith("s"):
        console_print(f"[yellow]⏭️ Instalação cancelada. Pulando comando.[/yellow]\n")
        return False

    console_print(f"\n[bold cyan]⚙️ Iniciando instalação no {distro_name}...[/bold cyan]")
    console_print("[dim]Se for solicitada, digite a sua senha de superusuário (sudo):[/dim]\n")

    try:
        # Execução interativa estruturada sem invocação direta do shell (mitigação CWE-78)
        cmd_args = shlex.split(install_cmd)
        ret = subprocess.call(cmd_args)
        if ret == 0 and shutil.which(tool_name) is not None:
            console_panel(
                f"✅ [bold green]Programa '{tool_name}' instalado com sucesso![/bold green]\n"
                f"Localização do binário: [cyan]{shutil.which(tool_name)}[/cyan]\n\n"
                f"🚀 [bold]Prosseguindo agora com a execução do comando original solicitado...[/bold]",
                title="Instalação Concluída",
                border_style="green"
            )
            return True
        else:
            console_print(f"\n[red]❌ Falha na instalação ou binário '{tool_name}' ainda não encontrado após a tentativa.[/red]\n")
            return False
    except Exception as e:
        console_print(f"\n[red]❌ Erro ao disparar instalação: {e}[/red]\n")
        return False
