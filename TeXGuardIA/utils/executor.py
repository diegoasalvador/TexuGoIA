"""
Módulo de Execução Segura de Comandos do TeXuGo-GuardIA (Human-in-the-Loop).

Permite que o agente execute comandos no sistema operacional local com confirmação
explícita do usuário, sanitização de comandos destrutivos, timeouts e streaming
em tempo real da saída.
"""

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any, List, Optional, Tuple

from TeXGuardIA.ui import console_print, console_panel, console_prompt
from TeXGuardIA.utils.package_installer import prompt_and_install_missing_tool


# Comandos ou padrões estritamente bloqueados por segurança operacional
DANGEROUS_PATTERNS = [
    r"\brm\s+-(?:r|f|rf|fr)\s+/(?:\s|$|\*)",       # rm -rf /
    r"\bmkfs\b",                                  # Formatação de discos
    r"\bdd\s+if=[^\s]+\s+of=/dev/sd[a-z]",        # Sobrescrita direta de partições
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", # Fork bomb
    r">\s*/dev/sd[a-z]",                          # Redirecionamento destrutivo para disco
    r">\s*/etc/(?:passwd|shadow|sudoers)",        # Sobrescrita de arquivos de autenticação
    r"\b(?:shutdown|reboot|poweroff|init\s+[06])\b" # Desligamento do sistema
]


def is_command_safe(command: str) -> Tuple[bool, str]:
    """Verifica se o comando contém instruções destrutivas ou proibidas."""
    cmd_clean = command.strip()
    if not cmd_clean:
        return False, "Comando vazio."

    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd_clean, re.IGNORECASE):
            return False, f"Comando bloqueado pela política de proteção do TeXuGo-GuardIA: padrão de risco detectado ({pattern})"

    return True, "Seguro para execução controlada."


KNOWN_SECURITY_TOOLS = [
    "nmap", "ping", "curl", "masscan", "gobuster", "ffuf", "nikto",
    "traceroute", "host", "dig", "whois", "arp", "sqlmap", "nuclei",
    "cat", "grep", "awk", "sed", "ufw", "iptables", "netstat", "ss",
    "sudo", "bandit", "semgrep", "safety", "lynis"
]


def extract_executable_commands(text: str) -> List[str]:
    """Extrai comandos executáveis de blocos Markdown, crases inline ou linhas de comando."""
    commands: List[str] = []

    def _add_if_valid(cmd_candidate: str):
        cmd_clean = cmd_candidate.strip()
        # Remove eventuais aspas ou crases extras residuais
        cmd_clean = cmd_clean.strip("`'\" \t")
        if not cmd_clean or cmd_clean.startswith("#"):
            return
        if cmd_clean.startswith("$ "):
            cmd_clean = cmd_clean[2:].strip()
        first_word = cmd_clean.split()[0].lower() if cmd_clean.split() else ""
        if first_word in KNOWN_SECURITY_TOOLS:
            if cmd_clean not in commands:
                commands.append(cmd_clean)

    # 1. Extrai blocos de código com linguagem bash, sh ou zsh ou sem linguagem
    code_blocks = re.findall(r"```(?:bash|sh|zsh)?[\t ]*\r?\n(.*?)```", text, re.DOTALL | re.IGNORECASE)
    for block in code_blocks:
        for line in block.splitlines():
            _add_if_valid(line)

    # 2. Extrai comandos entre crases inline: `nmap -sV ...`
    inline_ticks = re.findall(r"`([^`\n]+)`", text)
    for tick in inline_ticks:
        _add_if_valid(tick)

    # 3. Busca linhas com $ comando
    inline_cmds = re.findall(r"(?:^|\n)\s*\$\s*([a-zA-Z0-9_\-\./]+[^\n]+)", text)
    for cmd in inline_cmds:
        _add_if_valid(cmd)

    # 4. Busca linhas que comecem diretamente com ferramentas conhecidas
    for line in text.splitlines():
        _add_if_valid(line)

    return commands


PLACEHOLDER_PATTERN = re.compile(
    r'(?:<[A-Za-z0-9_-]+>|\[[A-Za-z0-9_-]+\]|(?<![--a-zA-Z0-9_])(?:TARGET|ALVO|HOST_IP)(?![--a-zA-Z0-9_]))',
    re.IGNORECASE
)


def has_placeholders(command: str) -> bool:
    """Verifica se o comando contém marcadores como <TARGET>, <IP>, <ALVO>."""
    return bool(PLACEHOLDER_PATTERN.search(command))


def substitute_placeholders(command: str, target: str) -> str:
    """Substitui marcadores genéricos pelo IP ou alvo especificado."""
    if not target.strip():
        return command
    return PLACEHOLDER_PATTERN.sub(target.strip(), command)


def parse_command_selection(choice_str: str, max_count: int) -> List[int]:
    """Interpreta seleções flexíveis como 'todos', 'all', '1,2,3', '1-5', '1 2 3'."""
    choice = choice_str.strip().lower()
    if not choice:
        return []
    if choice in ["todos", "all", "tudo", "t", "*"]:
        return list(range(1, max_count + 1))

    indices: List[int] = []
    parts = re.split(r"[,;\s]+", choice)
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if "-" in p:
            m = re.match(r"^(\d+)-(\d+)$", p)
            if m:
                start, end = int(m.group(1)), int(m.group(2))
                for n in range(start, end + 1):
                    if 1 <= n <= max_count and n not in indices:
                        indices.append(n)
        elif p.isdigit():
            n = int(p)
            if 1 <= n <= max_count and n not in indices:
                indices.append(n)

    return indices


def sanitize_command_syntax(command: str) -> str:
    """Higieniza comandos gerados por IA, removendo reticências (...) e fechando aspas quebradas."""
    cleaned = command.strip()
    # Remove reticências no final de comandos ou URLs
    if cleaned.endswith("..."):
        cleaned = cleaned[:-3].rstrip()
    elif cleaned.endswith("…"):
        cleaned = cleaned[:-1].rstrip()

    # Fecha aspas duplas desbalanceadas
    if cleaned.count('"') % 2 != 0:
        cleaned += '"'
    # Fecha aspas simples desbalanceadas
    if cleaned.count("'") % 2 != 0:
        cleaned += "'"

    return cleaned


def extract_primary_tool(command: str) -> str:
    """Extrai o nome do binário executável principal do comando."""
    parts = command.strip().split()
    if not parts:
        return ""
    idx = 0
    while idx < len(parts) and (parts[idx] in ["sudo", "env"] or "=" in parts[idx]):
        idx += 1
    if idx < len(parts):
        return Path(parts[idx]).name.lower()
    return ""


def execute_system_command(command: str, timeout: int = 120, agent: Optional[Any] = None) -> Tuple[int, str]:
    """Executa um comando no shell do sistema com streaming em tempo real e cancelamento seguro."""
    command = sanitize_command_syntax(command)

    safe, reason = is_command_safe(command)
    if not safe:
        console_print(f"[bold red]⛔ {reason}[/bold red]")
        return 1, reason

    # Verificação de disponibilidade da ferramenta com aviso intuitivo e autoinstalação
    primary_tool = extract_primary_tool(command)
    if primary_tool and primary_tool in KNOWN_SECURITY_TOOLS:
        if shutil.which(primary_tool) is None:
            # Avisa o usuário e oferece instalar conforme o sistema operacional dele
            installed = prompt_and_install_missing_tool(primary_tool, agent=agent)
            if not installed:
                return 127, f"Comando não executado: programa '{primary_tool}' não está instalado no sistema operacional."

    console_print(f"\n[cyan]⚙️ Executando no Linux:[/cyan] [bold yellow]{command}[/bold yellow]")
    console_print("[dim]Pressione Ctrl+C a qualquer momento para interromper a execução do comando.[/dim]\n")

    output_lines: List[str] = []
    exit_code = 0

    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Leitura linha a linha em tempo real
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                print(line, end="", flush=True)
                output_lines.append(line)

        exit_code = process.poll() or 0

    except KeyboardInterrupt:
        console_print("\n[yellow]⚠️ Execução cancelada pelo usuário (Ctrl+C). Encerrando processo...[/yellow]")
        try:
            process.terminate()
            time.sleep(0.5)
            if process.poll() is None:
                process.kill()
        except Exception:
            pass
        return 130, "Processo interrompido pelo usuário."
    except Exception as e:
        err_msg = f"Erro na execução do comando: {str(e)}"
        console_print(f"[red]❌ {err_msg}[/red]")
        return 1, err_msg

    full_output = "".join(output_lines)
    status_icon = "✅" if exit_code == 0 else "⚠️"
    console_print(f"\n{status_icon} [dim]Comando finalizado com código de saída: {exit_code}[/dim]\n")

    return exit_code, full_output
