"""
Módulo de Interface e Abstração de Terminal do TeXuGo-GuardIA.

Centraliza todas as operações de exibição, painéis, tabelas, regras e prompts,
fornecendo suporte completo ao 'rich' com fallback seguro e limpo caso a biblioteca
não esteja instalada ou o terminal não suporte cores ANSI.
"""

from contextlib import contextmanager
import getpass
import glob
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

# Auto-detecta dependências em .venv se executado fora do ambiente ativado
_proj_root = Path(__file__).resolve().parent.parent
_venv_candidates = glob.glob(str(_proj_root / ".venv/lib/python*/site-packages"))
if _venv_candidates and _venv_candidates[0] not in sys.path:
    sys.path.insert(0, _venv_candidates[0])

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt as RichPrompt
    from rich.table import Table
    from rich import box
    RICH_AVAILABLE = True
    _console = Console()
except ImportError:
    RICH_AVAILABLE = False
    _console = None


# Regex preciso para remover apenas tags de estilo do Rich sem tocar em opções como [1], [2], [0], [D]
_KNOWN_STYLES = (
    r"bold|dim|italic|underline|blink|reverse|strike|conceal|"
    r"black|red|green|yellow|blue|magenta|cyan|white|default|"
    r"bright_black|bright_red|bright_green|bright_yellow|bright_blue|bright_magenta|bright_cyan|bright_white|"
    r"dark_[a-z]+|light_[a-z]+|deep_[a-z]+|"
    r"#[0-9a-fA-F]{3,8}|link=[^\]]+|on [a-z0-9_#]+"
)
_RICH_TAG_REGEX = re.compile(rf"\[/?(?:{_KNOWN_STYLES})(?:\s+(?:{_KNOWN_STYLES}))*\]|\[/\]", re.IGNORECASE)


def strip_markup(text: str) -> str:
    """Remove marcações de estilo do Rich (ex: [bold cyan]...[/bold cyan]) preservando opções numéricas [1], [2], etc."""
    if not isinstance(text, str):
        text = str(text)
    return _RICH_TAG_REGEX.sub("", text)


def console_print(*args: Any, **kwargs: Any) -> None:
    """Imprime no terminal usando Rich (se disponível) ou fallback limpo com tags removidas."""
    if RICH_AVAILABLE and _console is not None:
        _console.print(*args, **kwargs)
    else:
        cleaned_args = [strip_markup(str(a)) for a in args]
        # Remove argumentos específicos do Rich que o print() nativo não suporta
        kwargs_clean = {k: v for k, v in kwargs.items() if k in ("sep", "end", "file", "flush")}
        print(*cleaned_args, **kwargs_clean)


def console_rule(title: str = "", style: str = "bold cyan") -> None:
    """Desenha uma linha divisória estilizada com título centralizado."""
    if RICH_AVAILABLE and _console is not None:
        _console.rule(title, style=style)
    else:
        clean_title = strip_markup(title)
        if clean_title:
            print(f"\n--- {clean_title} ---")
        else:
            print("\n" + "-" * 60)


def console_panel(content: Any, title: str = "", border_style: str = "cyan") -> None:
    """Exibe conteúdo envolvido em um painel estilizado, com salvaguarda contra valores None."""
    if content is None:
        content = "*(Nenhuma resposta gerada pelo modelo de IA)*"
    elif not isinstance(content, str):
        content = str(content)

    if RICH_AVAILABLE and _console is not None:
        _console.print(Panel(content, title=title, border_style=border_style))
    else:
        clean_title = strip_markup(title)
        clean_content = strip_markup(content)
        header = f"=== {clean_title} ===" if clean_title else "=========================="
        print(f"\n{header}\n{clean_content}\n{'=' * len(header)}\n")


def console_table(
    headers: List[str],
    rows: List[List[str]],
    title: Optional[str] = None,
    header_style: str = "bold magenta"
) -> None:
    """Renderiza uma tabela tabular com suporte ao Rich ou formatação em colunas alinhadas."""
    if RICH_AVAILABLE and _console is not None:
        table = Table(box=box.ROUNDED, show_header=True, header_style=header_style, title=title)
        for h in headers:
            table.add_column(h)
        for r in rows:
            table.add_row(*r)
        _console.print(table)
    else:
        if title:
            print(f"\n[ {strip_markup(title)} ]")
        clean_headers = [strip_markup(h) for h in headers]
        col_widths = [len(h) for h in clean_headers]
        clean_rows = []
        for row in rows:
            c_row = [strip_markup(str(c)) for c in row]
            clean_rows.append(c_row)
            for idx, cell in enumerate(c_row):
                if idx < len(col_widths):
                    col_widths[idx] = max(col_widths[idx], len(cell))

        # Linha de cabeçalho
        header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(clean_headers))
        separator = "-+-".join("-" * col_widths[i] for i in range(len(col_widths)))
        print(f"\n{header_line}\n{separator}")
        for r in clean_rows:
            row_line = " | ".join(str(c).ljust(col_widths[i]) if i < len(col_widths) else str(c) for i, c in enumerate(r))
            print(row_line)
        print()


def console_prompt(
    prompt: str = "",
    choices: Optional[List[str]] = None,
    default: str = "",
    password: bool = False
) -> str:
    """Obtém entrada do usuário com validação de opções e suporte a entrada mascarada."""
    clean_prompt = prompt if RICH_AVAILABLE else strip_markup(prompt)

    # Entrada de senha / chave de API confidencial
    if password:
        display = clean_prompt
        if default:
            display += f" [ENTER para manter atual: ...{default[-4:] if len(default) > 4 else '***'}]"
        display += ": "
        try:
            val = getpass.getpass(display)
        except Exception:
            # Fallback se getpass falhar em algum ambiente tty restrito
            val = input(display)
        val = val.strip()
        return val if val else default

    # Prompt regular com Rich
    if RICH_AVAILABLE and _console is not None:
        return RichPrompt.ask(prompt, choices=choices, default=default)

    # Prompt fallback com validação manual de escolhas
    suffix = f" [{default}]" if default else ""
    full_prompt = f"{clean_prompt}{suffix}: "

    while True:
        try:
            val = input(full_prompt).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nOperação cancelada pelo usuário.")
            return default

        if not val and default:
            return default

        if choices is not None:
            # Case-insensitive match se possível
            choices_lower = [c.lower() for c in choices]
            if val.lower() in choices_lower:
                idx = choices_lower.index(val.lower())
                return choices[idx]
            print(f"⚠️ Opção inválida '{val}'. Escolha entre: {', '.join(choices)}")
            continue

        return val


def clear_screen() -> None:
    """Limpa a tela do terminal de maneira confiável em qualquer SO."""
    if RICH_AVAILABLE and _console is not None:
        _console.clear()
    else:
        print("\033[H\033[J", end="", flush=True)


@contextmanager
def console_spinner(message: str):
    """Exibe um indicador de progresso animado (spinner) durante operações mais lentas."""
    if RICH_AVAILABLE and _console is not None:
        with _console.status(message, spinner="dots"):
            yield
    else:
        print(f"⏳ {strip_markup(message)}...", flush=True)
        try:
            yield
        finally:
            pass
