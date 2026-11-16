"""
Módulo de Configuração do TeXuGo-GuardIA.

Carrega configurações de variáveis de ambiente (.env) ou valores padrão.
"""

from dataclasses import dataclass
import os
from pathlib import Path

# Carrega .env se existir
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
    else:
        load_dotenv()
except ImportError:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass


@dataclass
class Config:
    """Configurações globais de execução do TeXuGo-GuardIA."""

    # Provedor de IA ('openrouter', 'opencode', 'gemini', 'openai', 'offline')
    ai_provider: str = os.getenv("AI_PROVIDER", "openrouter").lower()

    # OpenRouter (Suporta modelos gratuitos com :free)
    openrouter_api_key: str = os.getenv("OPENROUTER_API_KEY", "")
    openrouter_base_url: str = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    openrouter_model: str = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free")

    # Alibaba Cloud Model Studio (DashScope / Qwen)
    alibaba_api_key: str = os.getenv("ALIBABA_API_KEY", "") or os.getenv("DASHSCOPE_API_KEY", "")
    alibaba_base_url: str = os.getenv("ALIBABA_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1")
    alibaba_model: str = os.getenv("ALIBABA_MODEL", "qwen-plus")

    # SpaceXAI / xAI
    spacexai_api_key: str = os.getenv("SPACEXAI_API_KEY", "") or os.getenv("XAI_API_KEY", "")
    spacexai_base_url: str = os.getenv("SPACEXAI_BASE_URL", "https://api.x.ai/v1")
    spacexai_model: str = os.getenv("SPACEXAI_MODEL", "grok-2")

    # OpenCode (OpenAI-compatible)
    opencode_api_key: str = os.getenv("OPENCODE_API_KEY", "")
    opencode_base_url: str = os.getenv("OPENCODE_BASE_URL", "https://opencode.ai/inference/openai/v1")
    opencode_model: str = os.getenv("OPENCODE_MODEL", "meta-llama/llama-3.1-8b-instruct")

    # Chaves de API do Google Gemini
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

    # Chaves de API da OpenAI
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    # Parâmetros de rede
    network_timeout: int = int(os.getenv("NETWORK_TIMEOUT", "5"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    # Diretório raiz do projeto
    base_dir: Path = Path(__file__).resolve().parent.parent

    # Pasta padrão para relatórios e arquivos gerados (default: relatorios/)
    output_dir_name: str = os.getenv("OUTPUT_DIR", "relatorios")

    @property
    def output_dir(self) -> Path:
        """Retorna o caminho da pasta padrão de saída para relatórios e artefatos."""
        path = self.base_dir / self.output_dir_name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def resolve_output_path(self, target_path: Optional[str] = None, default_filename: str = "relatorio.md") -> Path:
        """Resolve o caminho de gravação do arquivo gerado pelo agente.
        - Se o usuário forneceu um caminho absoluto, respeita integralmente.
        - Se o usuário forneceu um caminho com pasta (ex: 'subpasta/relatorio.md'), respeita a pasta.
        - Se forneceu apenas o nome do arquivo (ex: 'relatorio.md') ou None, salva na pasta padrão (output_dir).
        """
        raw_name = (target_path or default_filename).strip()
        p = Path(raw_name)

        if p.is_absolute():
            p.parent.mkdir(parents=True, exist_ok=True)
            return p

        # Se especificou um subdiretório relativo (ex: 'pasta/arquivo.md')
        if len(p.parts) > 1:
            full_path = self.base_dir / p
            full_path.parent.mkdir(parents=True, exist_ok=True)
            return full_path

        # Caso contrário, salva dentro do diretório padrão 'relatorios/'
        dest = self.output_dir / p.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        return dest

    @property
    def has_ai_credentials(self) -> bool:
        """Verifica se há credenciais válidas configuradas para o provedor selecionado."""
        if self.ai_provider == "openrouter":
            return bool(self.openrouter_api_key and self.openrouter_api_key.strip())
        elif self.ai_provider in ["alibaba", "dashscope"]:
            return bool(self.alibaba_api_key and self.alibaba_api_key.strip())
        elif self.ai_provider in ["spacexai", "xai"]:
            return bool(self.spacexai_api_key and self.spacexai_api_key.strip())
        elif self.ai_provider == "opencode":
            return bool(self.opencode_api_key and self.opencode_api_key.strip())
        elif self.ai_provider == "gemini":
            return bool(self.gemini_api_key and self.gemini_api_key.strip())
        elif self.ai_provider == "openai":
            return bool(self.openai_api_key and self.openai_api_key.strip())
        return False

    def save_to_env(self) -> None:
        """Salva as configurações atuais no arquivo .env."""
        env_file = self.base_dir / ".env"
        lines = [
            "# =====================================================================",
            "# TeXuGo-GuardIA - Configurações Atualizadas pelo Menu Interativo",
            "# =====================================================================",
            f"AI_PROVIDER={self.ai_provider}",
            "",
            "# OpenRouter",
            f"OPENROUTER_API_KEY={self.openrouter_api_key}",
            f"OPENROUTER_BASE_URL={self.openrouter_base_url}",
            f"OPENROUTER_MODEL={self.openrouter_model}",
            "",
            "# Alibaba Cloud Model Studio (Qwen / DashScope)",
            f"ALIBABA_API_KEY={self.alibaba_api_key}",
            f"ALIBABA_BASE_URL={self.alibaba_base_url}",
            f"ALIBABA_MODEL={self.alibaba_model}",
            "",
            "# SpaceXAI / xAI",
            f"SPACEXAI_API_KEY={self.spacexai_api_key}",
            f"SPACEXAI_BASE_URL={self.spacexai_base_url}",
            f"SPACEXAI_MODEL={self.spacexai_model}",
            "",
            "# OpenCode",
            f"OPENCODE_API_KEY={self.opencode_api_key}",
            f"OPENCODE_BASE_URL={self.opencode_base_url}",
            f"OPENCODE_MODEL={self.opencode_model}",
            "",
            "# Google Gemini",
            f"GEMINI_API_KEY={self.gemini_api_key}",
            f"GEMINI_MODEL={self.gemini_model}",
            "",
            "# OpenAI",
            f"OPENAI_API_KEY={self.openai_api_key}",
            f"OPENAI_MODEL={self.openai_model}",
            "",
            "# Parâmetros Gerais",
            f"OUTPUT_DIR={self.output_dir_name}",
            f"NETWORK_TIMEOUT={self.network_timeout}",
            f"LOG_LEVEL={self.log_level}",
        ]
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


# Instância global reutilizável
settings = Config()
