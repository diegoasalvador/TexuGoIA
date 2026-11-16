"""
Orquestrador Principal do Agente Inteligente TeXuGo-GuardIA.

Integra analisadores especializados (SAST, Web, Portas) com modelos de Inteligência Artificial
(Google Gemini, OpenAI, OpenRouter, Alibaba ou heurística offline) para gerar diagnósticos e planos de remediação.
"""

import warnings
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Silencia aviso de depreciação do google.generativeai legado
warnings.filterwarnings("ignore", category=FutureWarning, module="google.generativeai")

from TeXGuardIA.config import settings
from TeXGuardIA.knowledge.owasp_rules import VulnerabilityInfo
from TeXGuardIA.analyzers.code_analyzer import CodeAnalyzer
from TeXGuardIA.analyzers.web_analyzer import WebAnalyzer
from TeXGuardIA.analyzers.port_analyzer import PortAnalyzer

# Importação condicional de SDKs de IA
try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=FutureWarning)
        import google.generativeai as genai
    GEMINI_SDK_AVAILABLE = True
except ImportError:
    GEMINI_SDK_AVAILABLE = False

try:
    from openai import OpenAI
    OPENAI_SDK_AVAILABLE = True
except ImportError:
    OPENAI_SDK_AVAILABLE = False


AGENT_PERSONAS = {
    "appsec": {
        "title": "Especialista em AppSec / SAST & Código Seguro (Padrão)",
        "mission": "Proteger o código-fonte e o ciclo de desenvolvimento de software (DevSecOps / Shift-Left).",
        "description": "Foco em OWASP Top 10, CWEs, injeções (SQLi, XSS, RCE), segredos expostos e geração de patches.",
        "can_request": [
            "Auditoria estática de código (Python, JS, PHP, C, Go, etc.)",
            "Geração de patches seguros e código corrigido (Prepared Statements, ORM, sanitização)",
            "Configuração de cabeçalhos de segurança web (CSP, HSTS, SameSite Cookies)",
            "Identificação de CVEs e vulnerabilidades em bibliotecas de terceiros (SCA)"
        ],
        "programs": ["bandit", "semgrep", "safety", "trufflehog", "npm audit"],
        "sample_commands": [
            "pip install bandit semgrep safety",
            "bandit -r ./app -ll",
            "semgrep --config=auto .",
            "safety check"
        ],
        "prompt": """Você é o TeXuGo-GuardIA atuando como Engenheiro Sênior de AppSec (Application Security) e DevSecOps.
Missão: Analisar vulnerabilidades de código (OWASP Top 10, CWEs, injeções, segredos expostos), explicar a mecânica da falha de forma didática e fornecer código defensivo de remediação (patches funcionais).
Ferramentas de Referência: bandit, semgrep, safety, trufflehog, npm audit.
Regras Estritas: Seja direto, técnico e assertivo. Não faça saudações nem encenações. Forneça código corrigido e comandos de terminal reais e sintaticamente válidos."""
    },
    "redteam": {
        "title": "Auditor Red Team / Pentester & Avaliação Ofensiva",
        "mission": "Pensar e agir como um adversário para encontrar brechas, encadear falhas e validar defesas.",
        "description": "Foco em superfície de ataque exposta, enumeração de serviços, exploração conceitual e testes de intrusão.",
        "can_request": [
            "Simulação conceitual de vetores de ataque e encadeamento de falhas (Exploit Chaining)",
            "Comandos de reconhecimento ativo, enumeração de portas, serviços e subdomínios",
            "Recomendação de ferramentas profissionais de pentest para instalação e execução",
            "Elaboração de Provas de Conceito (PoC) defensivas para apresentação a comitês de segurança"
        ],
        "programs": ["nmap", "masscan", "nikto", "gobuster", "ffuf", "sqlmap", "curl"],
        "sample_commands": [
            "sudo apt install -y nmap masscan nikto gobuster",
            "nmap -sV -sC -p 21,22,80,443 <alvo>",
            'nmap -p 80,443 --script "http-vuln*" <alvo>',
            "gobuster dir -u http://<alvo> -w /usr/share/wordlists/dirb/common.txt",
            "curl -I -k https://<alvo>"
        ],
        "prompt": """Você é o TeXuGo-GuardIA atuando como Auditor Sênior de Red Team e Especialista em Testes de Intrusão (Pentesting).
Missão: Avaliar a perspectiva adversária — criticidade de superfícies expostas, viabilidade de exploração, vetores de ataque e encadeamento de falhas (exploit chaining), orientando como simular ataques de forma controlada para fortalecer as defesas.
Regras Estritas: Seja direto e operacional. Forneça comandos de shell Linux exatos e completos para execução no Arch Linux. NUNCA use reticências '...' dentro de comandos executáveis e NUNCA deixe aspas abertas ou parâmetros incompletos. Priorize ferramentas já presentes como nmap, ping, curl e masscan."""
    },
    "blueteam": {
        "title": "Especialista Blue Team / Hardening & SecOps",
        "mission": "Defender a infraestrutura, conter incidentes, configurar firewalls e aplicar hardening nos sistemas.",
        "description": "Foco em contenção imediata, regras de firewall (UFW, IPTables), mitigação de DoS/Bruteforce e SecOps.",
        "can_request": [
            "Comandos imediatos de bloqueio de portas expostas e isolamento de tráfego de rede",
            "Arquivos de configuração segura para Nginx, Apache, SSH (/etc/ssh/sshd_config) e MySQL",
            "Instalação e configuração de ferramentas de proteção (Fail2ban, UFW, ModSecurity, Auditd)",
            "Playbooks de resposta a incidentes e contenção de invasões em tempo real"
        ],
        "programs": ["ufw", "iptables", "fail2ban", "auditd", "suricata", "lynis"],
        "sample_commands": [
            "sudo apt install -y ufw fail2ban auditd lynis",
            "sudo ufw default deny incoming",
            "sudo ufw deny 21/tcp && sudo ufw deny 23/tcp",
            "sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp",
            "sudo systemctl restart fail2ban"
        ],
        "prompt": """Você é o TeXuGo-GuardIA atuando como Especialista Blue Team e Engenheiro de Hardening e SecOps.
Missão: Proteger a infraestrutura, fechar superfícies expostas, aplicar regras de firewall, endurecer configurações de SO/serviços e mitigar incidentes em andamento.
Ferramentas de Referência: ufw, iptables, fail2ban, auditd, suricata, lynis.
Regras Estritas: Seja extremamente prático. Entregue comandos de terminal Linux prontos para execução imediata e arquivos de configuração exatos. Sem floreios ou repetições."""
    },
    "compliance": {
        "title": "Consultor de Conformidade (GRC / ISO 27001 / LGPD / CIS)",
        "mission": "Alinhar a postura técnica com leis e normas regulatórias, traduzindo falhas técnicas em riscos de negócio.",
        "description": "Foco em conformidade regulatória (LGPD, GDPR), normas (ISO/IEC 27001, NIST CSF, CIS) e governança.",
        "can_request": [
            "Mapeamento de vulnerabilidades para artigos da LGPD e controles da ISO 27001",
            "Elaboração de Matrizes de Risco (Probabilidade x Impacto) para a diretoria",
            "Comandos de varredura automatizada de conformidade (CIS Benchmarks via Lynis/OpenSCAP)",
            "Criação de Planos de Ação de Remediação e Políticas de Segurança da Informação (PSI)"
        ],
        "programs": ["lynis", "libopenscap8", "scap-workbench"],
        "sample_commands": [
            "sudo apt install -y lynis libopenscap8",
            "sudo lynis audit system --quick",
            "oscap oval eval --results relatorio.xml oval-definitions.xml"
        ],
        "prompt": """Você é o TeXuGo-GuardIA atuando como Consultor Sênior de Governança, Riscos e Conformidade (GRC).
Missão: Mapear vulnerabilidades técnicas contra legislações (LGPD, GDPR) e frameworks (ISO 27001, NIST CSF, CIS Benchmarks), produzindo diagnósticos com visão de risco para o negócio e auditoria formal.
Ferramentas de Referência: lynis, openscap, CIS benchmarks.
Regras Estritas: Seja formal, estruturado e técnico, sem prolixidade. Forneça matrizes de risco claras e comandos de auditoria de conformidade válidos."""
    }
}


class TeXGuardIAAgent:
    """Agente autônomo inteligente para diagnóstico e mitigação de vulnerabilidades (TeXGuardIA)."""

    def __init__(self):
        self.code_analyzer = CodeAnalyzer()
        self.web_analyzer = WebAnalyzer()
        self.port_analyzer = PortAnalyzer()
        self.ai_client = None
        self.provider = settings.ai_provider
        self.current_persona_key = "appsec"
        self.system_prompt = AGENT_PERSONAS["appsec"]["prompt"]
        self.chat_history: List[Dict[str, str]] = []
        self._init_ai_backend()

    def clear_chat_history(self) -> None:
        """Limpa o histórico de mensagens mantido na memória da sessão de chat."""
        self.chat_history.clear()

    def set_persona(self, persona_key: str) -> bool:
        """Altera a persona/perfil do agente de segurança."""
        if persona_key in AGENT_PERSONAS:
            self.current_persona_key = persona_key
            self.system_prompt = AGENT_PERSONAS[persona_key]["prompt"]
            if self.provider == "gemini" and self.ai_client:
                try:
                    self.ai_client = genai.GenerativeModel(
                        model_name=settings.gemini_model,
                        system_instruction=self.system_prompt
                    )
                except Exception:
                    pass
            return True
        return False

    def get_active_persona(self) -> dict:
        """Retorna os dados da persona atualmente ativa."""
        return {
            "key": self.current_persona_key,
            **AGENT_PERSONAS.get(self.current_persona_key, AGENT_PERSONAS["appsec"])
        }

    def reload_config(self) -> None:
        """Recarrega configurações e reinicializa cliente de IA."""
        self.provider = settings.ai_provider
        self._init_ai_backend()

    def _init_ai_backend(self) -> None:
        """Inicializa o cliente do modelo de linguagem configurado."""
        if self.provider == "openrouter" and settings.openrouter_api_key and OPENAI_SDK_AVAILABLE:
            try:
                self.ai_client = OpenAI(
                    api_key=settings.openrouter_api_key,
                    base_url=settings.openrouter_base_url,
                    default_headers={
                        "HTTP-Referer": "https://github.com/texguardia",
                        "X-Title": "TeXuGo-GuardIA Cybersecurity Agent",
                    }
                )
            except Exception:
                self.ai_client = None
        elif self.provider in ["alibaba", "dashscope"] and settings.alibaba_api_key and OPENAI_SDK_AVAILABLE:
            try:
                self.ai_client = OpenAI(
                    api_key=settings.alibaba_api_key,
                    base_url=settings.alibaba_base_url
                )
            except Exception:
                self.ai_client = None
        elif self.provider in ["spacexai", "xai"] and settings.spacexai_api_key and OPENAI_SDK_AVAILABLE:
            try:
                self.ai_client = OpenAI(
                    api_key=settings.spacexai_api_key,
                    base_url=settings.spacexai_base_url
                )
            except Exception:
                self.ai_client = None
        elif self.provider == "opencode" and settings.opencode_api_key and OPENAI_SDK_AVAILABLE:
            try:
                self.ai_client = OpenAI(
                    api_key=settings.opencode_api_key,
                    base_url=settings.opencode_base_url
                )
            except Exception:
                self.ai_client = None
        elif self.provider == "gemini" and settings.gemini_api_key and GEMINI_SDK_AVAILABLE:
            try:
                genai.configure(api_key=settings.gemini_api_key)
                self.ai_client = genai.GenerativeModel(
                    model_name=settings.gemini_model,
                    system_instruction=self.system_prompt
                )
            except Exception:
                self.ai_client = None
        elif self.provider == "openai" and settings.openai_api_key and OPENAI_SDK_AVAILABLE:
            try:
                self.ai_client = OpenAI(api_key=settings.openai_api_key)
            except Exception:
                self.ai_client = None

    def test_connection(self) -> Tuple[bool, str]:
        """Testa a conectividade com o modelo e a API ativa."""
        if not self.is_ai_ready():
            return False, f"Provedor '{self.provider}' não possui chave de API válida ou SDK correspondente ausente."

        test_msg = "Responda apenas 'Conectado com sucesso!' em poucas palavras."
        try:
            if self.provider == "openrouter":
                res = self.ai_client.chat.completions.create(
                    model=settings.openrouter_model,
                    messages=[{"role": "user", "content": test_msg}],
                    max_tokens=250
                )
                msg_txt = (res.choices[0].message.content or "OK").strip()
                return True, f"OpenRouter conectado! Resposta: {msg_txt}"
            elif self.provider in ["alibaba", "dashscope"]:
                res = self.ai_client.chat.completions.create(
                    model=settings.alibaba_model,
                    messages=[{"role": "user", "content": test_msg}],
                    max_tokens=250
                )
                msg_txt = (res.choices[0].message.content or "OK").strip()
                return True, f"Alibaba Model Studio conectado! Resposta: {msg_txt}"
            elif self.provider in ["spacexai", "xai"]:
                res = self.ai_client.chat.completions.create(
                    model=settings.spacexai_model,
                    messages=[{"role": "user", "content": test_msg}],
                    max_tokens=250
                )
                msg_txt = (res.choices[0].message.content or "OK").strip()
                return True, f"SpaceXAI conectado! Resposta: {msg_txt}"
            elif self.provider == "opencode":
                res = self.ai_client.chat.completions.create(
                    model=settings.opencode_model,
                    messages=[{"role": "user", "content": test_msg}],
                    max_tokens=250
                )
                msg_txt = (res.choices[0].message.content or "OK").strip()
                return True, f"OpenCode conectado! Resposta: {msg_txt}"
            elif self.provider == "gemini":
                res = self.ai_client.generate_content(test_msg)
                msg_txt = (getattr(res, "text", "") or "OK").strip()
                return True, f"Google Gemini conectado! Resposta: {msg_txt}"
            elif self.provider == "openai":
                res = self.ai_client.chat.completions.create(
                    model=settings.openai_model,
                    messages=[{"role": "user", "content": test_msg}],
                    max_tokens=250
                )
                msg_txt = (res.choices[0].message.content or "OK").strip()
                return True, f"OpenAI conectado! Resposta: {msg_txt}"
        except Exception as e:
            err_str = str(e)
            if "AccessDenied.Unpurchased" in err_str:
                return False, (
                    "Alibaba Model Studio: O modelo atual não está ativado no seu plano.\n"
                    "👉 Dica 1: No menu do TeXuGo-GuardIA, vá em '[4] Selecionar Modelo' e escolha '[3] qwen-turbo'.\n"
                    "👉 Dica 2: No console da Alibaba (modelstudio.console.alibabacloud.com), vá em 'Billing' ou 'Model Gallery' e clique em 'Free Trial' / 'Apply' para resgatar os tokens gratuitos do qwen-plus."
                )
            return False, f"Falha na comunicação com a API: {err_str}"

        return False, "Provedor desconhecido."

    def is_ai_ready(self) -> bool:
        """Indica se um provedor de IA com credenciais válidas está ativo."""
        return self.ai_client is not None

    def analyze_code(self, target_path: str, use_ai: bool = True) -> Tuple[List[VulnerabilityInfo], str]:
        """Executa auditoria SAST em código ou documento/configuração e opcionalmente gera parecer via IA."""
        vulnerabilities = self.code_analyzer.scan_path(target_path)
        summary = ""

        # Lê o conteúdo do arquivo alvo para que a IA possa analisar profundamente o documento/código
        file_content = None
        p = Path(target_path)
        if p.exists() and p.is_file():
            try:
                file_content = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                file_content = None

        if use_ai and self.is_ai_ready():
            is_doc = p.suffix.lower() in [".md", ".txt", ".log", ".cfg", ".conf", ".audit", ".xsf", ".ini"]
            ctx_type = "Auditoria Forense / Análise de Documento e Configuração" if is_doc else "Análise SAST de Código-Fonte"
            summary = self._consult_ai(ctx_type, target_path, vulnerabilities, target_content=file_content)
        else:
            summary = self._generate_heuristic_summary("Código-Fonte (SAST)", target_path, vulnerabilities)

        return vulnerabilities, summary

    def analyze_web(self, target_url: str, use_ai: bool = True) -> Tuple[List[VulnerabilityInfo], str]:
        """Executa auditoria de cabeçalhos e configurações web."""
        vulnerabilities = self.web_analyzer.scan_url(target_url)
        summary = ""

        if use_ai and self.is_ai_ready():
            summary = self._consult_ai("Análise de Superfície Web e Headers HTTP", target_url, vulnerabilities)
        else:
            summary = self._generate_heuristic_summary("Superfície Web", target_url, vulnerabilities)

        return vulnerabilities, summary

    def analyze_network(self, host: str, ports: Optional[List[int]] = None, use_ai: bool = True) -> Tuple[List[VulnerabilityInfo], str]:
        """Executa verificação de serviços e portas expostas."""
        vulnerabilities = self.port_analyzer.scan_host(host, ports)
        summary = ""

        if use_ai and self.is_ai_ready():
            summary = self._consult_ai("Análise de Portas e Serviços de Rede", host, vulnerabilities)
        else:
            summary = self._generate_heuristic_summary("Portas e Serviços de Rede", host, vulnerabilities)

        return vulnerabilities, summary

    @staticmethod
    def _extract_message_content(message: TeXuGoGuardIA) -> str:
        """Extrai o texto da resposta do modelo com salvaguardas contra None, tool_calls ou reasoning."""
        if message is None:
            return "Nenhuma resposta retornada pelo modelo de IA."

        content = getattr(message, "content", None)
        if content and isinstance(content, str) and content.strip():
            return content.strip()

        # Se o modelo gerou chamadas de ferramentas (tool_calls)
        tool_calls = getattr(message, "tool_calls", None)
        if tool_calls:
            calls_desc = []
            for tc in tool_calls:
                fn = getattr(tc, "function", None)
                if fn:
                    fn_name = getattr(fn, "name", "exec")
                    fn_args = getattr(fn, "arguments", "")
                    calls_desc.append(f"```bash\n# Proposta da IA ({fn_name})\n{fn_args}\n```")
                else:
                    calls_desc.append(f"```\n{tc}\n```")
            return "🤖 O modelo de IA propôs as seguintes ações:\n\n" + "\n\n".join(calls_desc)

        # Se o modelo gerou reasoning (raciocínio técnico)
        reasoning = getattr(message, "reasoning", None)
        if reasoning and isinstance(reasoning, str) and reasoning.strip():
            return reasoning.strip()

        refusal = getattr(message, "refusal", None)
        if refusal and isinstance(refusal, str) and refusal.strip():
            return f"⚠️ Resposta recusada pelo provedor: {refusal.strip()}"

        return "Nenhum conteúdo de texto retornado pelo provedor de IA."

    def chat_security_consultant(self, user_prompt: str) -> str:
        """Permite ao usuário consultar o agente sobre dúvidas de cibersegurança."""
        if not self.is_ai_ready():
            return (
                "ℹ️ **Modo Heurístico Ativo:** Para interações conversacionais com IA gerativa, "
                "configure a chave de API no arquivo `.env` (ex: GEMINI_API_KEY=sua_chave)."
            )

        # Prepara histórico de mensagens para conversa contextual contínua
        conv_messages = [{"role": "system", "content": self.system_prompt}]
        conv_messages.extend(self.chat_history[-8:])
        conv_messages.append({"role": "user", "content": user_prompt})

        reply = ""
        try:
            if self.provider == "openrouter":
                response = self.ai_client.chat.completions.create(
                    model=settings.openrouter_model,
                    messages=conv_messages,
                    temperature=0.3,
                    frequency_penalty=0.4
                )
                reply = self._extract_message_content(response.choices[0].message)
            elif self.provider in ["alibaba", "dashscope"]:
                response = self.ai_client.chat.completions.create(
                    model=settings.alibaba_model,
                    messages=conv_messages,
                    temperature=0.3,
                    frequency_penalty=0.4
                )
                reply = self._extract_message_content(response.choices[0].message)
            elif self.provider in ["spacexai", "xai"]:
                response = self.ai_client.chat.completions.create(
                    model=settings.spacexai_model,
                    messages=conv_messages,
                    temperature=0.3,
                    frequency_penalty=0.4
                )
                reply = self._extract_message_content(response.choices[0].message)
            elif self.provider == "opencode":
                response = self.ai_client.chat.completions.create(
                    model=settings.opencode_model,
                    messages=conv_messages,
                    temperature=0.3,
                    frequency_penalty=0.4
                )
                reply = self._extract_message_content(response.choices[0].message)
            elif self.provider == "gemini":
                gemini_contents = []
                for m in self.chat_history[-8:]:
                    r = "user" if m.get("role") == "user" else "model"
                    gemini_contents.append({"role": r, "parts": [m.get("content", "")]})
                gemini_contents.append({"role": "user", "parts": [user_prompt]})
                response = self.ai_client.generate_content(gemini_contents)
                reply = response.text if hasattr(response, "text") and response.text else "Sem resposta do Gemini."
            elif self.provider == "openai":
                response = self.ai_client.chat.completions.create(
                    model=settings.openai_model,
                    messages=conv_messages,
                    temperature=0.3,
                    frequency_penalty=0.4
                )
                reply = self._extract_message_content(response.choices[0].message)

            if reply and not reply.startswith("❌"):
                self.chat_history.append({"role": "user", "content": user_prompt})
                self.chat_history.append({"role": "assistant", "content": reply})

            return reply or "Sem resposta disponível."

        except Exception as e:
            err_msg = str(e)
            if "429" in err_msg and self.provider == "openrouter" and settings.alibaba_api_key:
                from TeXGuardIA.ui import console_print
                console_print("\n[bold yellow]⚠️ Limite diário gratuito do OpenRouter atingido (429 Rate Limit).[/bold yellow]")
                console_print("[bold cyan]🔄 Alternando automaticamente para o provedor Alibaba Cloud (Qwen)...[/bold cyan]\n")
                self.provider = "alibaba"
                self._init_ai_backend()
                return self.chat_security_consultant(user_prompt)
            return f"❌ Erro ao consultar a API de IA: {err_msg}"

    def _consult_ai(
        self,
        context_type: str,
        target: str,
        vulnerabilities: List[VulnerabilityInfo],
        target_content: Optional[str] = None
    ) -> str:
        """Monta o prompt de auditoria e submete ao modelo de IA."""
        findings_payload = []
        for idx, v in enumerate(vulnerabilities[:15], 1):  # Limita para eficiência de tokens
            findings_payload.append(
                f"{idx}. [{v.severity}] {v.title} (CWE: {v.cwe}) - Local/Alvo: {v.file_path or v.target}\n"
                f"   Snippet/Detalhe: {v.code_snippet or v.description}"
            )

        content_section = ""
        if target_content and target_content.strip():
            # Limita a 45.000 caracteres para manter performance e eficiência de tokens
            preview = target_content[:45000]
            if len(target_content) > 45000:
                preview += f"\n\n[... Truncado para caber no limite de contexto ({len(target_content)} bytes totais) ...]"
            content_section = (
                f"\nConteúdo do Alvo Analisado ({target}):\n"
                f"```text\n{preview}\n```\n"
            )

        prompt = (
            f"Você está avaliando o seguinte alvo em uma auditoria técnica de segurança:\n"
            f"- Tipo de Análise: {context_type}\n"
            f"- Alvo: {target}\n"
            f"- Total de Vulnerabilidades Detectadas pelo Scanner Local: {len(vulnerabilities)}\n"
            f"{content_section}\n"
            f"Achados Sintáticos do Scanner Local:\n"
            f"{chr(10).join(findings_payload) if findings_payload else 'Nenhuma vulnerabilidade estática de código detectada pelo scanner local.'}\n\n"
            f"Instruções Estritas de Formatação:\n"
            f"- Seja 100% técnico, direto e objetivo. Não faça saudações, dramatizações ou apresentações pessoais.\n"
            f"- Se houver conteúdo do arquivo acima, analise profundamente os dados, logs, evidências, configurações, falhas ou incidentes descritos nele.\n"
            f"- Não repita a lista de achados acima em texto corrido; vá direto aos pontos de análise e ação.\n"
            f"- Forneça comandos de shell Linux REAIS e EXATOS (ex: ufw, iptables, openssl, nmap, hashcat, curl, etc.) e trechos de código/configuração corrigidos.\n\n"
            f"Estrutura Obrigatória da Resposta:\n"
            f"1. **Avaliação Geral da Postura de Segurança** (análise crítica do impacto real com base nas evidências e dados do arquivo);\n"
            f"2. **Top Riscos Imediatos e Ações de Contenção** (comandos operacionais de mitigação);\n"
            f"3. **Código / Configuração de Remediação** (patch funcional, comandos de hardening ou plano de mitigação)."
        )

        try:
            if self.provider == "openrouter":
                response = self.ai_client.chat.completions.create(
                    model=settings.openrouter_model,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2,
                    frequency_penalty=0.4
                )
                return self._extract_message_content(response.choices[0].message)
            elif self.provider in ["alibaba", "dashscope"]:
                response = self.ai_client.chat.completions.create(
                    model=settings.alibaba_model,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2,
                    frequency_penalty=0.4
                )
                return self._extract_message_content(response.choices[0].message)
            elif self.provider in ["spacexai", "xai"]:
                response = self.ai_client.chat.completions.create(
                    model=settings.spacexai_model,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2,
                    frequency_penalty=0.4
                )
                return self._extract_message_content(response.choices[0].message)
            elif self.provider == "opencode":
                response = self.ai_client.chat.completions.create(
                    model=settings.opencode_model,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2,
                    frequency_penalty=0.4
                )
                return self._extract_message_content(response.choices[0].message)
            elif self.provider == "gemini":
                response = self.ai_client.generate_content(prompt)
                return response.text if hasattr(response, "text") and response.text else "Sem resposta do Gemini."
            elif self.provider == "openai":
                response = self.ai_client.chat.completions.create(
                    model=settings.openai_model,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2,
                    frequency_penalty=0.4
                )
                return self._extract_message_content(response.choices[0].message)
        except Exception as e:
            err_msg = str(e)
            if "429" in err_msg and self.provider == "openrouter" and settings.alibaba_api_key:
                from TeXGuardIA.ui import console_print
                console_print("\n[bold yellow]⚠️ Limite diário gratuito do OpenRouter atingido (429 Rate Limit).[/bold yellow]")
                console_print("[bold cyan]🔄 Alternando automaticamente para o provedor Alibaba Cloud (Qwen)...[/bold cyan]\n")
                self.provider = "alibaba"
                self._init_ai_backend()
                return self._consult_ai(context_type, target, vulnerabilities)
            return f"⚠️ Falha na consulta ao modelo de IA ({err_msg}). Recorrendo à análise heurística interna."

        return self._generate_heuristic_summary(context_type, target, vulnerabilities)

    def _generate_heuristic_summary(self, context_type: str, target: str, vulnerabilities: List[VulnerabilityInfo]) -> str:
        """Gera um diagnóstico estruturado e inteligente sem necessidade de conexão com API externa."""
        if not vulnerabilities:
            return (
                "🛡️ **Status de Segurança:** Postura Defensiva Conforme.\n\n"
                f"Nenhuma vulnerabilidade foi detectada na verificação de {context_type} para `{target}`. "
                "Recomenda-se manter verificações contínuas no pipeline de CI/CD."
            )

        counts = {"CRÍTICA": 0, "ALTA": 0, "MÉDIA": 0, "BAIXA": 0, "INFORMATIVA": 0}
        for v in vulnerabilities:
            counts[v.severity.upper()] = counts.get(v.severity.upper(), 0) + 1

        top_findings = sorted(
            vulnerabilities,
            key=lambda x: {"CRÍTICA": 4, "ALTA": 3, "MÉDIA": 2, "BAIXA": 1, "INFORMATIVA": 0}.get(x.severity.upper(), 0),
            reverse=True
        )[:3]

        lines = [
            f"🛡️ **Parecer do Motor Heurístico TeXuGo-GuardIA:**\n",
            f"Foram identificados **{len(vulnerabilities)} apontamentos** no alvo `{target}`:",
            f"- **{counts['CRÍTICA']} Críticas** | **{counts['ALTA']} Altas** | **{counts['MÉDIA']} Médias** | **{counts['BAIXA']} Baixas**\n",
            "**Prioridades Recomendadas de Mitigação:**"
        ]

        for i, item in enumerate(top_findings, start=1):
            lines.append(f"{i}. **[{item.severity}] {item.title}** ({item.cwe}): {item.remediation}")

        lines.append("\n*Dica: Adicione sua chave de API no arquivo `.env` para enriquecer esta análise com insights avançados de LLM.*")
        return "\n".join(lines)


# Aliases para conformidade com nomenclaturas legadas
TeXuGoGuardIA = TeXGuardIAAgent
GuardAIAgent = TeXGuardIAAgent
