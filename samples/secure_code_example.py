"""
Arquivo de Exemplo com Código Defensivo e Remediado (TeXGuardIA)

Demonstra como corrigir os 10 apontamentos de segurança identificados
no arquivo didático de testes (vulnerable_code_test.py).
"""

import ast
import hashlib
import html
import json
import os
from pathlib import Path
import sqlite3
from urllib.parse import urlparse
import defusedxml.ElementTree as DefusedET

# =====================================================================
# 1. Correção de Hardcoded Secrets (CWE-798)
# Solução: Carregar de variáveis de ambiente (.env) ou cofre de chaves
# =====================================================================
API_SECRET_KEY = os.getenv("API_SECRET_KEY", "")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "")

# =====================================================================
# 2. Correção de Debug Mode (CWE-489)
# Solução: Flag controlada por variável de ambiente, padrão False em produção
# =====================================================================
IS_DEBUG = os.getenv("APP_DEBUG", "False").lower() in ("true", "1")


# =====================================================================
# 3. Correção de Hash Criptográfico Obsoleto (CWE-328)
# Solução: Uso de PBKDF2-HMAC-SHA256, Argon2 ou SHA-256 com salt
# =====================================================================
def authenticate_user_secure(username: str, raw_password: str, salt: bytes = None) -> str:
    """Gera hash de senha usando derivação criptográfica robusta (PBKDF2-HMAC-SHA256)."""
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", raw_password.encode("utf-8"), salt, 100000)
    return f"{salt.hex()}:{key.hex()}"


# =====================================================================
# 4. Correção de Injeção de SQL (CWE-89)
# Solução: Consultas parametrizadas (Prepared Statements) nativas
# =====================================================================
def search_user_by_query_secure(user_input: str):
    """Executa consulta com parâmetros estruturados, evitando injeção."""
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # O driver substitui o placeholder '?' tratando o dado exclusivamente como literal
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (user_input,))
    return cursor.fetchall()


# =====================================================================
# 5. Correção de Command Injection (CWE-78)
# Solução: Passagem de argumentos em lista estruturada sem invocar shell
# =====================================================================
def run_backup_command_secure(folder_name: str) -> bool:
    """Executa comando do sistema de forma segura sem shell=True."""
    import subprocess
    # Valida o caminho do diretório
    safe_dir = Path(folder_name).resolve()
    if not safe_dir.is_dir():
        raise ValueError("Diretório inválido para backup.")

    # Lista estruturada de argumentos impede injeção de pipes (|), ponto-e-vírgula (;) ou subshells
    cmd = ["tar", "-czvf", "backup.tar.gz", str(safe_dir)]
    res = subprocess.run(cmd, check=True, capture_output=True)
    return res.returncode == 0


# =====================================================================
# 6. Correção de Desserialização Insegura (CWE-502)
# Solução: Uso de formatos neutros de dados como JSON
# =====================================================================
def deserialize_session_data_secure(raw_data: str) -> dict:
    """Desserializa dados utilizando JSON neutro e seguro."""
    session = json.loads(raw_data)
    return session


# =====================================================================
# 7. Correção de Execução Dinâmica de Código eval/exec (CWE-94)
# Solução: Uso de ast.literal_eval para literais ou parser controlado
# =====================================================================
def calculate_expression_secure(expression: str):
    """Avalia de forma segura apenas literais básicos de Python (listas, números, dicts)."""
    try:
        return ast.literal_eval(expression)
    except (ValueError, SyntaxError):
        return None


# =====================================================================
# 8. Correção de Path Traversal (CWE-22)
# Solução: Sanitização de basename e verificação de confinamento de diretório
# =====================================================================
def read_user_file_secure(filename: str) -> bytes:
    """Lê arquivo confinado em diretório seguro impedindo ../ ou traversal."""
    base_dir = Path("uploads").resolve()
    # os.path.basename extrai apenas o nome do arquivo, removendo caminhos relativos
    safe_filename = os.path.basename(filename)
    target_path = (base_dir / safe_filename).resolve()

    # Garante que o caminho final ainda reside dentro do base_dir autorizado
    if not str(target_path).startswith(str(base_dir)):
        raise PermissionError("Tentativa de acesso a diretório restrito.")

    with open(target_path, "rb") as f:
        return f.read()


# =====================================================================
# 9. Correção de Cross-Site Scripting - XSS (CWE-79)
# Solução: Codificação de saída (HTML Escaping) ou templates seguros
# =====================================================================
def render_user_profile_secure(user_input: str) -> str:
    """Escapa caracteres HTML especiais (&, <, >, ', \") impedindo execução de scripts."""
    sanitized_input = html.escape(user_input, quote=True)
    return f"<h1>Perfil de {sanitized_input}</h1>"


# =====================================================================
# 10. Correção de SSRF (CWE-918)
# Solução: Validação estrita contra Whitelist de domínios e bloqueio de IPs privados
# =====================================================================
ALLOWED_DOMAINS = {"api.github.com", "api.empresa.com.br"}

def fetch_remote_resource_secure(target_url: str) -> str:
    """Requisita recurso apenas de domínios homologados em whitelist."""
    import requests
    parsed = urlparse(target_url)

    if parsed.scheme != "https":
        raise ValueError("Apenas protocolo HTTPS é permitido.")

    if parsed.hostname not in ALLOWED_DOMAINS:
        raise PermissionError(f"Domínio não autorizado para requisição externa: {parsed.hostname}")

    # Monta a URL estritamente a partir dos componentes validados
    safe_endpoint = f"https://{parsed.hostname}{parsed.path}"
    resp = requests.get(safe_endpoint, timeout=5)
    return resp.text


# =====================================================================
# 11. Correção de XXE Injection (CWE-611)
# Solução: Uso do defusedxml ou desativação de entidades externas
# =====================================================================
def parse_xml_payload_secure(xml_content: str):
    """Processa XML usando defusedxml, prevenindo ataques de entidades externas e DoS."""
    root = DefusedET.fromstring(xml_content)
    return root
