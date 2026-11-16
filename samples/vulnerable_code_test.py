"""
Arquivo de Exemplo para Demonstração de Auditoria SAST do TeXGuardIA.

ATENÇÃO: Este arquivo contém padrões intencionalmente inseguros apenas para
fins didáticos de validação e teste dos analisadores do TeXGuardIA.
"""

import os
import pickle
import hashlib
import sqlite3

# 1. Credencial Fixada no Código (Hardcoded Secret) - CWE-798
API_SECRET_KEY = "dummy_test_api_key_for_sast_educational_purposes"
DATABASE_PASSWORD = "fake_educational_password_123"

# 2. Flag de Depuração Ativa em Código - CWE-489
DEBUG = True


def authenticate_user(username, raw_password):
    # 3. Uso de Hash Criptográfico Obsoleto (MD5) - CWE-328
    password_hash = hashlib.md5(raw_password.encode()).hexdigest()
    return password_hash


def search_user_by_query(user_input):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # 4. Injeção de SQL via Concatenação de String - CWE-89
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchall()


def run_backup_command(folder_name):
    # 5. Injeção de Comandos de Sistema Operacional (Command Injection) - CWE-78
    command = f"tar -czvf backup.tar.gz {folder_name}"
    os.system(command)


def deserialize_session_data(raw_data):
    # 6. Desserialização Insegura com pickle - CWE-502
    session = pickle.loads(raw_data)
    return session


def calculate_expression(expression):
    # 7. Execução dinâmica de código via eval() - CWE-94
    return eval(expression)


def read_user_file(filename):
    # 8. Path Traversal / File Inclusion - CWE-22
    with open("uploads/" + filename, "rb") as f:
        return f.read()


def render_user_profile(user_input):
    # 9. Cross-Site Scripting (XSS) / Renderização insegura - CWE-79
    return render_template_string(f"<h1>Perfil de {user_input}</h1>")


def fetch_remote_resource(target_url):
    # 10. Server-Side Request Forgery (SSRF) - CWE-918
    import requests
    return requests.get(target_url, timeout=5).text


def parse_xml_payload(xml_content):
    # 11. XML External Entity (XXE Injection) - CWE-611
    from lxml import etree
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(xml_content, parser=parser)
