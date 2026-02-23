# Vulnerable Python Application - For Testing Purposes
# This file contains intentional security vulnerabilities for testing Secure Vibe MCP

import os
import sys
import subprocess
import pickle
import hashlib
import random
import sqlite3
import json
import xml.etree.ElementTree as ET
from flask import Flask, request, render_template_string, redirect
import requests

app = Flask(__name__)

# Database setup
DB_PATH = "app.db"


# ============================================
# VULNERABILITY 1: Code Injection (SEC-001)
# ============================================
@app.route("/api/calculate", methods=["POST"])
def calculate():
    data = request.get_json()
    formula = data.get("formula", "")

    # DANGEROUS: Using eval() with user input
    result = eval(formula)  # SEC-001: Code Injection via eval()

    return json.dumps({"result": result})


# ============================================
# VULNERABILITY 2: SQL Injection (SEC-002)
# ============================================
@app.route("/api/users", methods=["GET"])
def get_users():
    user_id = request.args.get("id", "")

    # DANGEROUS: String formatting in SQL query
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE id = {user_id}"  # SEC-002: SQL Injection
    cursor.execute(query)

    results = cursor.fetchall()
    conn.close()

    return json.dumps({"users": results})


# ============================================
# VULNERABILITY 3: Command Injection (SEC-003)
# ============================================
@app.route("/api/ping", methods=["POST"])
def ping_host():
    data = request.get_json()
    host = data.get("host", "")

    # DANGEROUS: User input in shell command
    cmd = f"ping -c 4 {host}"  # SEC-003: Command Injection
    result = subprocess.check_output(cmd, shell=True)  # SEC-003

    return result.decode()


# ============================================
# VULNERABILITY 4: Command Injection via os.system (SEC-003)
# ============================================
@app.route("/api/backup", methods=["POST"])
def backup_file():
    filename = request.form.get("filename", "")

    # DANGEROUS: User input in os.system
    os.system(f"cp {filename} /backups/")  # SEC-003: Command Injection

    return json.dumps({"status": "success"})


# ============================================
# VULNERABILITY 5: Hardcoded Secrets (SEC-016)
# ============================================
API_KEY = "sk_live_51HYs2jJq3dKl4p9mN"  # SEC-016: Hardcoded API Key
SECRET_KEY = "my-super-secret-key-12345"  # SEC-016: Hardcoded Secret
DB_PASSWORD = "password123"  # SEC-016, SEC-025: Hardcoded Credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # SEC-016: Hardcoded AWS Key


def get_api_data():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    # Use API key...
    return headers


# ============================================
# VULNERABILITY 6: Weak Hash Algorithms (SEC-015)
# ============================================
@app.route("/api/hash", methods=["POST"])
def hash_data():
    data = request.get_json()
    input_data = data.get("data", "")

    # DANGEROUS: Using weak hash algorithms
    md5_hash = hashlib.md5(input_data.encode()).hexdigest()  # SEC-015: MD5
    sha1_hash = hashlib.sha1(input_data.encode()).hexdigest()  # SEC-015: SHA1

    return json.dumps({"md5": md5_hash, "sha1": sha1_hash})


# ============================================
# VULNERABILITY 7: Insecure Random (SEC-017)
# ============================================
def generate_token():
    # DANGEROUS: random is not cryptographically secure
    token = "".join(random.choice("0123456789abcdef") for _ in range(32))  # SEC-017
    return token


def generate_password():
    # DANGEROUS: Predictable password generation
    return str(random.randint(100000, 999999))  # SEC-017


# ============================================
# VULNERABILITY 8: Insecure Deserialization (SEC-026)
# ============================================
@app.route("/api/process", methods=["POST"])
def process_data():
    data = request.get_data()

    # DANGEROUS: Insecure deserialization of untrusted data
    obj = pickle.loads(data)  # SEC-026: Insecure Deserialization

    return json.dumps({"processed": str(obj)})


# ============================================
# VULNERABILITY 9: Path Traversal (SEC-035)
# ============================================
@app.route("/api/download", methods=["GET"])
def download_file():
    filename = request.args.get("filename", "")

    # DANGEROUS: No path validation
    file_path = f"./uploads/{filename}"  # SEC-035: Path Traversal

    with open(file_path, "r") as f:
        content = f.read()

    return content


# ============================================
# VULNERABILITY 10: Template Injection (SEC-008)
# ============================================
@app.route("/api/render", methods=["POST"])
def render_template():
    template = request.form.get("template", "")

    # DANGEROUS: User-controlled template rendering
    result = render_template_string(template)  # SEC-008: SSTI

    return result


# ============================================
# VULNERABILITY 11: SSRF (SEC-031)
# ============================================
@app.route("/api/fetch", methods=["POST"])
def fetch_url():
    data = request.get_json()
    url = data.get("url", "")

    # DANGEROUS: Server-Side Request Forgery
    response = requests.get(url)  # SEC-031: SSRF

    return response.text


# ============================================
# VULNERABILITY 12: XML Injection (SEC-007)
# ============================================
@app.route("/api/xml", methods=["POST"])
def parse_xml():
    xml_data = request.get_data()

    # DANGEROUS: XML parsing without protection
    root = ET.fromstring(xml_data)  # SEC-007: XML Injection, XXE

    return json.dumps({"tag": root.tag})


# ============================================
# VULNERABILITY 13: Open Redirect (SEC-032)
# ============================================
@app.route("/api/redirect")
def redirect_user():
    url = request.args.get("url", "/")

    # DANGEROUS: Unvalidated redirect
    return redirect(url)  # SEC-032: Open Redirect


# ============================================
# VULNERABILITY 14: Debug Information Exposure (SEC-030)
# ============================================
@app.errorhandler(Exception)
def handle_error(error):
    # DANGEROUS: Exposing debug information
    return json.dumps(
        {
            "error": str(error),
            "type": type(error).__name__,
            "traceback": str(sys.exc_info()),  # SEC-030: Debug Info Exposure
            "env": dict(os.environ),  # SEC-030: Environment exposure
        }
    ), 500


# ============================================
# VULNERABILITY 15: Weak Password Hashing (SEC-019, SEC-021)
# ============================================
def hash_password_weak(password):
    # DANGEROUS: No salt, weak algorithm
    return hashlib.sha256(password.encode()).hexdigest()  # SEC-019: Missing Salt


def hash_password_md5(password):
    # DANGEROUS: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()  # SEC-015, SEC-021


# ============================================
# VULNERABILITY 16: Hardcoded Credentials (SEC-025)
# ============================================
def db_connect():
    # DANGEROUS: Hardcoded credentials
    conn = sqlite3.connect(DB_PATH)
    return conn


def login_admin():
    username = "admin"
    password = "admin123"  # SEC-025: Hardcoded Credentials

    # Authenticate...
    return True


# ============================================
# VULNERABILITY 17: Dynamic Code Execution (SEC-001)
# ============================================
@app.route("/api/exec", methods=["POST"])
def exec_code():
    data = request.get_json()
    code = data.get("code", "")

    # DANGEROUS: Executing arbitrary code
    result = exec(code)  # SEC-001: Code Injection via exec()

    return json.dumps({"result": str(result)})


# ============================================
# VULNERABILITY 18: Compile Code Injection (SEC-001)
# ============================================
@app.route("/api/compile", methods=["POST"])
def compile_code():
    data = request.get_json()
    code = data.get("code", "")

    # DANGEROUS: Compiling user code
    compiled = compile(code, "<string>", "exec")  # SEC-001
    exec(compiled)

    return json.dumps({"status": "compiled"})


# ============================================
# VULNERABILITY 19: YAML Loading (if PyYAML is used)
# ============================================
try:
    import yaml

    @app.route("/api/yaml", methods=["POST"])
    def parse_yaml():
        yaml_data = request.get_data()

        # DANGEROUS: Unsafe YAML loading
        data = yaml.load(yaml_data, Loader=yaml.Loader)  # SEC-026: Insecure Deserialization

        return json.dumps(data)
except ImportError:
    pass


# ============================================
# VULNERABILITY 20: Subprocess with Shell (SEC-003)
# ============================================
def process_user_input(user_input):
    # DANGEROUS: Multiple command injection vectors
    os.popen(user_input)  # SEC-003
    subprocess.call(user_input, shell=True)  # SEC-003
    subprocess.Popen(user_input, shell=True)  # SEC-003


# ============================================
# VULNERABILITY 21: Regex DoS (SEC-044)
# ============================================
import re


@app.route("/api/validate", methods=["POST"])
def validate_email():
    data = request.get_json()
    email = data.get("email", "")

    # DANGEROUS: Regex vulnerable to ReDoS
    pattern = r"^([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})*$"  # SEC-044: ReDoS
    is_valid = re.match(pattern, email) is not None

    return json.dumps({"valid": is_valid})


# ============================================
# VULNERABILITY 22: Information Leakage (SEC-027, SEC-028)
# ============================================
import logging


@app.route("/api/register", methods=["POST"])
def register_user():
    data = request.get_json()

    # DANGEROUS: Logging sensitive data
    logging.info(f"User registration: {data}")  # SEC-027, SEC-028: PII Logging

    # DANGEROUS: Verbose error messages
    try:
        user_id = create_user(data)
    except Exception as e:
        return json.dumps({"error": f"Database error: {str(e)}"}), 500  # SEC-030

    return json.dumps({"user_id": user_id})


def create_user(data):
    # Implementation...
    pass


# ============================================
# VULNERABILITY 23: Insecure File Permissions (SEC-039)
# ============================================
def create_temp_file():
    import tempfile

    # DANGEROUS: World-readable temp file
    fd, path = tempfile.mkstemp()
    os.chmod(path, 0o777)  # SEC-039: Unsafe File Permissions

    return path


# ============================================
# VULNERABILITY 24: Timing Attack Vulnerability (SEC-024)
# ============================================
def verify_password(stored, provided):
    # DANGEROUS: String comparison vulnerable to timing attacks
    if stored == provided:  # Should use hmac.compare_digest
        return True
    return False


# ============================================
# Additional vulnerable functions
# ============================================


def dangerous_import(module_name):
    # DANGEROUS: Dynamic import with user input
    module = __import__(module_name)  # SEC-001
    return module


def dangerous_eval(expression):
    # DANGEROUS: Using eval
    return eval(expression)  # SEC-001


def dangerous_exec(code):
    # DANGEROUS: Using exec
    exec(code)  # SEC-001


# Run the app
if __name__ == "__main__":
    print("⚠️  WARNING: This application contains intentional security vulnerabilities!")
    print("🔒 Use only for testing Secure Vibe MCP scanner")
    print()

    # DANGEROUS: Debug mode enabled
    app.run(debug=True, host="0.0.0.0")  # SEC-030: Debug mode in production
