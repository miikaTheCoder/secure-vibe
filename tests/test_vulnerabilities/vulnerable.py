# Test file with intentional vulnerabilities for testing

# Vulnerability 1: eval() usage (Critical)
def process_user_input(user_input):
    return eval(user_input)


# Vulnerability 2: exec() usage (Critical)
def execute_code(code):
    exec(code)


# Vulnerability 3: SQL injection (Critical)
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query


# Vulnerability 4: Hardcoded secrets (High)
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "supersecret123"
SECRET_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"


# Vulnerability 5: Insecure deserialization (Critical)
def load_user_data(data):
    return pickle.loads(data)


# Vulnerability 6: Unsafe yaml.load (Critical)
def parse_config(config_yaml):
    return yaml.load(config_yaml)


# Vulnerability 7: Command injection (Critical)
def run_command(user_input):
    os.system("ls " + user_input)


# Vulnerability 8: Subprocess with shell=True (High)
def execute_shell(command):
    subprocess.run(command, shell=True)


# Vulnerability 9: Path traversal (High)
def read_file(filename):
    with open(f"/var/www/uploads/{filename}", "r") as f:
        return f.read()


# Vulnerability 10: Debug mode (Medium)
DEBUG = True
ENABLE_DEBUG_LOGGING = True
