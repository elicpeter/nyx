import os
import subprocess
import pickle
import yaml
import hashlib
import tempfile

# ───── Deserialization ─────

def load_cached_session(session_file):
    """Loads a pickled session from disk.
    VULN: pickle.load on untrusted data (arbitrary code execution)
    """
    with open(session_file, "rb") as f:
        session = pickle.load(f)
    return session

def load_yaml_config(config_path):
    """Loads YAML configuration.
    VULN: yaml.load without SafeLoader (arbitrary code execution)
    """
    with open(config_path) as f:
        config = yaml.load(f)
    return config

# ───── File operations ─────

def process_upload(request):
    """Saves an uploaded file to a path constructed from user input.
    VULN: request.form flows into open() path (path traversal)
    """
    filename = request.form.get("filename")
    content = request.form.get("content")
    upload_path = os.path.join("/uploads", filename)
    with open(upload_path, "w") as f:
        f.write(content)
    return {"saved": upload_path}

# ───── System commands ─────

def check_disk_usage():
    """Reports disk usage from an env-configured mount point.
    VULN: os.getenv flows into subprocess.check_output
    """
    mount = os.getenv("MOUNT_POINT")
    output = subprocess.check_output(["df", "-h", mount])
    return output.decode()

def compile_template(template_path):
    """Compiles a template by calling an external tool.
    VULN: os.getenv flows into exec (code injection via env)
    """
    compiler = os.getenv("TEMPLATE_COMPILER")
    exec(compiler + "('" + template_path + "')")

# ───── Hashing ─────

def hash_token(token):
    """VULN: MD5 is cryptographically weak, should use sha256+salt."""
    return hashlib.md5(token.encode()).hexdigest()

# ───── Safe utilities ─────

def sanitize_filename(name):
    """Strips path traversal characters from a filename."""
    return os.path.basename(name).replace("..", "")

def safe_hash(data):
    """SAFE: uses SHA-256 with proper salt."""
    salt = os.urandom(16)
    return hashlib.sha256(salt + data.encode()).hexdigest()
