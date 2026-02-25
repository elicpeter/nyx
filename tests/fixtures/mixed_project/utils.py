import os
import subprocess
import shlex

# Infrastructure provisioning tool — Python automation scripts.
# Handles configuration management and deployment automation.

# ───── Configuration management ─────

def sync_config():
    """Syncs configuration from a remote source.
    VULN: os.getenv flows into subprocess.run (command injection)
    """
    remote = os.getenv("CONFIG_REMOTE_URL")
    local_dir = os.getenv("CONFIG_LOCAL_DIR")
    subprocess.run(["rsync", "-avz", remote, local_dir])

def apply_ansible_playbook():
    """Runs an Ansible playbook from env-configured path.
    VULN: os.getenv flows into subprocess.Popen (command injection)
    """
    playbook = os.getenv("ANSIBLE_PLAYBOOK")
    inventory = os.getenv("ANSIBLE_INVENTORY")
    proc = subprocess.Popen(
        ["ansible-playbook", "-i", inventory, playbook],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Playbook failed: {stderr.decode()}")
    return stdout.decode()

# ───── Secret management ─────

def rotate_secrets():
    """Rotates secrets by calling a vault CLI.
    VULN: os.getenv flows into os.system (command injection)
    """
    vault_addr = os.getenv("VAULT_ADDR")
    vault_token = os.getenv("VAULT_TOKEN")
    os.system(f"vault write -address={vault_addr} secret/app/key value=rotated")

def inject_secrets():
    """Injects secrets into the environment from vault.
    VULN: os.getenv flows into eval (code injection via env)
    """
    secret_loader = os.getenv("SECRET_LOADER_EXPR")
    secrets = eval(secret_loader)
    return secrets

# ───── Monitoring ─────

def check_service_health():
    """Checks health of all configured services.
    VULN: os.getenv flows into subprocess.call
    """
    services = os.getenv("MONITORED_SERVICES", "").split(",")
    for svc in services:
        subprocess.call(["curl", "-sf", f"http://{svc}/health"])

# ───── Safe patterns ─────

def safe_exec():
    """SAFE: shlex.quote properly sanitizes before shell use."""
    user_path = os.getenv("USER_PATH")
    safe_path = shlex.quote(user_path)
    subprocess.run(f"ls -la {safe_path}", shell=True, capture_output=True)
