import os
import subprocess
import sqlite3
import pickle
import shlex

# ───── Configuration ─────

DATABASE_PATH = os.getenv("DB_PATH", "/var/lib/app/data.db")
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/uploads")
REDIS_URL = os.getenv("REDIS_URL")

# ───── Request handlers ─────

def handle_admin_exec(request):
    """POST /admin/exec
    Runs an admin command from environment config.
    VULN: os.getenv flows into subprocess.run (command injection)
    """
    admin_cmd = os.getenv("ADMIN_COMMAND")
    result = subprocess.run(admin_cmd, shell=True, capture_output=True)
    return {"status": result.returncode, "output": result.stdout.decode()}

def handle_report_generate(request):
    """POST /reports/generate
    Generates a report by calling an external script.
    VULN: os.getenv flows into subprocess.Popen
    """
    script_path = os.getenv("REPORT_SCRIPT")
    proc = subprocess.Popen(
        [script_path, "--format", "pdf"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()
    return {"report": stdout.decode()}

def handle_eval_expression(request):
    """POST /api/eval
    Evaluates a mathematical expression from user input.
    VULN: request.form flows into eval (code injection)
    """
    expression = request.form.get("expr")
    result = eval(expression)
    return {"result": result}

def handle_dynamic_import(request):
    """POST /api/plugins/load
    Loads a plugin by executing its setup code.
    VULN: request.json flows into exec (arbitrary code execution)
    """
    plugin_code = request.json.get("setup_code")
    exec(plugin_code)
    return {"status": "loaded"}

def handle_search(request):
    """GET /api/search
    Searches the database with user-supplied query.
    VULN: request.args flows into cursor.execute (SQL injection)
    """
    query = request.args.get("q")
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE name LIKE '%" + query + "%'")
    rows = cursor.fetchall()
    conn.close()
    return {"results": rows}

def handle_lookup(request):
    """GET /api/lookup
    Looks up a record by user-supplied ID.
    VULN: request.args flows into os.popen (command injection)
    """
    record_id = request.args.get("id")
    output = os.popen("grep " + record_id + " /var/log/audit.log").read()
    return {"matches": output}

def handle_backup(request):
    """POST /admin/backup
    Creates a database backup.
    VULN: os.environ flows into subprocess.call
    """
    backup_dir = os.environ.get("BACKUP_DIR", "/backups")
    subprocess.call(["pg_dump", "-f", backup_dir + "/dump.sql", REDIS_URL])
    return {"status": "ok"}

# ───── Input handling ─────

def handle_interactive_setup():
    """Interactive setup wizard.
    VULN: input() flows into os.system (command injection from stdin)
    """
    db_host = input("Enter database host: ")
    os.system("ping -c 1 " + db_host)

    db_password = input("Enter database password: ")
    return {"host": db_host, "password": db_password}

# ───── Safe patterns ─────

def handle_safe_exec():
    """SAFE: shlex.quote sanitizes before shell execution."""
    user_dir = os.getenv("USER_DIR")
    safe_dir = shlex.quote(user_dir)
    subprocess.run(["ls", "-la", safe_dir], capture_output=True)

def handle_safe_search(request):
    """SAFE: parameterized query prevents SQL injection."""
    query = request.args.get("q")
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE name LIKE ?", ("%" + query + "%",))
    rows = cursor.fetchall()
    conn.close()
    return {"results": rows}
