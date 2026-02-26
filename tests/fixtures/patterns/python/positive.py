# Positive fixture: each snippet should trigger the named pattern.

import os
import subprocess
import pickle
import yaml
import hashlib

# py.code_exec.eval
def trigger_eval(data):
    result = eval(data)

# py.code_exec.exec
def trigger_exec(code):
    exec(code)

# py.code_exec.compile
def trigger_compile(code):
    co = compile(code, "<string>", "exec")

# py.cmdi.os_system
def trigger_os_system(cmd):
    os.system(cmd)

# py.cmdi.os_popen
def trigger_os_popen(cmd):
    os.popen(cmd)

# py.cmdi.subprocess_shell
def trigger_subprocess_shell(cmd):
    subprocess.run(cmd, shell=True)

# py.deser.pickle_loads
def trigger_pickle(data):
    obj = pickle.loads(data)

# py.deser.yaml_load
def trigger_yaml(data):
    obj = yaml.load(data)

# py.sqli.execute_format
def trigger_sql_concat(cursor, user):
    cursor.execute("SELECT * FROM users WHERE name = '" + user + "'")

# py.crypto.md5
def trigger_md5(data):
    hashlib.md5(data)

# py.crypto.sha1
def trigger_sha1(data):
    hashlib.sha1(data)
