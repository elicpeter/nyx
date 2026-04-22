"""File B — middle of the A → B → C chain.  Forwards its argument to
sinks.exec_cmd in sinks.py.  Under k=1 inline analysis, the hop from
A into B is context-sensitive; the hop from B into C is resolved via
the SsaFuncSummary for exec_cmd (which records param 0 → CMD_EXEC)."""

from sinks import exec_cmd


def forward(cmd):
    exec_cmd(cmd)
