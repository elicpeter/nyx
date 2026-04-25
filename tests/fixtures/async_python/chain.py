# Regression fixture: asyncio coroutine with env-var source flowing
# across an `await` boundary to a subprocess.run sink.
#
# Intended finding: taint-unsanitised-flow from os.environ["CMD"] to
# subprocess.run (shell=True).  The await point must not break taint
# tracking — awaited expressions resume in the same stack frame and the
# tainted variable is still in scope.
import asyncio
import os
import subprocess


async def fetch_and_exec():
    cmd = os.environ["CMD"]
    await asyncio.sleep(0)
    subprocess.run(cmd, shell=True)


asyncio.run(fetch_and_exec())
