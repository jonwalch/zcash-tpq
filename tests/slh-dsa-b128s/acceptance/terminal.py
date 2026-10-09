"""Human-only PTY adapter, reused from pinned research cli_smoke.py.

Only explicit human live drivers call run(). Tests mock it; importing is inert.
Passwords and terminal output are never retained in public artifacts or errors.
"""
import errno
import os
import pty
import select
import signal
import termios
import time
from common import require


def run(binary, arguments, prompts, success=True):
    terminal, slave = pty.openpty()
    original_mode = termios.tcgetattr(slave)
    pid = os.fork()
    if pid == 0:
        os.close(terminal)
        os.login_tty(slave)
        os.execv(str(binary), ["pq-wallet", *map(str, arguments)])
    os.close(slave)
    transcript = b""
    cursor = 0
    pending = list(prompts)
    status = None
    deadline = time.monotonic() + 600
    try:
        while time.monotonic() < deadline:
            if select.select([terminal], [], [], 0.1)[0]:
                try:
                    data = os.read(terminal, 8192)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not data:
                    break
                require(len(transcript) + len(data) <= 2 * 1024 * 1024, "cli_output_size")
                transcript += data
                while pending:
                    prompt, reply = pending[0]
                    index = transcript.find(prompt, cursor)
                    if index == -1:
                        break
                    cursor = index + len(prompt)
                    pending.pop(0)
                    # A visible prompt must already be safe to answer. Never
                    # wait for echo to turn off: that would mask the echo race.
                    require(not termios.tcgetattr(terminal)[3] & (termios.ECHO | termios.ECHONL), "terminal_echo")
                    os.write(terminal, reply + b"\n")
            completed, status = os.waitpid(pid, os.WNOHANG)
            if completed:
                pid = None
                break
        else:
            raise TimeoutError("wallet CLI did not finish")
        if pid is not None:
            _, status = os.waitpid(pid, 0)
            pid = None
        require(not pending, "cli_missing_prompt")
        require((os.waitstatus_to_exitcode(status) == 0) == success, "cli_exit_status")
        require(termios.tcgetattr(terminal) == original_mode, "terminal_restore")
        for _, reply in prompts:
            if len(reply) >= 8:
                require(reply not in transcript, "terminal_password_exposure")
        return transcript
    finally:
        os.close(terminal)
        if pid is not None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def new_password(value):
    return [(b"New backup password: ", value), (b"Repeat new password: ", value)]

