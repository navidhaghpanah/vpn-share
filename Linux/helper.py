#!/usr/bin/python3
"""Fixed, root-owned polkit helper. One start request; stop/EOF ends the session."""
import fcntl
import json
import os
import signal
import sys
import threading
from pathlib import Path
import core


def main():
    if os.geteuid() != 0:
        raise RuntimeError("Administrator authentication is required")
    core.secure_run()
    lock = open(core.RUN / "lock", "a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    stopping = threading.Event()
    for name in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(name, lambda *_: stopping.set())
    session = core.Session()

    def emit(data):
        print(json.dumps(data), flush=True)

    try:
        line = sys.stdin.readline(8193)
        if len(line) > 8192 or not line.endswith("\n"):
            raise ValueError("Invalid control request")
        request = json.loads(line)
        session.start(request)
        emit({"event": "started", "gateway": session.state["gateway"]})

        def control():
            try:
                for line in sys.stdin:
                    if len(line) > 8192:
                        break
                    if json.loads(line).get("action") == "stop":
                        break
            finally:
                stopping.set()
        threading.Thread(target=control, daemon=True).start()
        while not stopping.wait(1):
            try:
                if session.dhcp and session.dhcp.poll() is not None:
                    raise RuntimeError("The DHCP process stopped")
                emit(session.refresh())
            except BrokenPipeError:
                stopping.set()
            except Exception as error:
                session.connected = False
                emit({**session.status(), "error": str(error)})
    except BrokenPipeError:
        pass
    except Exception as error:
        try: emit({"event": "error", "error": str(error)})
        except BrokenPipeError: pass
    finally:
        try:
            session.stop()
            try: emit({"event": "stopped"})
            except BrokenPipeError: pass
        except Exception as error:
            try: emit({"event": "error", "error": "Recovery needs attention: " + str(error)})
            except BrokenPipeError: pass


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"event": "error", "error": str(error)}), flush=True)
        sys.exit(1)
