import json
import sys
import os
import socket


PORT_ENV_VAR = "PPRINTER_TOOL_PORT"
KEY_TOOL_NAME = "name"
KEY_TOOL_ARGS = "args"
KEY_TOOL_CWD = "cwd"


def send_packet(sock: socket.socket, payload: dict) -> None:
    sock.send(json.dumps(payload).encode() + b"\n")


def recv_packet(sock: socket.socket) -> dict:
    data = b""
    while True:
        new_data = sock.recv(1024)
        if not new_data:
            return None

        data += new_data
        if data[-1] == 10:
            return json.loads(data)


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", int(os.environ[PORT_ENV_VAR])))

        # Strip the executable to just the base name so that tests don't need
        # to worry about where the checkout is.
        tool, *args = sys.argv
        tool = os.path.basename(tool)

        packet = {
            KEY_TOOL_NAME: tool,
            KEY_TOOL_ARGS: args,
            KEY_TOOL_CWD: os.getcwd(),
        }
        send_packet(s, packet)

        # Wait until we're told it's time to continue.
        recv_packet(s)
        sys.exit(0)
