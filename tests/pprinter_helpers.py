"""
Utilities for testing gtirb-pprinter.
"""

import concurrent.futures
import contextlib
import dataclasses
import os
import os.path
from pathlib import Path
import re
import socket
import sys
import subprocess
import tempfile
import unittest
from distutils.util import strtobool
from typing import (
    Iterable,
    Iterator,
    NamedTuple,
    List,
    Optional,
    Sequence,
    Tuple,
)

import gtirb

TESTS_DIR = os.path.abspath(os.path.dirname(__file__))
_FAKEBIN_DIR = os.path.join(TESTS_DIR, "fakebin")

sys.path.append(_FAKEBIN_DIR)
import fakeprog  # noqa: E402


ToolInvocation = NamedTuple(
    "ToolInvocation", [("name", str), ("args", List[str]), ("cwd", str)]
)


def interesting_lines(s: str, comment_chars: str = "") -> List[str]:
    """
    Takes a string and returns a list of non-whitespace/non-comment lines,
    with each line stripped of trailing/leading whitespace.
    """
    result = []
    for line in s.splitlines():
        line = line.strip()
        if line and line[0] not in comment_chars:
            result.append(line)
    return result


def asm_lines(asm: str) -> List[str]:
    return interesting_lines(asm, "#")


def contains(a: Sequence, b: Sequence) -> bool:
    """
    Determines if a sequence contains a subsequence.
    """
    # If we needed to deal with larger inputs, this could be smarter.
    return any(
        all(a[a_i + b_i] == b[b_i] for b_i in range(len(b)))
        for a_i in range(len(a) - len(b) + 1)
    )


@contextlib.contextmanager
def temp_directory(suffix=None, prefix=None, dir=None):
    """
    Creates a temporary directory, potentially deleting it when done.
    """
    keep = strtobool(os.environ.get("KEEP_TEMP_FILES", "0"))
    if keep:
        yield tempfile.mkdtemp(suffix, prefix, dir)
    else:
        with tempfile.TemporaryDirectory(suffix, prefix, dir) as tmpdir:
            yield tmpdir


def pprinter_binary() -> str:
    """
    The binary to invoke to test the pretty-printer.
    """
    return os.environ.get("PPRINTER_PATH", "gtirb-pprinter")


def running_in_pytest() -> bool:
    """
    Determines if the test is running under pytest.
    """
    return "pytest" in sys.modules


def should_print_subprocess_output() -> bool:
    """
    Should subprocess output be printed to stdout?
    """
    env = os.environ.get("PPRINTER_VERBOSE_OUTPUT")
    if env is not None:
        return strtobool(env)

    # Pytest hides a test's stdout unless it fails, so feel free to write
    # potentially useful information if we're running under it.
    return running_in_pytest()


def can_mock_binaries() -> bool:
    """
    Determines if the binary pretty printer mock tests work on this platform.
    """
    return os.name == "posix"


def run_asm_pprinter(ir: gtirb.IR, args: Iterable[str] = ()) -> str:
    """
    Runs the pretty-printer to generate an assembly output.
    :param ir: The IR object to print.
    :param args: Any additional arguments for the pretty printer.
    :returns: The assembly string.
    """
    asm, _ = run_asm_pprinter_with_output(ir, args)
    return asm


def run_asm_pprinter_with_output(
    ir: gtirb.IR, args: Iterable[str] = ()
) -> Tuple[str, str]:
    """
    Runs the pretty-printer to generate an assembly output.
    :param ir: The IR object to print.
    :param args: Any additional arguments for the pretty printer.
    :returns: The assembly string and the contents of stdout/stderr.
    """
    with temp_directory() as tmpdir:
        gtirb_path = os.path.join(tmpdir, "test.gtirb")
        ir.save_protobuf(gtirb_path)

        asm_path = os.path.join(tmpdir, "test.asm")
        proc = subprocess.run(
            (pprinter_binary(), gtirb_path, "--asm", asm_path, *args),
            check=False,
            cwd=tmpdir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        if should_print_subprocess_output():
            sys.stdout.buffer.write(proc.stdout)
        proc.check_returncode()

        with open(asm_path, "r") as f:
            return f.read(), proc.stdout.decode("ascii")


def run_binary_pprinter_mock_out(
    ir: gtirb.IR,
    args: Iterable[str],
    port: Optional[int] = None,
    fakebin_dir: Optional[str] = None,
    check_output: bool = False,
) -> subprocess.CompletedProcess:
    if fakebin_dir is None:
        fakebin_dir = _FAKEBIN_DIR
    with temp_directory() as tmpdir:
        gtirb_path = os.path.join(tmpdir, "test.gtirb")
        ir.save_protobuf(gtirb_path)

        # Put our fake binaries first on PATH so that we can monitor
        # what the pretty-printer is invoking (as long as we have a
        # stub for everything it invokes).
        env = dict(os.environ)
        env["PATH"] = "%s%s%s" % (
            fakebin_dir,
            os.pathsep,
            env.get("PATH", ""),
        )
        if port is not None:
            env[fakeprog.PORT_ENV_VAR] = str(port)

        bin_path = os.path.join(tmpdir, "test")

        capture_output_args = {}
        if check_output or not should_print_subprocess_output():
            capture_output_args["stdout"] = subprocess.PIPE
            capture_output_args["stderr"] = subprocess.PIPE

        return subprocess.run(
            (
                pprinter_binary(),
                "--ir",
                gtirb_path,
                "--binary",
                bin_path,
                *args,
            ),
            env=env,
            check=False,
            cwd=tmpdir,
            **capture_output_args,
        )


def run_binary_pprinter_mock(
    ir: gtirb.IR,
    args: Iterable[str] = (),
    fakebin_dir: Optional[str] = None,
) -> Iterator[ToolInvocation]:
    """
    Runs the binary pretty-printer and yields each subcommand's arguments,
    while the command is still running (allowing access to temporary files
    that might be arguments).
    :param ir: The IR object to print.
    :param args: Any additional arguments for the pretty printer.
    :param fakebin_dir: The path where pprinter will look for binaries.
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("localhost", 0))
        listener.listen()

        proc_future = concurrent.futures.ThreadPoolExecutor().submit(
            run_binary_pprinter_mock_out,
            ir=ir,
            args=args,
            port=listener.getsockname()[1],
            fakebin_dir=fakebin_dir,
        )

        # We set a relatively small timeout on the socket so that we are
        # more responsive to when the proc future finishes, at the expense
        # of spurious wakeups on this thread.
        listener.settimeout(0.01)

        # The pretty-printer invokes processes synchronously and serially,
        # so we don't need to get clever about multiple connections at
        # once (or the ordering of things).
        generator_exit = False
        while not proc_future.done():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue

            with contextlib.closing(client):
                packet = fakeprog.recv_packet(client)
                if not packet:
                    continue

                if not generator_exit:
                    invocation = ToolInvocation(
                        packet[fakeprog.KEY_TOOL_NAME],
                        packet[fakeprog.KEY_TOOL_ARGS],
                        packet[fakeprog.KEY_TOOL_CWD],
                    )
                    try:
                        yield invocation
                    except GeneratorExit:
                        # If our caller stopped early, we still need to
                        # service the rest of the requests so that the
                        # pretty-printer exits correctly.
                        generator_exit = True

                # Tell the client that it's good to exit.
                fakeprog.send_packet(client, {})

        proc_result = proc_future.result()
        proc_result.check_returncode()


class PPrinterTest(unittest.TestCase):
    def assertContains(
        self, seq: Sequence, subseq: Sequence, msg: str = None
    ) -> None:
        """
        Asserts that a sequence contains another sequence.
        """
        if not contains(seq, subseq):
            default_message = "sequence did not contain subsequence"
            if msg:
                msg = "%s: %s" % (default_message, msg)
            else:
                msg = default_message
            self.fail(msg)

    def assertNotContains(
        self, seq: Sequence, subseq: Sequence, msg: str = None
    ) -> None:
        """
        Asserts that a sequence does not contain another sequence.
        """
        if contains(seq, subseq):
            default_message = "sequence contains subsequence"
            if msg:
                msg = "%s: %s" % (default_message, msg)
            else:
                msg = default_message
            self.fail(msg)

    def assertRegexMatch(self, text: str, pattern: str) -> re.Match:
        """
        Like unittest's assertRegex, but also return the match object on
        success.

        assertRegex provides a nice output on failure, but doesn't return the
        match object, so we assert, and then search.
        """
        compiled = re.compile(pattern)
        self.assertRegex(text, compiled)
        return re.search(compiled, text)


@dataclasses.dataclass
class BinaryPrintResult:
    """Result of a executing binary print command"""

    path: Path
    completed_process: subprocess.CompletedProcess


class BinaryPPrinterTest(PPrinterTest):
    @contextlib.contextmanager
    def binary_print(self, ir: gtirb.IR, *extra_args) -> BinaryPrintResult:
        """
        Run binary printer and provide a path to the compiled binary
        """
        with tempfile.TemporaryDirectory() as testdir:
            testdir = Path(testdir)
            gtirb_path = testdir / "test.gtirb"
            exe_path = testdir / "test_rewritten"
            ir.save_protobuf(str(gtirb_path))

            args = [
                pprinter_binary(),
                "--ir",
                gtirb_path,
                "--binary",
                exe_path,
                *extra_args,
            ]

            completed_process = subprocess.run(
                args, check=True, capture_output=True, text=True
            )
            self.assertTrue(exe_path.exists())
            yield BinaryPrintResult(exe_path, completed_process)
