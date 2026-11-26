"""Command line helper that shells out safely.

The command is always passed as a list and shell=False is used, so arguments
that start with a dash or contain spaces cannot be reinterpreted by a shell.
"""

import argparse
import json
import shutil
import subprocess
import sys

DEFAULT_TIMEOUT = 30


class CommandError(RuntimeError):
    """Raised when an external command fails."""


def run_command(arguments, timeout=DEFAULT_TIMEOUT):
    if not isinstance(arguments, list):
        raise TypeError("arguments must be a list")
    if not arguments:
        raise ValueError("arguments must not be empty")
    completed = subprocess.run(
        arguments,
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise CommandError(completed.stderr.strip())
    return completed.stdout


def find_tool(name):
    return shutil.which(name)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Run a helper command")
    parser.add_argument("--tool", default="git", help="tool to run")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("args", nargs=argparse.REMAINDER)
    return parser.parse_args(argv)


def main(argv=None):
    options = parse_args(argv if argv is not None else sys.argv[1:])
    tool = find_tool(options.tool)
    if tool is None:
        sys.stderr.write("tool not found\n")
        return 2
    try:
        output = run_command([tool, *options.args], timeout=options.timeout)
    except CommandError as error:
        sys.stderr.write(str(error) + "\n")
        return 1
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())