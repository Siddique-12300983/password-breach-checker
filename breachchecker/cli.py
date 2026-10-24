"""Command-line interface. Reads the password with getpass and never echoes,
logs or stores it."""

from __future__ import annotations

import argparse
import getpass
import sys

import requests

from . import __version__
from .hibp import pwned_count
from .strength import rate


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="password-breach-checker",
        description="Check a password against Have I Been Pwned without sending it anywhere.",
        epilog="The password is read interactively and never passed as an argument.",
    )
    p.add_argument("--version", action="version", version=f"password-breach-checker {__version__}")
    return p


def _format_strength(password: str) -> str:
    s = rate(password)
    line = f"Strength : {s.rating} ({s.length} chars, {len(s.categories)} character types)"
    if s.suggestions:
        line += "\n           tip: " + "; ".join(s.suggestions)
    return line


def run(argv=None) -> int:
    build_parser().parse_args(argv)

    # getpass does not echo the password to the terminal.
    password = getpass.getpass("Password (hidden): ")
    if not password:
        print("No password entered.", file=sys.stderr)
        return 2

    try:
        count = pwned_count(password)
    except requests.RequestException as exc:
        print(f"Could not reach the HIBP API: {exc}", file=sys.stderr)
        return 3
    finally:
        # Drop the reference as soon as we are done with it.
        pass

    if count > 0:
        print(f"BREACHED : found in {count:,} known breaches. Do not use this password.")
    else:
        print("OK       : not found in any known breach.")

    print(_format_strength(password))
    del password
    return 1 if count > 0 else 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
