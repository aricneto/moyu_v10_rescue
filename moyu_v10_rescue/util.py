from __future__ import annotations

import os
import sys
import textwrap
from datetime import datetime
from pathlib import Path


class Term:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


def color_enabled(default: bool = True) -> bool:
    if not default:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def c(text: str, code: str, enabled: bool = True) -> str:
    if not enabled:
        return text
    return f"{code}{text}{Term.RESET}"


def banner(enabled: bool = True):
    print()
    print(c("╔══════════════════════════════════════════════════════╗", Term.CYAN, enabled))
    print(c("║        MoYu WeiLong V10 AI Rescue Toolkit           ║", Term.CYAN, enabled))
    print(c("╚══════════════════════════════════════════════════════╝", Term.CYAN, enabled))
    print()


def section(title: str, enabled: bool = True):
    print()
    print(c(f"== {title} ==", Term.BOLD + Term.BLUE, enabled))


def info(msg: str, enabled: bool = True):
    print(c("[i] ", Term.CYAN, enabled) + msg)


def ok(msg: str, enabled: bool = True):
    print(c("[OK] ", Term.GREEN, enabled) + msg)


def warn(msg: str, enabled: bool = True):
    print(c("[!] ", Term.YELLOW, enabled) + msg)


def fail(msg: str, enabled: bool = True):
    print(c("[X] ", Term.RED, enabled) + msg)


def hr(enabled: bool = True):
    print(c("─" * 62, Term.DIM, enabled))


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def hex_bytes(data: bytes) -> str:
    return data.hex(" ")


def ascii_preview(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


def hexdump(data: bytes, base: int = 0, width: int = 16):
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = ascii_preview(chunk)
        print(f"{base + i:08x}  {hx:<{width * 3}}  {asc}")


def prompt_yes_no(question: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    ans = input(f"{question} {suffix} ").strip().lower()
    if not ans:
        return default
    return ans in {"y", "yes"}


def prompt_exact(prompt: str, expected: str) -> bool:
    print(textwrap.fill(prompt, width=78))
    ans = input(f"Type exactly {expected!r} to continue: ").strip()
    return ans == expected
