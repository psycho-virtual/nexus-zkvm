#!/usr/bin/env python3
"""
pretty_logs.py: A post-processor to colorize Rust tracing logs.

Usage:
    pip install rich
    tail -F your_tests.log | python pretty_logs.py
"""

import re
import sys
from rich.console import Console
from rich.text import Text

# Regex to capture the log fields
pattern = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+'
    r'(?P<level>INFO|DEBUG|WARN|ERROR)\s+'
    r'(?P<test>test_[A-Za-z0-9_]+):\s+'
    r'(?P<module>[A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)*):\s*'
    r'(?P<msg>.*)$'
)

# Mapping log levels to colors
level_colors = {
    "INFO": "bold green",
    "DEBUG": "bold blue",
    "WARN": "bold yellow",
    "ERROR": "bold red"
}

console = Console()

def colorize_line(line: str):
    m = pattern.match(line)
    if m:
        ts = Text(m.group('ts'), style="cyan")
        lvl = m.group('level')
        lvl_text = Text(lvl, style=level_colors.get(lvl, "white"))
        test = Text(m.group('test') + ":", style="grey50")
        module = Text(m.group('module') + ":", style="grey50")
        msg = Text(" " + m.group('msg'))
        console.print(ts, " ", lvl_text, " ", test, " ", module, msg)
    else:
        # Print lines that don't match as-is
        console.print(line.rstrip())

def main():
    for raw_line in sys.stdin:
        colorize_line(raw_line)

if __name__ == "__main__":
    main()

