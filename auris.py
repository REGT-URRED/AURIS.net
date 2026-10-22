import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

# Windows: sin esto, la consola cp1252 revienta con los box-drawing de Rich.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

from auris.cli import app

if __name__ == "__main__":
    app()
