import sys
import io
import os

# Fix encoding before any imports
os.environ['PYTHONIOENCODING'] = 'utf-8'
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', line_buffering=True)

# Monkey patch Path.write_text to always use utf-8
import pathlib
_original_write_text = pathlib.Path.write_text

def _utf8_write_text(self, data, encoding=None, errors=None):
    return _original_write_text(self, data, encoding='utf-8', errors=errors)

pathlib.Path.write_text = _utf8_write_text

# Call push directly with no interface
from openenv.cli.commands.push import push

# Manually invoke with no interface
sys.argv = ['push', '.', '--no-interface']
push()