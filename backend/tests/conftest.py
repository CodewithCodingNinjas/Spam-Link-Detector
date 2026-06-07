"""
Shared pytest configuration.
Ensures the backend package root is importable when tests are run from anywhere,
and registers the asyncio marker so network-free async tests run deterministically.
"""
import os
import sys

BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)
