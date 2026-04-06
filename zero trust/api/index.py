"""
Vercel serverless entry point.

Vercel's @vercel/python builder looks for a WSGI callable named `app`
in this file. All Flask routes, static files, and API logic are wired here.
"""

import sys
import os

# Make sure the project root is importable (modules/, data/, static/)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app import app  # noqa: F401  — Vercel picks up this `app` object
