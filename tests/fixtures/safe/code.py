"""Safe code fixtures — code that should NOT trigger findings."""

import hashlib
import json
import os
import subprocess

def secure_function():
    """This function uses safe patterns."""
    secret = os.environ.get("API_KEY")
    if not secret:
        raise ValueError("API_KEY not set")

    result = subprocess.run(
        ["ls", "-la"],
        capture_output=True,
        text=True,
        shell=False,
    )
    return result.stdout

def hash_data(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def safe_load_config(path: str) -> dict:
    with open(path) as f:
        return json.load(f)
